use std::convert::TryInto;
use std::fmt;
use std::str;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{transport_channel, udp_packet_iter};

const DNS_HEADER_LENGTH: usize = 12;
const DNS_MIN_ANSWER_LENGTH: usize = 11;
const DNS_MIN_QUESTION_LENGTH: usize = 5;
const DNS_PORT: u16 = 53;

// common struct for dns records
//
// dns resource records consist of the following fields:
// * Name (variable number of labels terminated by 0 label)
// * Type (16 bits)
// * Class (16 bits)
// * TTL (32 bits)            (not in dns questions)
// * Data Length (16 bits)    (not in dns questions)
// * Data (Data Length bytes) (not in dns questions)
//
// use methods to read fields from dns record;
// be careful to not use ttl, data length and data functions in dns questions!
struct DnsRecord<'a> {
    // raw packet data and offset to resource record inside the packet data
    raw: &'a [u8],
    offset: usize,

    // indexes of labels within the packet
    label_indexes: Vec<usize>,

    // start index of next message fields after labels:
    // * type (2 byte): next_index
    // * class (2 byte): next_index + 2
    // * ttl (4 byte): next_index + 4
    // * data length (2 byte): next_index + 8
    // * data (data length bytes): next_index + 10
    next_index: usize,
}

impl<'a> DnsRecord<'a> {
    // parse labels inside raw packet data starting at offset,
    // sets the index of the next message field after the labels
    // and adds all labels to the list of label indexes
    fn parse_labels(&mut self) -> Result<(), ()> {
        let mut i = self.offset;
        let mut is_reference = false;
        loop {
            if i >= self.raw.len() {
                return Err(());
            }
            // get length of current label from first byte
            let length: usize = usize::from(self.raw[i]);

            // have we reached end of labels?
            if length == 0 {
                // if we reached this end of labels while following a
                // label reference, do not update indexes, they have
                // been updated before following the reference
                if is_reference {
                    break;
                }

                // save indexes of type, class, ttl, data length, data fields
                self.next_index = i + 1;
                break;
            }

            // is current label a reference to a previous one?
            if length & 0b11000000 != 0 {
                if !is_reference {
                    // this is the first reference in this answer, so this
                    // marks the end of this answer's labels;
                    // save indexes of type, class, ttl, data length,
                    // data fields
                    self.next_index = i + 2;
                }

                // follow reference to previous label
                is_reference = true;
                let raw_index = [self.raw[i] & 0b00111111, self.raw[i + 1]];
                let new_i = usize::from(read_be_u16(&raw_index));

                // reference must point to previous label
                if new_i >= i {
                    return Err(());
                }
                i = new_i;

                continue;
            }

            // save current label index
            self.label_indexes.push(i);

            // skip to next label
            i += length + 1;
        }

        // parsing successful
        return Ok(());
    }

    // create a new dns resource record from raw packet bytes,
    // parse the dns resource record packet:
    // * find labels in the raw packet bytes,
    // * find first index of next fields in packet:
    //   type, class, ttl, data length, data.
    // TODO: add error handling
    fn parse(raw: &'a [u8], offset: usize) -> Result<DnsRecord<'a>, ()> {
        // check offset and minimum size
        if offset > raw.len() || raw.len() - offset < DNS_MIN_QUESTION_LENGTH {
            println!("short dns answer with length {}", raw.len());
            return Err(());
        }

        // retur dns record
        let mut record = DnsRecord {
            raw: raw,
            offset: offset,
            label_indexes: Vec::new(),
            next_index: 0,
        };

        // parse labels
        record.parse_labels()?;

        // return record
        Ok(record)
    }

    // get the length of the labels in this dns record
    fn get_labels_length(&self) -> usize {
        self.next_index - self.offset
    }

    // get the name from labels inside raw packet bytes
    fn get_name(&self) -> String {
        let mut name = String::new();
        for i in &self.label_indexes {
            // get length of current label from first byte
            let length: usize = usize::from(self.raw[*i]);

            // read domain name part from current label
            let j = i + 1;
            let part = match str::from_utf8(&self.raw[j..j + length]) {
                Ok(part) => part,
                Err(err) => {
                    println!("{}", err);
                    "<error>"
                }
            };
            name.push_str(part);
            name += ".";
        }
        return name;
    }

    // get the type field from raw packet bytes
    fn get_type(&self) -> u16 {
        let i = self.next_index;
        read_be_u16(&self.raw[i..i + 2])
    }

    // get the class field from raw packet bytes
    fn get_class(&self) -> u16 {
        let i = self.next_index + 2;
        read_be_u16(&self.raw[i..i + 2])
    }

    // get the ttl field from raw packet bytes;
    // note: do not use in dns question
    fn get_ttl(&self) -> u32 {
        let i = self.next_index + 4;
        read_be_u32(&self.raw[i..i + 4])
    }

    // get the data length field from raw packet bytes;
    // note: do not use in dns question
    fn get_data_length(&self) -> u16 {
        let i = self.next_index + 8;
        read_be_u16(&self.raw[i..i + 2])
    }

    // get the data field from raw packet bytes;
    // note: do not use in dns question
    fn get_data(&self) -> &[u8] {
        let i = self.next_index + 10;
        &self.raw[i..i + usize::from(self.get_data_length())]
    }
}

// dns question conists of the following fields:
//
// Name (variable number of labels terminated by 0 label)
// Type (16 bits)
// Class (16 bits)
//
// use methods to read fields from question
struct DnsQuestion<'a> {
    record: DnsRecord<'a>,
}

impl<'a> DnsQuestion<'a> {
    // create a new dns question from raw packet bytes,
    // parse the question packet:
    pub fn parse(raw: &'a [u8], offset: usize) -> Result<DnsQuestion<'a>, ()> {
        // create and return question
        Ok(DnsQuestion {
            record: DnsRecord::parse(raw, offset)?,
        })
    }

    // get the name field from raw packet bytes
    pub fn get_name(&self) -> String {
        self.record.get_name()
    }

    // get the type field from raw packet bytes
    pub fn get_type(&self) -> u16 {
        self.record.get_type()
    }

    // get the class field from raw packet bytes
    pub fn get_class(&self) -> u16 {
        self.record.get_class()
    }

    // get the length of the question
    pub fn get_length(&self) -> usize {
        self.record.get_labels_length() + 4
    }
}

impl<'a> fmt::Display for DnsQuestion<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{name: {}, type: {}, class: {}}}",
            self.get_name(),
            self.get_type(),
            self.get_class(),
        )
    }
}

// dns answer consists of the following fields:
//
// Name (variable number of labels terminated by 0 label)
// Type (16 bits)
// Class (16 bits)
// TTL (32 bits)
// Data Length (16 bits)
// Data (Data Length bytes)
//
// use methods to read fields from question
struct DnsAnswer<'a> {
    record: DnsRecord<'a>,
}

impl<'a> DnsAnswer<'a> {
    // create a new dns answer from raw packet bytes,
    // parse the answer packet:
    // find labels in the raw packet bytes,
    // find index of type field,
    // find index of class field,
    // find index of ttl field,
    // find index of data length field,
    // find index of data field.
    // TODO: add error handling
    pub fn parse(raw: &'a [u8], offset: usize) -> Result<DnsAnswer<'a>, ()> {
        if raw.len() - offset < DNS_MIN_ANSWER_LENGTH {
            println!("short dns answer with length {}", raw.len());
            return Err(());
        }

        Ok(DnsAnswer {
            record: DnsRecord::parse(raw, offset)?,
        })
    }

    // get the name field from raw packet bytes
    pub fn get_name(&self) -> String {
        self.record.get_name()
    }

    // get the type field from raw packet bytes
    pub fn get_type(&self) -> u16 {
        self.record.get_type()
    }

    // get the class field from raw packet bytes
    pub fn get_class(&self) -> u16 {
        self.record.get_class()
    }

    // get the ttl field from raw packet bytes
    pub fn get_ttl(&self) -> u32 {
        self.record.get_ttl()
    }

    // get the data length field from raw packet bytes
    pub fn get_data_length(&self) -> u16 {
        self.record.get_data_length()
    }

    // get the data field from raw packet bytes;
    fn get_data(&self) -> &[u8] {
        self.record.get_data()
    }

    // get the length of the answer
    pub fn get_length(&self) -> usize {
        self.record.get_labels_length() + 10 + usize::from(self.record.get_data_length())
    }
}

impl<'a> fmt::Display for DnsAnswer<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{name: {}, type: {}, class: {}, ttl: {}, data length: {}, data: {:?}}}",
            self.get_name(),
            self.get_type(),
            self.get_class(),
            self.get_ttl(),
            self.get_data_length(),
            self.get_data(),
        )
    }
}

// dns authority resource record consists of the same fields as dns answer,
// so reuse DnsAnswer for this
type DnsAuthority<'a> = DnsAnswer<'a>;

// dns additional resource record consists of the same fields as dns answer,
// so reuse DnsAnswer for this
type DnsAdditional<'a> = DnsAnswer<'a>;

// dns packet consists of the following 16 bit fields:
//
// Identification,
// Flags/codes
//   (QR (1 bit),  Opcode (4 bits), AA (1 bit), TC (1 bit), RD (1 bit),
//    RA (1 bit), Z (3 bits), RCODE (4 bits)),
// Number of questions,
// Number of answers,
// Number of authority resource records (RRs)
// Number of additional RRs
//
// use methods to read fields from the packet
struct DnsPacket<'a> {
    raw: &'a [u8],

    // dns questions inside the packet
    questions: Vec<DnsQuestion<'a>>,

    // dns answers inside the packet
    answers: Vec<DnsAnswer<'a>>,

    // dns authority resource records inside the packet
    authorities: Vec<DnsAuthority<'a>>,

    // dns additional resource records inside the packet
    additionals: Vec<DnsAdditional<'a>>,
}

impl<'a> DnsPacket<'a> {
    // create a new dns packet from raw packet bytes
    pub fn parse(raw: &'a [u8]) -> Result<DnsPacket<'a>, ()> {
        if raw.len() < DNS_HEADER_LENGTH {
            println!("short dns packet with length {}", raw.len());
            return Err(());
        }

        let mut packet = DnsPacket {
            raw: raw,
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        packet.parse_records()?;

        Ok(packet)
    }

    // parse dns records in the dns packet:
    // find questions, answers, authorities, additionals
    // TODO: improve error handling
    fn parse_records(&mut self) -> Result<(), ()> {
        // parse questions
        let mut offset = DNS_HEADER_LENGTH;
        for _ in 0..self.get_questions() {
            let q = DnsQuestion::parse(self.raw, offset)?;
            offset += q.get_length();
            self.questions.push(q);
        }

        // parse answers
        for _ in 0..self.get_answers() {
            let a = DnsAnswer::parse(self.raw, offset)?;
            offset += a.get_length();
            self.answers.push(a);
        }

        // parse authorities
        for _ in 0..self.get_authorities() {
            let a = DnsAuthority::parse(self.raw, offset)?;
            offset += a.get_length();
            self.authorities.push(a);
        }

        // parse additionals
        for _ in 0..self.get_additionals() {
            let a = DnsAdditional::parse(self.raw, offset)?;
            offset += a.get_length();
            self.additionals.push(a);
        }

        return Ok(());
    }

    // get identification field from packet
    pub fn get_id(&self) -> u16 {
        read_be_u16(&self.raw[0..2])
    }

    // get Query (0)/Response (1) bit from packet
    pub fn get_qr(&self) -> u8 {
        (self.raw[2] & 0b10000000) >> 7
    }

    // get OPCODE bits (4 bits) from packet
    pub fn get_opcode(&self) -> u8 {
        (self.raw[2] & 0b01111000) >> 3
    }

    // get Authoritative Answer (AA) bit from packet
    pub fn get_aa(&self) -> u8 {
        (self.raw[2] & 0b00000100) >> 2
    }

    // get TrunCation (TC) bit from packet
    pub fn get_tc(&self) -> u8 {
        (self.raw[2] & 0b00000010) >> 1
    }

    // get Recursion Desired (RD) bit from packet
    pub fn get_rd(&self) -> u8 {
        self.raw[2] & 0b00000001
    }

    // get Recursion Available (RA) bit from packet
    pub fn get_ra(&self) -> u8 {
        (self.raw[3] & 0b10000000) >> 7
    }

    // get reserved (Z) bits (3 bits) from packet
    pub fn get_z(&self) -> u8 {
        (self.raw[3] & 0b01110000) >> 4
    }

    // get response code (RCODE) bits (4 bits) from packet
    pub fn get_rcode(&self) -> u8 {
        self.raw[3] & 0b00001111
    }

    // get number of questions from packet
    pub fn get_questions(&self) -> u16 {
        read_be_u16(&self.raw[4..6])
    }

    // get number of answers from packet
    pub fn get_answers(&self) -> u16 {
        read_be_u16(&self.raw[6..8])
    }

    // get number of authority resource records from packet
    pub fn get_authorities(&self) -> u16 {
        read_be_u16(&self.raw[8..10])
    }

    // get number of additional resource records from packet
    pub fn get_additionals(&self) -> u16 {
        read_be_u16(&self.raw[10..12])
    }

    // get nth question from packet
    pub fn get_question(&self, nth: usize) -> Option<&DnsQuestion> {
        if nth >= self.questions.len() {
            return None;
        }
        Some(&self.questions[nth])
    }

    // get nth answer from packet
    pub fn get_answer(&self, nth: usize) -> Option<&DnsAnswer> {
        if nth >= self.answers.len() {
            return None;
        }
        Some(&self.answers[nth])
    }

    // get nth authority from packet
    pub fn get_authority(&self, nth: usize) -> Option<&DnsAuthority> {
        if nth >= self.authorities.len() {
            return None;
        }
        Some(&self.authorities[nth])
    }

    // get nth additional from packet
    pub fn get_additional(&self, nth: usize) -> Option<&DnsAdditional> {
        if nth >= self.additionals.len() {
            return None;
        }
        Some(&self.additionals[nth])
    }
}

impl<'a> fmt::Display for DnsPacket<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // dns packet header
        write!(
            f,
            "{{id: {}, qr: {}, opcode: {}, aa: {}, tc: {}, rd: {}, ra: {}, \
            z: {}, rcode: {}, questions: {}, answers: {}, authorities: {}, \
            additionals: {}",
            self.get_id(),
            self.get_qr(),
            self.get_opcode(),
            self.get_aa(),
            self.get_tc(),
            self.get_rd(),
            self.get_ra(),
            self.get_z(),
            self.get_rcode(),
            self.get_questions(),
            self.get_answers(),
            self.get_authorities(),
            self.get_additionals(),
        )?;

        // dns questions
        for i in 0..self.get_questions().into() {
            if let Some(question) = self.get_question(i) {
                write!(f, ", question {}: {}", i, question)?;
            }
        }

        // dns answers
        for i in 0..self.get_answers().into() {
            if let Some(answer) = self.get_answer(i) {
                write!(f, ", answer {}: {}", i, answer)?;
            }
        }

        // dns authorities
        for i in 0..self.get_authorities().into() {
            if let Some(authority) = self.get_authority(i) {
                write!(f, ", authority {}: {}", i, authority)?;
            }
        }

        // dns additionals
        for i in 0..self.get_additionals().into() {
            if let Some(additional) = self.get_additional(i) {
                write!(f, ", additional {}: {}", i, additional)?;
            }
        }

        // closing brackets
        write!(f, "}}")
    }
}

// convert a 16 bit field from big endian to native byte order
fn read_be_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(bytes.try_into().expect("slice with incorrect length"))
}

// convert a 32 bit field from big endian to native byte order
fn read_be_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().expect("slice with incorrect length"))
}

fn main() {
    // create an udp channel
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Udp));
    let (_, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occurred when creating the transport channel: {}",
            e
        ),
    };

    // read udp packets from channel and handle dns packets
    let mut iter = udp_packet_iter(&mut rx);
    loop {
        match iter.next() {
            Ok((packet, addr)) => {
                // only handle dns packets
                if packet.get_source() != DNS_PORT && packet.get_destination() != DNS_PORT {
                    continue;
                }

                // parse dns packet
                let dns = match DnsPacket::parse(packet.payload()) {
                    Ok(dns) => dns,
                    Err(_) => {
                        println!("malformed dns packet");
                        continue;
                    }
                };
                println!("got dns packet from {}: {}", addr, dns);
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}
