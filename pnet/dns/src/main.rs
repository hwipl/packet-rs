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

// dns question conists of the following fields:
//
// Name (variable number of labels terminated by 0 label)
// Type (16 bits)
// Class (16 bits)
//
// use methods to read fields from question
struct DnsQuestion<'a> {
    // raw packet data and offset to dns question inside the packet data
    raw: &'a [u8],
    offset: usize,

    // indexes of labels within the packet
    label_indexes: Vec<usize>,

    // indexes of type and class fields that are after the labels
    type_index: usize,
    class_index: usize,
}

impl<'a> DnsQuestion<'a> {
    // create a new dns question from raw packet bytes,
    // parse the question packet:
    // find labels in the raw packet bytes,
    // find index of type field,
    // find index of class field.
    // TODO: add error handling
    pub fn parse(raw: &'a [u8], offset: usize) -> Option<DnsQuestion<'a>> {
        if offset >= raw.len() || raw.len() - offset < DNS_MIN_QUESTION_LENGTH {
            println!("short dns question with length {}", raw.len());
            return None;
        }

        // parse labels and find index of next message field
        let (next_index, label_indexes) = parse_labels(raw, offset);

        // create and return question
        Some(DnsQuestion {
            raw: raw,
            offset: offset,
            label_indexes: label_indexes,
            type_index: next_index,
            class_index: next_index + 2,
        })
    }

    // get the name field from raw packet bytes
    pub fn get_name(&self) -> String {
        return get_name_from_labels(self.raw, &self.label_indexes);
    }

    // get the type field from raw packet bytes
    pub fn get_type(&self) -> u16 {
        let i = self.type_index;
        read_be_u16(&self.raw[i..i + 2])
    }

    // get the class field from raw packet bytes
    pub fn get_class(&self) -> u16 {
        let i = self.class_index;
        read_be_u16(&self.raw[i..i + 2])
    }

    // get the length of the question
    pub fn get_length(&self) -> usize {
        self.class_index + 2 - self.offset
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
    // raw packet data and offset to dns answer inside the packet data
    raw: &'a [u8],
    offset: usize,

    // indexes of labels within the packet
    label_indexes: Vec<usize>,

    // indexes of type, class, ttl, data length, data fields
    // that are after the labels
    type_index: usize,
    class_index: usize,
    ttl_index: usize,
    data_length_index: usize,
    data_index: usize,
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
    pub fn parse(raw: &'a [u8], offset: usize) -> Option<DnsAnswer<'a>> {
        if offset > raw.len() || raw.len() - offset < DNS_MIN_ANSWER_LENGTH {
            println!("short dns answer with length {}", raw.len());
            return None;
        }

        // parse labels
        let (next_index, label_indexes) = parse_labels(raw, offset);

        Some(DnsAnswer {
            raw: raw,
            offset: offset,
            label_indexes: label_indexes,
            type_index: next_index,
            class_index: next_index + 2,
            ttl_index: next_index + 4,
            data_length_index: next_index + 8,
            data_index: next_index + 10,
        })
    }

    // get the name field from raw packet bytes
    pub fn get_name(&self) -> String {
        return get_name_from_labels(self.raw, &self.label_indexes);
    }

    // get the type field from raw packet bytes
    pub fn get_type(&self) -> u16 {
        let i = self.type_index;
        read_be_u16(&self.raw[i..i + 2])
    }

    // get the class field from raw packet bytes
    pub fn get_class(&self) -> u16 {
        let i = self.class_index;
        read_be_u16(&self.raw[i..i + 2])
    }

    // get the ttl field from raw packet bytes
    pub fn get_ttl(&self) -> u32 {
        let i = self.ttl_index;
        read_be_u32(&self.raw[i..i + 4])
    }

    // get the data length field from raw packet bytes
    pub fn get_data_length(&self) -> u16 {
        let i = self.data_length_index;
        read_be_u16(&self.raw[i..i + 2])
    }

    // get the length of the answer
    pub fn get_length(&self) -> usize {
        self.data_index + usize::from(self.get_data_length()) - self.offset
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
// Flags,
// Number of questions,
// Number of answers,
// Number of authority resource records (RRs)
// Number of additional RRs
//
// use methods to read fields from the packet
struct DnsPacket<'a> {
    raw: &'a [u8],

    // dns questions inside the packet
    questions_offset: usize,
    questions: Vec<DnsQuestion<'a>>,

    // dns answers inside the packet
    answers_offset: usize,
    answers: Vec<DnsAnswer<'a>>,

    // dns authority resource records inside the packet
    authorities_offset: usize,
    authorities: Vec<DnsAuthority<'a>>,

    // dns additional resource records inside the packet
    additionals_offset: usize,
    additionals: Vec<DnsAdditional<'a>>,
}

impl<'a> DnsPacket<'a> {
    // create a new dns packet from raw packet bytes
    pub fn new(raw: &'a [u8]) -> Option<DnsPacket<'a>> {
        if raw.len() < DNS_HEADER_LENGTH {
            println!("short dns packet with length {}", raw.len());
            None
        } else {
            let mut packet = DnsPacket {
                raw: raw,
                questions_offset: DNS_HEADER_LENGTH,
                questions: Vec::new(),
                answers_offset: 0,
                answers: Vec::new(),
                authorities_offset: 0,
                authorities: Vec::new(),
                additionals_offset: 0,
                additionals: Vec::new(),
            };
            packet.parse_questions().ok()?;
            packet.parse_answers().ok()?;
            packet.parse_authorities().ok()?;
            packet.parse_additionals().ok()?;
            Some(packet)
        }
    }

    // parse dns packet and find questions, set answers offset
    // TODO: improve error handling?
    fn parse_questions(&mut self) -> Result<(), ()> {
        let mut offset = self.questions_offset;
        for _ in 0..self.get_questions() {
            let q = DnsQuestion::parse(&self.raw, offset);
            match q {
                None => return Err(()),
                Some(q) => {
                    offset += q.get_length();
                    self.questions.push(q);
                }
            }
        }

        // set offset to answers section
        self.answers_offset = offset;
        return Ok(());
    }

    // parse dns packet and find answers, set authorities offset
    // TODO: improve error handling
    fn parse_answers(&mut self) -> Result<(), ()> {
        let mut offset = self.answers_offset;
        for _ in 0..self.get_answers() {
            let a = DnsAnswer::parse(self.raw, offset);
            match a {
                None => return Err(()),
                Some(a) => {
                    offset += a.get_length();
                    self.answers.push(a);
                }
            }
        }

        // set offset to authorities section
        self.authorities_offset = offset;
        return Ok(());
    }

    // parse dns packet and find authorities, set additionals offset
    // TODO: improve error handling
    fn parse_authorities(&mut self) -> Result<(), ()> {
        let mut offset = self.authorities_offset;
        for _ in 0..self.get_authorities() {
            let a = DnsAuthority::parse(self.raw, offset);
            match a {
                None => return Err(()),
                Some(a) => {
                    offset += a.get_length();
                    self.authorities.push(a);
                }
            }
        }

        // set offset to additionals section
        self.additionals_offset = offset;
        return Ok(());
    }

    // parse dns packet and find additionals
    // TODO: improve error handling
    fn parse_additionals(&mut self) -> Result<(), ()> {
        let mut offset = self.additionals_offset;
        for _ in 0..self.get_additionals() {
            let a = DnsAdditional::parse(self.raw, offset);
            match a {
                None => return Err(()),
                Some(a) => {
                    offset += a.get_length();
                    self.additionals.push(a);
                }
            }
        }
        return Ok(());
    }

    // get identification field from packet
    pub fn get_id(&self) -> u16 {
        read_be_u16(&self.raw[0..2])
    }

    // get flags from packet
    pub fn get_flags(&self) -> u16 {
        read_be_u16(&self.raw[2..4])
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
        write!(
            f,
            "{{id: {}, flags: {}, questions: {}, answers: {}, authorities: {}, additionals: {}}}",
            self.get_id(),
            self.get_flags(),
            self.get_questions(),
            self.get_answers(),
            self.get_authorities(),
            self.get_additionals(),
        )
    }
}

// parse labels inside raw packet data starting at offset,
// return the index of the next message field after the labels
// and a list of label indexes
fn parse_labels(raw: &[u8], offset: usize) -> (usize, Vec<usize>) {
    let mut i = offset;
    let mut is_reference = false;
    let mut label_indexes = Vec::new();
    let mut next_index = 0;
    loop {
        if i >= raw.len() {
            break;
        }
        // get length of current label from first byte
        let length: usize = usize::from(raw[i]);

        // have we reached end of labels?
        if length == 0 {
            // if we reached this end of labels while following a
            // label reference, do not update indexes, they have
            // been updated before following the reference
            if is_reference {
                break;
            }

            // save indexes of type, class, ttl, data length, data fields
            next_index = i + 1;
            break;
        }

        // is current label a reference to a previous one?
        if length & 0b11000000 != 0 {
            if !is_reference {
                // this is the first reference in this answer, so this
                // marks the end of this answer's labels;
                // save indexes of type, class, ttl, data length,
                // data fields
                next_index = i + 2;
            }

            // follow reference to previous label
            // TODO: add error handling
            is_reference = true;
            let raw_index = [raw[i] & 0b00111111, raw[i + 1]];
            i = usize::from(read_be_u16(&raw_index));
            continue;
        }

        // save current label index
        label_indexes.push(i);

        // skip to next label
        i += length + 1;
    }

    return (next_index, label_indexes);
}

// get the name from labels inside raw packet bytes
fn get_name_from_labels(raw: &[u8], label_indexes: &Vec<usize>) -> String {
    let mut name = String::new();
    for i in label_indexes {
        // get length of current label from first byte
        let length: usize = usize::from(raw[*i]);

        // read domain name part from current label
        let j = i + 1;
        let part = match str::from_utf8(&raw[j..j + length]) {
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
                let dns = match DnsPacket::new(packet.payload()) {
                    Some(dns) => dns,
                    None => {
                        println!("malformed dns packet");
                        continue;
                    }
                };
                println!("got dns packet from {}: {}", addr, dns);

                // handle questions in dns packet
                for i in 0..dns.get_questions().into() {
                    match dns.get_question(0) {
                        None => {}
                        Some(question) => {
                            println!("Question {}:", i);
                            println!("  Name: {}", question.get_name());
                            println!("  Type: {}", question.get_type());
                            println!("  Class: {}", question.get_class());
                        }
                    }
                }

                // handle answers in dns packet
                for i in 0..dns.get_answers().into() {
                    match dns.get_answer(i) {
                        None => {}
                        Some(answer) => {
                            println!("Answer {}:", i);
                            println!("  Name: {}", answer.get_name());
                            println!("  Type: {}", answer.get_type());
                            println!("  Class: {}", answer.get_class());
                            println!("  TTL: {}", answer.get_ttl());
                            println!("  Data Length: {}", answer.get_data_length());
                        }
                    }
                }

                // handle authorities in dns packet
                for i in 0..dns.get_authorities().into() {
                    match dns.get_authority(i) {
                        None => {}
                        Some(authority) => {
                            println!("Authority {}:", i);
                            println!("  Name: {}", authority.get_name());
                            println!("  Type: {}", authority.get_type());
                            println!("  Class: {}", authority.get_class());
                            println!("  TTL: {}", authority.get_ttl());
                            println!("  Data Length: {}", authority.get_data_length());
                        }
                    }
                }

                // handle additionals in dns packet
                for i in 0..dns.get_additionals().into() {
                    match dns.get_additional(i) {
                        None => {}
                        Some(additional) => {
                            println!("Additional {}:", i);
                            println!("  Name: {}", additional.get_name());
                            println!("  Type: {}", additional.get_type());
                            println!("  Class: {}", additional.get_class());
                            println!("  TTL: {}", additional.get_ttl());
                            println!("  Data Length: {}", additional.get_data_length());
                        }
                    }
                }
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}
