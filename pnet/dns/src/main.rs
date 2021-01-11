use std::convert::TryInto;
use std::fmt;
use std::str;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{transport_channel, udp_packet_iter};

const DNS_HEADER_LENGTH: usize = 12;
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
    raw: &'a [u8],

    // indexes of labels within the packet
    label_indexes: Vec<usize>,

    // indexes of type and class fields that are after the labels
    type_index: usize,
    class_index: usize,
}

impl<'a> DnsQuestion<'a> {
    // create a new dns question from raw packet bytes
    pub fn new(raw: &'a [u8]) -> Option<DnsQuestion<'a>> {
        if raw.len() < DNS_MIN_QUESTION_LENGTH {
            println!("short dns question with length {}", raw.len());
            None
        } else {
            let mut question = DnsQuestion {
                raw: raw,
                label_indexes: Vec::new(),
                type_index: 0,
                class_index: 0,
            };
            question.parse();
            Some(question)
        }
    }

    // parse the question packet:
    // find labels in the raw packet bytes,
    // find index of type field,
    // find index of class field.
    // TODO: add error handling
    fn parse(&mut self) {
        let mut i = 0;
        loop {
            if i >= self.raw.len() {
                break;
            }
            // get length of current label from first byte
            let length: usize = usize::from(self.raw[i]);

            // have we reached end of labels?
            if length == 0 {
                // save index of type field
                self.type_index = i + 1;
                self.class_index = i + 3;
                break;
            }
            // TODO: check if current label is a reference to another one

            // save current label index
            self.label_indexes.push(i);

            // skip to next label
            i += length + 1;
        }
    }

    // get the dns name from raw packet bytes
    pub fn print_name(&self) {
        println!("Domain name: {}", self.get_name());
    }

    // get the name field from raw packet bytes
    pub fn get_name(&self) -> String {
        let mut name = String::new();
        for i in &self.label_indexes {
            // get length of current label from first byte
            let length: usize = usize::from(self.raw[*i]);

            // TODO: check if current label is a reference to another one

            // read domain name part from current label
            let j = i + 1;
            let part = str::from_utf8(&self.raw[j..j + length]).unwrap();
            name.push_str(part);
            name += ".";
        }
        return name;
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
        self.class_index + 2
    }
}

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
    questions: Vec<DnsQuestion<'a>>,
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
                questions: Vec::new(),
            };
            packet.parse_questions();
            Some(packet)
        }
    }

    // parse dns packet and find questions
    // TODO: add error handling
    fn parse_questions(&mut self) {
        if self.get_questions() == 0 {
            return;
        }

        let mut offset = DNS_HEADER_LENGTH;
        for _ in 0..self.get_questions() {
            if offset >= self.raw.len() {
                println!("invalid number of questions and/or packet too short");
                return;
            }

            let q = DnsQuestion::new(&self.raw[offset..]);
            match q {
                None => return,
                Some(q) => {
                    offset += q.get_length();
                    self.questions.push(q);
                }
            }
        }
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

// convert a 16 bit field from big endian to native byte order
fn read_be_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(bytes.try_into().expect("slice with incorrect length"))
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

                // handle question in dns packet
                match dns.get_question(0) {
                    None => {}
                    Some(question) => {
                        question.print_name();
                        println!("Name: {}", question.get_name());
                        println!("Type: {}", question.get_type());
                        println!("Class: {}", question.get_class());
                    }
                }
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}
