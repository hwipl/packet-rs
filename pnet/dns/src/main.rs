use std::convert::TryInto;
use std::fmt;

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
}

impl<'a> DnsQuestion<'a> {
    // create a new dns question from raw packet bytes
    pub fn new(raw: &'a [u8]) -> Option<DnsQuestion<'a>> {
        if raw.len() < DNS_MIN_QUESTION_LENGTH {
            println!("short dns question with length {}", raw.len());
            None
        } else {
            Some(DnsQuestion { raw: raw })
        }
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
}

impl<'a> DnsPacket<'a> {
    // create a new dns packet from raw packet bytes
    pub fn new(raw: &'a [u8]) -> Option<DnsPacket<'a>> {
        if raw.len() < DNS_HEADER_LENGTH {
            println!("short dns packet with length {}", raw.len());
            None
        } else {
            Some(DnsPacket { raw: raw })
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

    // get first question from packet
    // TODO: add number parameter for retrieving specific question
    pub fn get_question(&self) -> Option<DnsQuestion> {
        if self.get_questions() == 0 {
            return None;
        }
        DnsQuestion::new(&self.raw[DNS_HEADER_LENGTH..])
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
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}
