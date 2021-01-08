use std::convert::TryInto;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{transport_channel, udp_packet_iter};

const DNS_HEADER_LENGTH: usize = 12;
const DNS_PORT: u16 = 53;

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
                println!(
                    "got dns packet from {}:
                    id: {}
                    flags: {}",
                    addr,
                    dns.get_id(),
                    dns.get_flags(),
                );
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}
