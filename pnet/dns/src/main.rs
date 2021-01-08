use std::convert::TryInto;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{transport_channel, udp_packet_iter};

const DNS_PORT: u16 = 53;

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
                println!("got dns packet from {}", addr);
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}
