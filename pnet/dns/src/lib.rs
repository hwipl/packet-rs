mod characters;
mod error;
mod helpers;
mod labels;
mod packet;
mod record;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::Packet;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{tcp_packet_iter, transport_channel, udp_packet_iter};

use helpers::*;
use packet::*;

const DNS_PORT: u16 = 53;

// run udp listener and handle dns packets
fn listen_udp() {
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
                print!("got udp dns packet from {}: ", addr);
                match DnsPacket::parse(packet.payload()) {
                    Ok(dns) => println!("{}", dns),
                    Err(e) => println!("malformed dns packet: {}", e),
                };
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}

// run tcp listener and handle dns packets
// note: only handles single dns packets that fit in a single tcp segment,
// no tcp re-assembly
fn listen_tcp() {
    // create an udp channel
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));
    let (_, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occurred when creating the transport channel: {}",
            e
        ),
    };

    // read udp packets from channel and handle dns packets
    let mut iter = tcp_packet_iter(&mut rx);
    loop {
        match iter.next() {
            Ok((packet, addr)) => {
                // only handle dns packets
                if packet.get_source() != DNS_PORT && packet.get_destination() != DNS_PORT {
                    continue;
                }

                // ignore syn and fin packets
                let flags = packet.get_flags();
                if flags & TcpFlags::SYN != 0 || flags & TcpFlags::FIN != 0 {
                    continue;
                }

                // get length of dns message from first two bytes and
                // get message from remaining data
                let data = packet.payload();
                if data.len() < 2 + DNS_HEADER_LENGTH {
                    continue;
                }
                let length = usize::from(read_be_u16(&data[..2]));
                if data.len() < 2 + length {
                    continue;
                }
                let msg = &data[2..2 + length];

                // parse dns packet
                print!("got tcp dns packet from {}: ", addr);
                match DnsPacket::parse(msg) {
                    Ok(dns) => println!("{}", dns),
                    Err(e) => println!("malformed dns packet: {}: {:?}", e, packet.payload()),
                };
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}

// run udp and tcp listener in separate threads and handle dns packets
pub fn listen() {
    let udp = std::thread::spawn(|| listen_udp());
    let tcp = std::thread::spawn(|| listen_tcp());
    let _ = udp.join();
    let _ = tcp.join();
}
