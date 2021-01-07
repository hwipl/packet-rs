extern crate pnet;

use pnet::packet::icmp::IcmpTypes;
use pnet::packet::icmp::MutableIcmpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::icmp_packet_iter;
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;

fn main() {
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occurred when creating the transport channel: {}",
            e
        ),
    };

    let mut iter = icmp_packet_iter(&mut rx);
    loop {
        match iter.next() {
            Ok((packet, addr)) => {
                // only handle icmp echo requests
                if packet.get_icmp_type() != IcmpTypes::EchoRequest {
                    continue;
                }
                println!("got icmp echo request from {}", addr);

                // create echo reply packet
                let mut vec: Vec<u8> = vec![0; packet.packet().len()];
                let mut reply = MutableIcmpPacket::new(&mut vec[..]).unwrap();

                reply.clone_from(&packet);
                reply.set_icmp_type(IcmpTypes::EchoReply);
                reply.set_checksum(pnet::util::checksum(reply.packet(), 1));

                // send echo reply back to sender address
                match tx.send_to(reply, addr) {
                    Ok(n) => assert_eq!(n, packet.packet().len()),
                    Err(e) => panic!("failed to send packet: {}", e),
                }
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}
