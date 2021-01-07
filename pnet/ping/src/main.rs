extern crate pnet;

use pnet::datalink::Channel;
use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::{MutablePacket, Packet};

use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr};

// packet constants
const ECHO_SIZE: usize = MutableEchoRequestPacket::minimum_packet_size();
const IPV4_SIZE: usize = MutableIpv4Packet::minimum_packet_size() + ECHO_SIZE;
const PACKET_SIZE: usize = MutableEthernetPacket::minimum_packet_size() + IPV4_SIZE;

// get default interface
fn get_default_interface() -> NetworkInterface {
    let interfaces = pnet::datalink::interfaces();
    let interface = interfaces
        .iter()
        .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty())
        .unwrap();
    interface.clone()
}

// get interface ip address
fn get_interface_ip(interface: &NetworkInterface) -> Ipv4Addr {
    let ip = interface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| match ip.ip() {
            IpAddr::V4(ip) => ip,
            _ => unreachable!(),
        })
        .unwrap();
    return ip;
}

// create ping/echo request packet
fn create_ping_packet(interface: &NetworkInterface) -> [u8; PACKET_SIZE] {
    // get source ip address
    let source_ip = get_interface_ip(&interface);

    // create echo request packet
    let mut echo_buffer = [0u8; ECHO_SIZE];
    let mut echo_packet = MutableEchoRequestPacket::new(&mut echo_buffer).unwrap();
    echo_packet.set_icmp_type(IcmpTypes::EchoRequest);
    echo_packet.set_checksum(pnet::util::checksum(echo_packet.packet(), 1));

    // create ipv4 packet
    let mut ipv4_buffer = [0u8; IPV4_SIZE];
    let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_total_length(u16::try_from(IPV4_SIZE).unwrap());
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_source(source_ip);
    ipv4_packet.set_destination(Ipv4Addr::BROADCAST);
    ipv4_packet.set_checksum(pnet::util::checksum(ipv4_packet.packet(), 5));
    ipv4_packet.set_payload(echo_packet.packet_mut());

    // create ethernet packet
    let mut ethernet_buffer = [0u8; PACKET_SIZE];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.set_source(interface.mac.unwrap());
    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_ethertype(EtherTypes::Ipv4);
    ethernet_packet.set_payload(ipv4_packet.packet_mut());

    return ethernet_buffer;
}

// send a ping packet
fn send_ping() {
    // get default interface
    let interface = get_default_interface();
    println!("Sending echo request on interface {}", interface.name);

    // create channel
    let (mut tx, _) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    // send packet
    let ethernet_buffer = create_ping_packet(&interface);
    tx.send_to(&ethernet_buffer, None).unwrap().unwrap();
}

fn main() {
    send_ping();
}
