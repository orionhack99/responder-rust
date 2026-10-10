//! Integration tests for the DHCP/DHCPv6 reply builders and the NBT-NS codec.

use std::net::{Ipv4Addr, Ipv6Addr};

use responder::poisoners::dhcp;
use responder::poisoners::dhcpv6;
use responder::poisoners::nbtns;

const MAGIC: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

fn dhcp_request(msg_type: u8) -> Vec<u8> {
    let mut p = vec![0u8; 240];
    p[0] = 1; // BOOTREQUEST
    p[1] = 1; // Ethernet
    p[2] = 6; // hlen
    p[4..8].copy_from_slice(&0xdead_beefu32.to_be_bytes()); // xid
    p[28..34].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    p[236..240].copy_from_slice(&MAGIC);
    p.extend_from_slice(&[53, 1, msg_type]);
    p.push(255);
    p
}

#[test]
fn dhcp_discover_offered_with_wpad() {
    let req = dhcp_request(1);
    assert_eq!(dhcp::message_type(&req), Some(1));

    let reply = dhcp::build_reply(&req, Ipv4Addr::new(10, 0, 0, 1), true).unwrap();
    assert_eq!(dhcp::message_type(&reply), Some(2), "DISCOVER -> OFFER");
    assert!(reply.windows(8).any(|w| w == b"wpad.dat"));
}

#[test]
fn dhcp_request_acked_with_dns_when_not_wpad() {
    let req = dhcp_request(3);
    let server = Ipv4Addr::new(10, 0, 0, 77);
    let reply = dhcp::build_reply(&req, server, false).unwrap();
    assert_eq!(dhcp::message_type(&reply), Some(5), "REQUEST -> ACK");
    // DNS option (6) carries our address.
    assert!(
        reply
            .windows(5)
            .any(|w| w[0] == 6 && w[1] == 4 && w[2..5] == server.octets()[..3])
    );
    assert!(!reply.windows(8).any(|w| w == b"wpad.dat"));
}

#[test]
fn dhcp_build_reply_rejects_non_dhcp() {
    assert!(dhcp::build_reply(&[0u8; 10], Ipv4Addr::LOCALHOST, false).is_none());
}

#[test]
fn dhcpv6_solicit_advertise_with_dns() {
    // SOLICIT with a client-id option.
    let mut req = vec![1u8, 0xaa, 0xbb, 0xcc];
    req.extend_from_slice(&[0x00, 0x01, 0x00, 0x02, 0xde, 0xad]); // client-id
    let dns = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x1);
    let reply = dhcpv6::build_reply(&req, dns, &["corp.local".to_string()]).unwrap();
    assert_eq!(reply[0], 2, "SOLICIT -> ADVERTISE");
    // DNS servers option (23) present with our address.
    assert!(reply.windows(2).any(|w| w == [0x00, 23]));
    assert!(reply.windows(16).any(|w| w == dns.octets()));
}

#[test]
fn dhcpv6_info_request_reply() {
    let req = vec![11u8, 0, 0, 1];
    let reply = dhcpv6::build_reply(&req, Ipv6Addr::LOCALHOST, &[]).unwrap();
    assert_eq!(reply[0], 7, "INFORMATION-REQUEST -> REPLY");
}

fn encode_nbt_name(name: &str) -> Vec<u8> {
    let mut raw = [b' '; 16];
    for (i, c) in name.to_ascii_uppercase().bytes().take(15).enumerate() {
        raw[i] = c;
    }
    raw[15] = 0x00; // workstation
    let mut out = vec![0x20u8];
    for b in raw {
        out.push(b'A' + (b >> 4));
        out.push(b'A' + (b & 0x0f));
    }
    out.push(0x00);
    out
}

fn nbt_query(name: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&0x1234u16.to_be_bytes()); // txid
    p.extend_from_slice(&0x0110u16.to_be_bytes()); // query, broadcast
    p.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&encode_nbt_name(name));
    p.extend_from_slice(&0x0020u16.to_be_bytes()); // NB
    p.extend_from_slice(&0x0001u16.to_be_bytes()); // IN
    p
}

#[test]
fn nbtns_parse_and_respond() {
    let q = nbtns::parse(&nbt_query("WPAD")).expect("parsed");
    assert_eq!(q.name, "WPAD");
    assert_eq!(q.txid, 0x1234);

    let ip = Ipv4Addr::new(10, 0, 0, 1);
    let resp = nbtns::build_response(&q, ip, 30);
    assert_eq!(&resp[0..2], &0x1234u16.to_be_bytes());
    assert_eq!(&resp[2..4], &0x8400u16.to_be_bytes()); // response + authoritative
    assert_eq!(&resp[6..8], &1u16.to_be_bytes(), "ANCOUNT");
    assert_eq!(&resp[resp.len() - 4..], &ip.octets());
}

#[test]
fn nbtns_rejects_responses() {
    let mut p = nbt_query("WPAD");
    p[2..4].copy_from_slice(&0x8400u16.to_be_bytes()); // mark as response
    assert!(nbtns::parse(&p).is_none());
}
