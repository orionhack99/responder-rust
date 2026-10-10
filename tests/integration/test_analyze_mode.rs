//! Integration test: analyze mode observes queries but never emits a response (SC-005).
//!
//! Uses the NBT-NS poisoner because it can be bound to an arbitrary loopback port and needs no
//! multicast membership, making the answer/no-answer distinction directly observable.

#[path = "../common/mod.rs"]
mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use responder::poisoners::{PoisonConfig, nbtns};

fn encode_nbt_name(name: &str) -> Vec<u8> {
    let mut raw = [b' '; 16];
    for (i, c) in name.to_ascii_uppercase().bytes().take(15).enumerate() {
        raw[i] = c;
    }
    raw[15] = 0x00;
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
    p.extend_from_slice(&0x4242u16.to_be_bytes());
    p.extend_from_slice(&0x0110u16.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&encode_nbt_name(name));
    p.extend_from_slice(&0x0020u16.to_be_bytes());
    p.extend_from_slice(&0x0001u16.to_be_bytes());
    p
}

/// Reserve a free loopback UDP port by binding and immediately dropping a socket.
fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn client_socket() -> tokio::net::UdpSocket {
    // Bind to 127.0.0.2 so the source address differs from the poisoned answer (self-poison guard).
    tokio::net::UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0))
        .await
        .unwrap()
}

#[tokio::test]
async fn analyze_mode_observes_without_responding() {
    let port = free_udp_port();
    let td = common::TempDir::new("analyze");
    let (ctx, mut rx) = common::make_ctx(&td);

    let mut pcfg = PoisonConfig::new(Ipv4Addr::new(127, 0, 0, 1));
    pcfg.analyze = true;
    let task = tokio::spawn(nbtns::run(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        Arc::new(pcfg),
        ctx.sink.clone(),
        ctx.logger.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(150)).await;

    let client = client_socket().await;
    client
        .send_to(
            &nbt_query("WPAD"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        )
        .await
        .unwrap();

    // The query is logged...
    let q = common::recv_query(&mut rx, 2)
        .await
        .expect("query observed");
    assert!(q.analysis_only);
    assert!(!q.answered);

    // ...but no datagram comes back.
    let mut buf = [0u8; 512];
    let got = tokio::time::timeout(Duration::from_millis(400), client.recv_from(&mut buf)).await;
    assert!(got.is_err(), "analyze mode must not respond");

    task.abort();
}

#[tokio::test]
async fn active_mode_responds() {
    let port = free_udp_port();
    let td = common::TempDir::new("active");
    let (ctx, mut rx) = common::make_ctx(&td);

    let pcfg = PoisonConfig::new(Ipv4Addr::new(127, 0, 0, 1));
    let task = tokio::spawn(nbtns::run(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        Arc::new(pcfg),
        ctx.sink.clone(),
        ctx.logger.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(150)).await;

    let client = client_socket().await;
    client
        .send_to(
            &nbt_query("WPAD"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        )
        .await
        .unwrap();

    let q = common::recv_query(&mut rx, 2)
        .await
        .expect("query observed");
    assert!(q.answered);

    let mut buf = [0u8; 512];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("a response")
        .unwrap();
    // NBT-NS response header: same transaction id, response flags.
    assert_eq!(&buf[0..2], &0x4242u16.to_be_bytes());
    assert_eq!(&buf[2..4], &0x8400u16.to_be_bytes());
    assert!(n > 12);

    task.abort();
}
