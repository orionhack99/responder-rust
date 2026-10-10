//! Unit tests for the DNS-format poison response builder and domain filter.

use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};

use responder::capture::model::{Protocol, Ttl};
use responder::poisoners::{PoisonConfig, dns_response, domain_allowed, nxdomain, query_event};

fn query(name: &str, rtype: RecordType) -> Message {
    let mut m = Message::new(0x1234, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_utf8(name).unwrap(), rtype));
    m
}

fn cfg() -> PoisonConfig {
    let mut c = PoisonConfig::new(Ipv4Addr::new(10, 0, 0, 1));
    c.ttl = Ttl::Fixed(31);
    c
}

#[test]
fn answers_a_with_configured_ip() {
    let resp = dns_response(&query("foo.local.", RecordType::A), &cfg());
    assert_eq!(resp.metadata.id, 0x1234);
    assert_eq!(resp.metadata.message_type, MessageType::Response);
    assert!(resp.metadata.recursion_available);
    assert_eq!(resp.answers.len(), 1);
    match &resp.answers[0].data {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(10, 0, 0, 1)),
        other => panic!("unexpected rdata {other:?}"),
    }
}

#[test]
fn aaaa_answered_only_when_ipv6_configured() {
    let q = query("host.local.", RecordType::AAAA);
    let mut c = cfg();
    assert_eq!(dns_response(&q, &c).answers.len(), 0);
    c.answer_ipv6 = Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
    let resp = dns_response(&q, &c);
    assert_eq!(resp.answers.len(), 1);
    assert!(matches!(&resp.answers[0].data, RData::AAAA(_)));
}

#[test]
fn any_and_other_types_resolve_to_us() {
    for rt in [RecordType::ANY, RecordType::MX, RecordType::SRV] {
        let resp = dns_response(&query("svc.local.", rt), &cfg());
        assert_eq!(resp.answers.len(), 1, "type {rt:?}");
        assert!(matches!(&resp.answers[0].data, RData::A(_)));
    }
}

#[test]
fn answer_name_override_is_used() {
    let mut c = cfg();
    c.answer_name = Some("wpad".to_string());
    let resp = dns_response(&query("anything.local.", RecordType::A), &c);
    assert_eq!(resp.answers.len(), 1);
    assert!(resp.answers[0].name.to_utf8().starts_with("wpad"));
}

#[test]
fn nxdomain_sets_response_code() {
    let resp = nxdomain(&query("blocked.example.", RecordType::A));
    assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(resp.queries.len(), 1);
    assert!(resp.answers.is_empty());
}

#[test]
fn domain_filter() {
    assert!(domain_allowed("anything", &[]));
    let filter = vec!["corp.local".to_string()];
    assert!(domain_allowed("wpad.corp.local", &filter));
    assert!(domain_allowed("corp.local", &filter));
    assert!(!domain_allowed("wpad.other.com", &filter));
    assert!(!domain_allowed("notcorp.local", &filter));
}

#[test]
fn query_event_marks_analysis() {
    let q = query_event(
        Protocol::Llmnr,
        "10.0.0.9".parse().unwrap(),
        "wpad",
        "A",
        false,
        true,
    );
    assert!(!q.answered);
    assert!(q.analysis_only);
    assert_eq!(q.protocol, Protocol::Llmnr);
}
