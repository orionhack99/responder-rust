//! Core data model: captured artifacts, poisoned queries, client hosts, sessions and the
//! resolved run-time configuration. Validation invariants from `data-model.md` are enforced by
//! the constructors here so the rest of the codebase can trust the values.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};

use crate::constants::Service;
use crate::protocols::ntlm::NetNtlm;
use crate::util;

/// Which rogue service or poisoner produced an artifact. The string form matches the
/// per-protocol log file prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Protocol {
    Llmnr,
    NbtNs,
    Mdns,
    Smb,
    Http,
    Https,
    Wpad,
    Ftp,
    Pop3,
    Smtp,
    Imap,
    Imaps,
    Mssql,
    Ldap,
    Ldaps,
    Kerberos,
    Dns,
    Rdp,
    Winrm,
    Winrms,
    Dcerpc,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Llmnr => "LLMNR",
            Protocol::NbtNs => "NBT-NS",
            Protocol::Mdns => "MDNS",
            Protocol::Smb => "SMB",
            Protocol::Http => "HTTP",
            Protocol::Https => "HTTPS",
            Protocol::Wpad => "WPAD",
            Protocol::Ftp => "FTP",
            Protocol::Pop3 => "POP",
            Protocol::Smtp => "SMTP",
            Protocol::Imap => "IMAP",
            Protocol::Imaps => "IMAPS",
            Protocol::Mssql => "MSSQL",
            Protocol::Ldap => "LDAP",
            Protocol::Ldaps => "LDAPS",
            Protocol::Kerberos => "Kerberos",
            Protocol::Dns => "DNS",
            Protocol::Rdp => "RDP",
            Protocol::Winrm => "WinRM",
            Protocol::Winrms => "WinRMS",
            Protocol::Dcerpc => "DCERPC",
        }
    }
}

/// The kind of secret captured. The suffix matches the reference tool's log file naming.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ArtifactType {
    NetNtlmV1,
    NetNtlmV2,
    Cleartext,
    CramMd5,
    DigestMd5,
    Apop,
    AsRep,
    Digest,
}

impl ArtifactType {
    /// File-name suffix (e.g. `NTLMv2`, `Cleartext`).
    pub fn file_suffix(&self) -> &'static str {
        match self {
            ArtifactType::NetNtlmV1 => "NTLMv1",
            ArtifactType::NetNtlmV2 => "NTLMv2",
            ArtifactType::Cleartext => "Cleartext",
            ArtifactType::CramMd5 => "CRAM-MD5",
            ArtifactType::DigestMd5 => "DIGEST-MD5",
            ArtifactType::Apop => "APOP",
            ArtifactType::AsRep => "ASREP",
            ArtifactType::Digest => "Digest",
        }
    }

    /// hashcat mode, when applicable (informational; written to the session log).
    pub fn hashcat_mode(&self) -> Option<u32> {
        match self {
            ArtifactType::NetNtlmV1 => Some(5500),
            ArtifactType::NetNtlmV2 => Some(5600),
            ArtifactType::AsRep => Some(18200),
            _ => None,
        }
    }
}

/// A single captured credential/artifact. Exactly one representation is populated depending on
/// `artifact_type`, and `formatted` is always non-empty.
#[derive(Clone, Debug)]
pub struct CaptureArtifact {
    pub protocol: Protocol,
    pub artifact_type: ArtifactType,
    pub client: IpAddr,
    pub timestamp: DateTime<Utc>,
    pub username: Option<String>,
    pub domain: Option<String>,
    /// Hex-encoded server challenge.
    pub challenge: Option<String>,
    /// Hex-encoded NTProofStr (v2) or NT response (v1).
    pub response: Option<String>,
    /// Hex-encoded NTLMv2 blob (`temp`).
    pub blob: Option<String>,
    /// Cleartext secret (password, APOP digest, etc.).
    pub secret: Option<String>,
    /// Raw bytes for artifacts that are not otherwise representable (e.g. AS-REQ/AS-REP).
    pub raw: Option<Vec<u8>>,
    /// The cracker-ready one-line representation.
    pub formatted: String,
    /// Stable de-duplication key.
    pub dedup_hash: String,
}

/// Stable de-duplication key derived from every identifying field of an artifact. Two captures
/// collapse only when protocol, artifact type, client address and the formatted credential line
/// are all identical; anything else is preserved.
fn dedup_key(
    protocol: Protocol,
    artifact_type: ArtifactType,
    client: IpAddr,
    formatted: &str,
) -> String {
    util::md5_hex(
        format!(
            "{}|{}|{}|{}",
            protocol.as_str(),
            artifact_type.file_suffix(),
            client,
            formatted
        )
        .as_bytes(),
    )
}

impl CaptureArtifact {
    /// Build a NetNTLMv1/v2 artifact from an NTLM AUTHENTICATE message.
    pub fn netntlm(protocol: Protocol, client: IpAddr, net: &NetNtlm) -> Self {
        let challenge = util::hex(&net.server_challenge);
        let response = util::hex(&net.nt_proof_str);
        let blob = net.blob.as_ref().map(|b| util::hex(b));
        let (artifact_type, formatted) = if let Some(blob) = &net.blob {
            (
                ArtifactType::NetNtlmV2,
                format!(
                    "{}::{}:{}:{}:{}",
                    net.user,
                    net.domain,
                    util::hex(&net.server_challenge),
                    util::hex(&net.nt_proof_str),
                    util::hex(blob),
                ),
            )
        } else {
            (
                ArtifactType::NetNtlmV1,
                format!(
                    "{}::{}:{}:{}",
                    net.user,
                    net.domain,
                    util::hex(&net.server_challenge),
                    util::hex(&net.nt_proof_str),
                ),
            )
        };
        let dedup_hash = dedup_key(protocol, artifact_type, client, &formatted);
        CaptureArtifact {
            protocol,
            artifact_type,
            client,
            timestamp: Utc::now(),
            username: Some(net.user.clone()),
            domain: Some(net.domain.clone()),
            challenge: Some(challenge),
            response: Some(response),
            blob,
            secret: None,
            raw: None,
            formatted,
            dedup_hash,
        }
    }

    /// Build a cleartext credential artifact.
    pub fn cleartext(protocol: Protocol, client: IpAddr, user: &str, secret: &str) -> Option<Self> {
        if secret.is_empty() {
            // Cleartext requires a non-empty secret.
            return None;
        }
        let formatted = format!("{user}:{secret}");
        Some(CaptureArtifact {
            protocol,
            artifact_type: ArtifactType::Cleartext,
            client,
            timestamp: Utc::now(),
            username: Some(user.to_string()),
            domain: None,
            challenge: None,
            response: None,
            blob: None,
            secret: Some(secret.to_string()),
            raw: None,
            dedup_hash: dedup_key(protocol, ArtifactType::Cleartext, client, &formatted),
            formatted,
        })
    }

    /// Build a challenge-response artifact (APOP / CRAM-MD5 / DIGEST-MD5).
    pub fn challenge_response(
        protocol: Protocol,
        artifact_type: ArtifactType,
        client: IpAddr,
        user: &str,
        secret: &str,
    ) -> Self {
        let formatted = format!("{user}:{secret}");
        CaptureArtifact {
            protocol,
            artifact_type,
            client,
            timestamp: Utc::now(),
            username: Some(user.to_string()),
            domain: None,
            challenge: None,
            response: None,
            blob: None,
            secret: Some(secret.to_string()),
            raw: None,
            dedup_hash: dedup_key(protocol, artifact_type, client, &formatted),
            formatted,
        }
    }

    /// Build an AS-REP / raw artifact for Kerberos and other binary exchanges.
    pub fn raw(protocol: Protocol, client: IpAddr, label: &str, raw: Vec<u8>) -> Self {
        let hex = util::hex(&raw);
        let formatted = format!("{label}:{hex}");
        CaptureArtifact {
            protocol,
            artifact_type: ArtifactType::AsRep,
            client,
            timestamp: Utc::now(),
            username: Some(label.to_string()),
            domain: None,
            challenge: None,
            response: None,
            blob: None,
            secret: None,
            raw: Some(raw),
            dedup_hash: dedup_key(protocol, ArtifactType::AsRep, client, &formatted),
            formatted,
        }
    }
}

/// A name-resolution query observed (and optionally answered) by a poisoner.
#[derive(Clone, Debug)]
pub struct PoisonedQuery {
    pub protocol: Protocol,
    pub client: IpAddr,
    pub name: String,
    pub record_type: String,
    pub timestamp: DateTime<Utc>,
    /// Whether the poisoner sent a response. In `Analyze` mode this is always false.
    pub answered: bool,
    /// True when the run is analyze-only.
    pub analysis_only: bool,
}

/// A client observed on the network.
#[derive(Clone, Debug)]
pub struct ClientHost {
    pub addr: IpAddr,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub hostname: Option<String>,
    pub mac: Option<String>,
}

impl ClientHost {
    pub fn new(addr: IpAddr) -> Self {
        let now = Utc::now();
        ClientHost {
            addr,
            first_seen: now,
            last_seen: now,
            hostname: None,
            mac: None,
        }
    }

    pub fn touch(&mut self) {
        self.last_seen = Utc::now();
    }
}

/// One `run` row: a single start-to-stop invocation of the toolkit.
#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub id: i64,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub interface: String,
    pub analyze: bool,
    pub artifact_count: i64,
}

/// Per-service run-time configuration.
#[derive(Clone, Debug)]
pub struct ServiceConfiguration {
    pub service: Service,
    pub enabled: bool,
    /// `Challenge=Random` marker or a fixed hex challenge override.
    pub challenge: Option<String>,
    pub custom_option: Option<String>,
    pub bind_ok: bool,
    pub bind_error: Option<String>,
}

impl ServiceConfiguration {
    pub fn new(service: Service, enabled: bool) -> Self {
        ServiceConfiguration {
            service,
            enabled,
            challenge: None,
            custom_option: None,
            bind_ok: false,
            bind_error: None,
        }
    }
}

/// Answer TTL policy (`-t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ttl {
    Fixed(u32),
    Random,
}

impl Ttl {
    pub fn resolve(&self) -> u32 {
        match self {
            Ttl::Fixed(t) => *t,
            Ttl::Random => rand::random::<u32>() % 128 + 1,
        }
    }
}

/// The fully-resolved run configuration (config file merged with CLI overrides).
#[derive(Clone, Debug)]
pub struct RunConfiguration {
    pub interface: String,
    pub analyze: bool,
    pub wpad: bool,
    pub force_wpad_auth: bool,
    pub force_basic_only: bool,
    pub proxy_auth: bool,
    pub upstream_proxy: Option<String>,
    pub external_ip: Option<Ipv4Addr>,
    pub external_ipv6: Option<Ipv6Addr>,
    pub local_ip: Option<IpAddr>,
    pub answer_name: Option<String>,
    pub ttl: Ttl,
    pub error_code: Option<String>,
    pub lm_downgrade: bool,
    pub disable_ess: bool,
    pub verbose: bool,
    pub quiet: bool,
    pub db_file: String,
    pub log_dir: String,
    pub html_filename: String,
    pub ssl_cert: String,
    pub ssl_key: String,
    /// Domain filter for DNS/DHCPv6 poisoning (empty = answer everything).
    pub dns_domains: Vec<String>,
    pub services: Vec<ServiceConfiguration>,
}

impl RunConfiguration {
    pub fn service(&self, service: Service) -> Option<&ServiceConfiguration> {
        self.services.iter().find(|s| s.service == service)
    }

    pub fn is_enabled(&self, service: Service) -> bool {
        self.service(service).map(|s| s.enabled).unwrap_or(false)
    }
}
