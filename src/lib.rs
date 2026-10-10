//! Responder — an LLMNR/NBT-NS/mDNS poisoner and rogue authentication server, implemented in
//! Rust with behaviour compatible with the reference tool.
//!
//! The crate is organised as:
//! - [`cli`]/[`config`] — invocation surface and `Responder.conf` parsing.
//! - [`poisoners`] — name-resolution spoofing (LLMNR/NBT-NS/mDNS/DNS/DHCP/DHCPv6).
//! - [`protocols`] — wire codecs (NTLM, SMB2, TDS, DCE/RPC, LDAP/BER, Kerberos).
//! - [`servers`] — rogue authentication servers wired to the capture pipeline.
//! - [`capture`]/[`logger`]/[`store`] — artifact persistence (files + SQLite).

pub mod capture;
pub mod cli;
pub mod config;
pub mod constants;
pub mod crypto;
pub mod logger;
pub mod net;
pub mod poisoners;
pub mod protocols;
pub mod report;
pub mod servers;
pub mod store;
pub mod util;
