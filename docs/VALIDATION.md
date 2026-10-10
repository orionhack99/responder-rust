# Validation Record — Rust Responder

**Date**: 2026-10-10
**Environment**: Linux dev container, Rust 1.99.0 (edition 2024). The container has permission to
bind privileged ports, but no Windows/dhcpv6 client VM is attached, so the end-to-end lab
scenarios in `quickstart.md` that require a real victim were validated at the protocol level via
automated tests rather than live clients. This file records exactly what was and was not run.

## Automated validation (`cargo test`)

70 tests pass across unit / integration / contract layers.

| Area | Test target | Result |
|------|-------------|--------|
| Encoders/helpers | `tests/unit/test_util.rs` (9) | pass |
| NTLMSSP challenge + Type 3 parse/formats | `tests/unit/test_ntlm.rs` (8) | pass |
| DNS poison response + domain filter | `tests/unit/test_dns_poison.rs` (7) | pass |
| APOP/CRAM-MD5/DIGEST-MD5 | `tests/unit/test_challenge.rs` (6) | pass |
| Config + CLI merge | `tests/unit/test_config.rs` (6) | pass |
| Output formats, file naming, DB schema, dedup | `tests/contract/test_output_formats.rs` (6) | pass |
| Reference `Responder.conf` compatibility | `tests/contract/test_config_compat.rs` (3) | pass |
| CLI surface, `--help`/`--version`, missing interface | `tests/contract/test_cli_surface.rs` (5) | pass |
| SMB NEGOTIATE + SESSION_SETUP NetNTLMv2 capture | `tests/integration/test_smb_capture.rs` (1) | pass |
| HTTP Basic + NTLM capture | `tests/integration/test_http_capture.rs` (3) | pass |
| FTP/POP3/SMTP cleartext + APOP | `tests/integration/test_mail_services.rs` (3) | pass |
| Review/list/export + dedup | `tests/integration/test_review_export.rs` (1) | pass |
| DHCPv4/DHCPv6 reply builders + NBT-NS codec | `tests/integration/test_dns_dhcp.rs` (7) | pass |
| LDAP simple bind + WinRM NTLM | `tests/integration/test_ldap_winrm.rs` (2) | pass |
| Analyze mode (zero responses) / active respond | `tests/integration/test_analyze_mode.rs` (2) | pass |
| 50 concurrent SMB sessions | `tests/integration/test_soak.rs` (1) | pass |

Static analysis: `cargo clippy --all-targets` is warning-free; `cargo fmt --check` is clean;
there are no `unsafe` blocks in the crate.

## Smoke test (startup)

`responder -I lo -A` starts, binds all 21 services (LLMNR, NBT-NS, mDNS, DNS udp+tcp, DHCPv6,
SMB, HTTP, HTTPS, FTP, POP, SMTP, IMAP, IMAPS, MSSQL, LDAP, LDAPS, Kerberos, RDP, WinRM, WinRMS,
DCERPC), prints the startup summary, and shuts down cleanly on signal. `--help` renders the full
option surface.

## Not validated live (see residual tasks T039, T041, T042, T079)

- MSSQL `/ Kerberos / RDP(CredSSP) / DCERPC` capture with a real Windows client (services are
  implemented and compile; no dedicated integration test authored).
- IMAPS / STARTTLS / LDAPS TLS-wrapped capture paths (TLS config + native TLS smoke is exercised
  only indirectly).
- DHCPv6 and DNS domain-filter behaviour against a live IPv6 client.
- macOS interface/`-i` behaviour and `#[cfg(target_os)]` guards (T079).
