# Responder (Rust)

[![CI](https://github.com/orionhack99/responder-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/orionhack99/responder-rust/actions/workflows/ci.yml)

A Rust reimplementation of [lgandx/Responder](https://github.com/lgandx/Responder): an
LLMNR/NBT-NS/mDNS poisoner paired with a set of rogue authentication servers that capture
NetNTLM hashes and cleartext credentials from clients that resolve names incorrectly.

> **⚠️ Authorization required.**
> This tool is for **isolated lab networks you own or are explicitly authorized to test**.
> Never run it against production or third-party networks. You are responsible for complying
> with all applicable laws.

## Features

- **Name-resolution poisoning**: LLMNR, NBT-NS, mDNS, rogue DNS, DHCPv4 (WPAD/DNS injection)
  and DHCPv6, with an analyze-only (passive) mode.
- **Rogue authentication servers**: SMB, HTTP/HTTPS/WPAD, FTP, POP3, SMTP, IMAP/IMAPS, MSSQL,
  LDAP/LDAPS, Kerberos, RDP, WinRM/WinRMS and DCERPC.
- **Cracker-ready output**: NetNTLMv1/v2 (`user::domain:challenge:NTProofStr:blob`), cleartext
  (`user:secret`), challenge-response (APOP/CRAM-MD5/DIGEST-MD5) and Kerberos AS-REQ material.
- **Persistence**: per-protocol log files, a session log, and a SQLite database with
  de-duplication.
- **Reference-compatible** CLI and `Responder.conf` option surface.

## Build

Requires a recent Rust toolchain (edition 2024, Rust 1.99+). Linux is the primary target.

```bash
cargo build --release
```

The binary is written to `target/release/responder`.

## Usage

```bash
# Full capture on one interface
sudo ./target/release/responder -I eth0

# Analyze only: observe name resolution, never answer
sudo ./target/release/responder -I eth0 -A

# Every usable interface
sudo ./target/release/responder -I ALL
```

### Options

```
-I, --interface <IFACE>      Interface to use (`ALL` = every usable interface)
-A, --analyze                Observe only; never respond
-w, --wpad                   Start the rogue WPAD proxy
-F, --ForceWpadAuth          Force auth on wpad.dat retrieval
-P, --ProxyAuth              Force auth for the rogue proxy
-d, --DHCP                   Answer DHCP with WPAD injection
-D, --DHCP-DNS               Inject the DNS server in DHCP instead of WPAD
    --dhcpv6                 Enable DHCPv6 poisoning
-e, --externalip <IPv4>      Answer with this external IPv4
-6, --externalip6 <IPv6>     Answer with this external IPv6
-i, --ip <IPv4>              Override the local IPv4 used in answers
-b, --basic                  Force HTTP Basic instead of NTLM
    --lm                     Force LM hashing (NTLMv1) downgrade
    --disable-ess            Disable Extended Session Security
-u, --upstream-proxy <URL>   Upstream proxy for WPAD
-t, --ttl <TTL>              Poison TTL (hex) or `random`
-N, --answer-name <NAME>     Name to claim in answers
-E, --error-code <CODE>      Spoofed error / STATUS code
-v, --verbose                Increase verbosity (repeatable)
-Q, --quiet                  Suppress routine output
    --config <PATH>          Config file (default Responder.conf)
-h, --help / --version
```

### Ports

| Service | Port(s) | Service | Port(s) |
|---------|---------|---------|---------|
| FTP | 21 | LDAP/LDAPS | 389 / 636 |
| SMTP | 25 / 587 | HTTPS | 443 |
| DNS | 53 (udp+tcp) | SMB | 445 / 139 |
| Kerberos | 88 | MSSQL | 1433 |
| POP3 | 110 | RDP | 3389 |
| DCERPC | 135 | WinRM/WinRMS | 5985 / 5986 |
| IMAP/IMAPS | 143 / 993 | LLMNR | 5355 |
| HTTP | 80 | mDNS | 5353 |
| NBT-NS | 137 | DHCPv6 | 547 |
| DHCPv4 | 67 | | |

Privileged ports and raw sockets require `root`, or the capabilities
`CAP_NET_BIND_SERVICE` + `CAP_NET_RAW`. When a service cannot bind, the tool reports it and keeps
serving the rest.

## Configuration

`Responder.conf` uses the reference INI layout. Booleans accept `On/Off`, `Yes/No`,
`True/False` (case-insensitive); unknown keys are ignored.

```ini
[Responder Core]
SMB = On
HTTP = On
HTTPS = On
DNS = On
DHCP = Off
DHCPv6 = On
SessionLog = On
LogToFile = On
Verbose = Yes
Database = Responder.db
SSLCert = certs/responder.crt
SSLKey = certs/responder.key

[HTTP Server]
HtmlFilename = files/AccessDenied.html

[DHCPv6 Server]
DHCPv6_Domain =
BindToIPv6 = fe80::1

[DNS Server]
DNS_Domain = corp.local
TTL = 1e
```

A self-signed cert/key pair is generated automatically into `certs/` on first use of a TLS
service if the files are missing.

## Output artifacts

Written to the working directory:

- Per-protocol files `<PROTOCOL>-<ARTIFACT>-<client-ip>.txt`, e.g.
  `SMB-NTLMv2-10.0.0.5.txt`, `HTTP-Cleartext-10.0.0.5.txt`.
- `Responder-Session.log` (when `SessionLog = On`).
- `Responder.db` — SQLite with tables `runs`, `hosts`, `sessions`, `captures`,
  `poisoned_queries` and a unique index on `captures.dedup_hash`.

```bash
sqlite3 Responder.db "SELECT protocol, artifact_type, client, formatted FROM captures;"
```

Cracking (out of scope, for reference): NetNTLMv2 → `hashcat -m 5600`, NetNTLMv1 → `-m 5500`.

## Architecture

- `src/main.rs` — CLI → config → interface → logger/store → single capture writer → spawn
  poisoners/servers → summary → wait for `Ctrl-C` → graceful shutdown.
- `src/capture/` — data model + a single-writer `mpsc` pipeline that serializes all persistence
  (files + DB) so output is never interleaved.
- `src/poisoners/` — LLMNR, NBT-NS, mDNS, DNS, DHCPv4, DHCPv6 (Tokio UDP + `hickory-proto`).
- `src/servers/` — one module per rogue auth service.
- `src/protocols/` — wire codecs (NTLMSSP, SMB2, BER/LDAP, TDS, DCERPC, Kerberos).
- `src/store.rs`, `src/logger.rs`, `src/report.rs` — persistence and review/export.

### Known deviations from the reference tool

- Poisoners use ordinary UDP sockets + a DNS codec rather than raw L2 `pnet` datalink frames
  (more portable; still answers LLMNR/NBT-NS/mDNS/DNS/DHCP on a shared segment). An unused raw
  datalink wrapper remains in `src/net/raw.rs`.
- The HTTP/1.1 stack is hand-rolled over a generic async stream (shared by TCP and TLS) instead
  of `hyper`; NTLM/Basic/Digest negotiation and capture behavior match.
- Kerberos, RDP (CredSSP) and DCERPC are best-effort: they assemble the required handshake and
  capture the NTLMSSP material.

## Tests

```bash
cargo test                      # unit + integration + contract suites
cargo clippy --all-targets
cargo fmt --check
```

See [`docs/VALIDATION.md`](docs/VALIDATION.md) for the validation record and known gaps.

## CI/CD

GitHub Actions workflows live in `.github/workflows/`:

- **`ci.yml`** — on every push/PR to `main`: `cargo fmt --check`, `cargo clippy -D warnings`,
  `cargo test`, a release build, and a `cargo-audit` dependency scan.
- **`release.yml`** — on tags matching `v*`: builds release binaries for
  `x86_64-unknown-linux-gnu` and `aarch64-apple-darwin`, and publishes them as GitHub Release
  assets.

Cut a release by pushing a tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Dependency and GitHub Actions updates are proposed weekly via `.github/dependabot.yml`.

## Disclaimer & attribution

This is an independent Rust reimplementation, inspired by and interoperable with
[lgandx/Responder](https://github.com/lgandx/Responder). It is intended strictly for authorized
security testing and research. The authors are not responsible for misuse.

Licensed under the **GNU General Public License v3.0 or later** — see [`LICENSE`](LICENSE).
