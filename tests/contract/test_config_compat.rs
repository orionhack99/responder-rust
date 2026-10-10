//! Contract test: a reference-style `Responder.conf` loads with the documented semantics.

#[path = "../common/mod.rs"]
mod common;

use responder::config::Settings;
use responder::constants::Service;

const REFERENCE_CONF: &str = "\
[Responder Core]

; Servers to start
SQL = On
SMB = On
RDP = On
Kerberos = On
FTP = On
POP = On
SMTP = On
IMAP = On
IMAPS = On
HTTP = On
HTTPS = On
DNS = On
LDAP = On
DCERPC = On
WINRM = On
LLMNR = On
NBTNS = On
MDNS = On
DHCP = Off
DHCPv6 = Off

; Logging
SessionLog = On
LogToFile = On
Verbose = On
Database = Responder.db

[HTTP Server]
HtmlFilename = files/AccessDenied.html

[DHCPv6 Server]
DHCPv6_Domain =
BindToIPv6 = ::

[DNS Server]
DNS_Domain = corp.local
TTL = 1e
";

fn load(text: &str, tag: &str) -> Settings {
    let td = common::TempDir::new(tag);
    let path = td.path.join("Responder.conf");
    std::fs::write(&path, text).unwrap();
    Settings::load(path.to_str().unwrap()).unwrap().0
}

#[test]
fn reference_conf_parses() {
    let s = load(REFERENCE_CONF, "refconf");
    for svc in [
        Service::Smb,
        Service::Http,
        Service::Https,
        Service::Dns,
        Service::Ldap,
        Service::Kerberos,
        Service::Ftp,
        Service::Pop3,
        Service::Smtp,
        Service::Imap,
        Service::Imaps,
        Service::Mssql,
        Service::Rdp,
        Service::Winrm,
        Service::Dcerpc,
        Service::Llmnr,
        Service::NbtNs,
        Service::Mdns,
    ] {
        assert!(s.service_enabled(svc), "{svc:?} should be enabled");
    }
    assert!(!s.service_enabled(Service::Dhcp));
    assert!(!s.service_enabled(Service::Dhcpv6));
    assert_eq!(s.dns_domain, "corp.local");
    assert_eq!(s.html_filename, "files/AccessDenied.html");
    assert_eq!(s.bind_ipv6, Some("::".parse().unwrap()));
    assert_eq!(s.database, "Responder.db");
}

#[test]
fn boolean_coercion_accepts_all_spellings() {
    for (token, expected) in [
        ("On", true),
        ("off", false),
        ("YES", true),
        ("No", false),
        ("True", true),
        ("false", false),
    ] {
        let conf = format!("[Responder Core]\nSMB = {token}\n");
        let s = load(&conf, "boolcoerce");
        assert_eq!(s.service_enabled(Service::Smb), expected, "SMB = {token}");
    }
}

#[test]
fn unknown_keys_are_ignored() {
    let conf = "[Responder Core]\nSMB = On\nTotallyUnknownKey = whatever\n";
    let s = load(conf, "unknown");
    assert!(s.service_enabled(Service::Smb));
}
