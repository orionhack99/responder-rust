//! Unit tests for config-file parsing and CLI/config merging.

#[path = "../common/mod.rs"]
mod common;

use clap::Parser;

use responder::capture::model::Ttl;
use responder::cli::Cli;
use responder::config::{Settings, resolve};
use responder::constants::Service;

#[test]
fn defaults_match_contract() {
    let s = Settings::default();
    assert!(s.service_enabled(Service::Smb));
    assert!(s.service_enabled(Service::Http));
    assert!(s.service_enabled(Service::Dns));
    assert!(
        !s.service_enabled(Service::Dhcp),
        "DHCPv4 is off by default"
    );
    assert!(s.session_log);
    assert_eq!(s.database, "Responder.db");
    assert_eq!(s.ttl, "1e");
}

#[test]
fn config_file_toggles_services() {
    let td = common::TempDir::new("cfg");
    let path = td.path.join("Responder.conf");
    std::fs::write(
        &path,
        "[Responder Core]\n\
         SMB = Off\n\
         DNS = Off\n\
         SQL = On\n\
         HTTP = yes\n\
         SessionLog = Off\n\
         LogToFile = False\n\
         [DNS Server]\n\
         TTL = random\n",
    )
    .unwrap();

    let (s, existed) = Settings::load(path.to_str().unwrap()).unwrap();
    assert!(existed);
    assert!(!s.service_enabled(Service::Smb));
    assert!(!s.service_enabled(Service::Dns));
    assert!(s.service_enabled(Service::Mssql));
    assert!(s.service_enabled(Service::Http));
    assert!(!s.session_log);
    assert!(!s.log_to_file);
    assert_eq!(s.ttl, "random");
    // An unspecified key keeps its default.
    assert!(s.service_enabled(Service::Ftp));
}

#[test]
fn missing_file_yields_defaults() {
    let (s, existed) = Settings::load("/nonexistent/Responder.conf").unwrap();
    assert!(!existed);
    assert!(s.service_enabled(Service::Smb));
}

#[test]
fn cli_enables_dhcp_and_disables_wpad_on_dhcp_dns() {
    let cli = Cli::try_parse_from(["responder", "-I", "eth0", "-d"]).unwrap();
    let cfg = resolve(&cli, &Settings::default()).unwrap();
    assert!(cfg.is_enabled(Service::Dhcp));
    assert_eq!(cfg.interface, "eth0");

    let cli = Cli::try_parse_from(["responder", "-I", "eth0", "-w", "-D"]).unwrap();
    let cfg = resolve(&cli, &Settings::default()).unwrap();
    assert!(!cfg.wpad, "-D must disable WPAD injection");
}

#[test]
fn cli_advanced_options() {
    let cli = Cli::try_parse_from([
        "responder",
        "-I",
        "eth0",
        "-e",
        "10.1.1.1",
        "-t",
        "1e",
        "-N",
        "WPADSERVER",
    ])
    .unwrap();
    let cfg = resolve(&cli, &Settings::default()).unwrap();
    assert_eq!(cfg.external_ip, Some("10.1.1.1".parse().unwrap()));
    assert_eq!(cfg.ttl, Ttl::Fixed(0x1e));
    assert_eq!(cfg.answer_name.as_deref(), Some("WPADSERVER"));

    let cli = Cli::try_parse_from(["responder", "-I", "eth0", "-t", "random"]).unwrap();
    let cfg = resolve(&cli, &Settings::default()).unwrap();
    assert_eq!(cfg.ttl, Ttl::Random);
}

#[test]
fn resolve_requires_interface() {
    let cli = Cli::try_parse_from(["responder"]).unwrap();
    assert!(resolve(&cli, &Settings::default()).is_err());
}
