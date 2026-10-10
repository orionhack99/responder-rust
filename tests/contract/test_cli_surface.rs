//! Contract test for the CLI option surface (`contracts/cli.md`).

#[path = "../common/mod.rs"]
mod common;

use clap::CommandFactory;
use clap::Parser;
use clap::error::ErrorKind;

use responder::cli::Cli;

#[test]
fn clap_definition_is_valid() {
    Cli::command().debug_assert();
}

#[test]
fn help_and_version_exit_cleanly() {
    let help = Cli::try_parse_from(["responder", "--help"]).unwrap_err();
    assert_eq!(help.kind(), ErrorKind::DisplayHelp);
    let version = Cli::try_parse_from(["responder", "--version"]).unwrap_err();
    assert_eq!(version.kind(), ErrorKind::DisplayVersion);
}

#[test]
fn every_documented_option_parses() {
    let cli = Cli::try_parse_from([
        "responder",
        "-I",
        "eth0",
        "-A",
        "-w",
        "-F",
        "-P",
        "-d",
        "-D",
        "--dhcpv6",
        "-e",
        "10.0.0.1",
        "-6",
        "fe80::1",
        "-i",
        "10.0.0.2",
        "-b",
        "--lm",
        "--disable-ess",
        "-u",
        "proxy:8080",
        "-t",
        "1e",
        "-N",
        "WPAD",
        "-E",
        "0xC000006D",
        "-v",
        "-v",
        "-Q",
        "--config",
        "custom.conf",
    ])
    .unwrap();

    assert_eq!(cli.interface.as_deref(), Some("eth0"));
    assert!(cli.analyze && cli.wpad && cli.force_wpad_auth && cli.proxy_auth);
    assert!(cli.dhcp && cli.dhcp_dns && cli.dhcpv6);
    assert_eq!(cli.external_ip, Some("10.0.0.1".parse().unwrap()));
    assert_eq!(cli.external_ip6, Some("fe80::1".parse().unwrap()));
    assert_eq!(cli.local_ip, Some("10.0.0.2".parse().unwrap()));
    assert!(cli.basic && cli.lm && cli.disable_ess);
    assert_eq!(cli.upstream_proxy.as_deref(), Some("proxy:8080"));
    assert_eq!(cli.ttl.as_deref(), Some("1e"));
    assert_eq!(cli.answer_name.as_deref(), Some("WPAD"));
    assert_eq!(cli.error_code.as_deref(), Some("0xC000006D"));
    assert_eq!(cli.verbose, 2);
    assert!(cli.quiet);
    assert_eq!(cli.config, "custom.conf");
}

#[test]
fn error_code_flag_has_default_missing_value() {
    let cli = Cli::try_parse_from(["responder", "-I", "eth0", "-E"]).unwrap();
    assert_eq!(cli.error_code.as_deref(), Some("STATUS_LOGON_FAILURE"));
}

#[test]
fn missing_interface_is_a_resolution_error() {
    let cli = Cli::try_parse_from(["responder"]).unwrap();
    assert!(responder::config::resolve(&cli, &responder::config::Settings::default()).is_err());
}
