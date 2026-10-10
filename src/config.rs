//! `Responder.conf` loading and CLI/config merging.
//!
//! Uses `configparser` for Python-`configparser`-compatible semantics (case-insensitive keys,
//! `;`/`#` comments, `key = value`). Unknown keys are ignored, never fatal.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use configparser::ini::Ini;

use crate::capture::model::{RunConfiguration, ServiceConfiguration, Ttl};
use crate::cli::Cli;
use crate::constants::Service;

/// Parsed configuration-file contents with reference-compatible defaults.
#[derive(Clone, Debug)]
pub struct Settings {
    services: HashMap<Service, bool>,
    pub session_log: bool,
    pub log_to_file: bool,
    pub verbose: bool,
    pub database: String,
    pub ssl_cert: String,
    pub ssl_key: String,
    pub html_filename: String,
    pub dhcpv6_domain: String,
    pub dns_domain: String,
    pub ttl: String,
    pub bind_ipv6: Option<std::net::Ipv6Addr>,
    pub interface: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        let mut services = HashMap::new();
        for s in Service::all() {
            // DHCPv4 is off by default (per the config contract); everything else is on.
            services.insert(*s, *s != Service::Dhcp);
        }
        Settings {
            services,
            session_log: true,
            log_to_file: true,
            verbose: true,
            database: "Responder.db".to_string(),
            ssl_cert: "certs/responder.crt".to_string(),
            ssl_key: "certs/responder.key".to_string(),
            html_filename: "files/AccessDenied.html".to_string(),
            dhcpv6_domain: String::new(),
            dns_domain: String::new(),
            ttl: "1e".to_string(),
            bind_ipv6: None,
            interface: None,
        }
    }
}

impl Settings {
    pub fn service_enabled(&self, s: Service) -> bool {
        self.services.get(&s).copied().unwrap_or(true)
    }

    /// Load settings from a config file. A missing file yields documented defaults.
    pub fn load(path: &str) -> Result<(Settings, bool)> {
        let mut settings = Settings::default();
        if !std::path::Path::new(path).exists() {
            return Ok((settings, false));
        }
        let mut ini = Ini::new();
        ini.load(path)
            .map_err(|e| anyhow::anyhow!("parsing config {path}: {e}"))?;

        let core = "Responder Core";
        let bool_or = |ini: &Ini, key: &str, default: bool| -> bool {
            ini.get(core, key)
                .as_deref()
                .and_then(parse_bool)
                .unwrap_or(default)
        };

        macro_rules! set_service {
            ($key:literal, $svc:expr) => {
                if let Some(v) = ini.get(core, $key).as_deref().and_then(parse_bool) {
                    settings.services.insert($svc, v);
                }
            };
        }
        set_service!("SQL", Service::Mssql);
        set_service!("SMB", Service::Smb);
        set_service!("RDP", Service::Rdp);
        set_service!("Kerberos", Service::Kerberos);
        set_service!("FTP", Service::Ftp);
        set_service!("POP", Service::Pop3);
        set_service!("SMTP", Service::Smtp);
        set_service!("IMAP", Service::Imap);
        set_service!("IMAPS", Service::Imaps);
        set_service!("HTTP", Service::Http);
        set_service!("HTTPS", Service::Https);
        set_service!("DNS", Service::Dns);
        set_service!("DCERPC", Service::Dcerpc);
        set_service!("WINRM", Service::Winrm);
        // LDAP covers 389/636; WinRM covers 5985/5986.
        if let Some(v) = ini.get(core, "LDAP").as_deref().and_then(parse_bool) {
            settings.services.insert(Service::Ldap, v);
            settings.services.insert(Service::Ldaps, v);
        }
        if let Some(v) = ini.get(core, "WINRM").as_deref().and_then(parse_bool) {
            settings.services.insert(Service::Winrms, v);
        }
        set_service!("LLMNR", Service::Llmnr);
        set_service!("NBTNS", Service::NbtNs);
        set_service!("MDNS", Service::Mdns);
        set_service!("DHCP", Service::Dhcp);
        set_service!("DHCPv6", Service::Dhcpv6);

        settings.session_log = bool_or(&ini, "SessionLog", settings.session_log);
        settings.log_to_file = bool_or(&ini, "LogToFile", settings.log_to_file);
        settings.verbose = bool_or(&ini, "Verbose", settings.verbose);
        if let Some(v) = ini.get(core, "Database") {
            settings.database = v;
        }
        if let Some(v) = ini.get(core, "SSLCert") {
            settings.ssl_cert = v;
        }
        if let Some(v) = ini.get(core, "SSLKey") {
            settings.ssl_key = v;
        }
        if let Some(v) = ini.get("HTTP Server", "HtmlFilename") {
            settings.html_filename = v;
        }
        if let Some(v) = ini.get("DHCPv6 Server", "DHCPv6_Domain") {
            settings.dhcpv6_domain = v;
        }
        if let Some(v) = ini.get("DHCPv6 Server", "BindToIPv6") {
            settings.bind_ipv6 = v.trim().parse().ok();
        }
        if let Some(v) = ini.get("DNS Server", "DNS_Domain") {
            settings.dns_domain = v;
        }
        if let Some(v) = ini.get("DNS Server", "TTL") {
            settings.ttl = v;
        }
        Ok((settings, true))
    }
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "on" | "yes" | "true" | "t" | "1" | "enabled" => Some(true),
        "off" | "no" | "false" | "f" | "0" | "disabled" => Some(false),
        _ => None,
    }
}

fn parse_ttl(s: &str) -> Ttl {
    let t = s.trim();
    if t.eq_ignore_ascii_case("random") {
        Ttl::Random
    } else {
        let v = u32::from_str_radix(t, 16)
            .or_else(|_| t.parse::<u32>())
            .unwrap_or(crate::constants::DEFAULT_TTL);
        Ttl::Fixed(v)
    }
}

/// Merge CLI arguments with config-file settings into the fully-resolved run configuration.
pub fn resolve(cli: &Cli, settings: &Settings) -> Result<RunConfiguration> {
    let interface = cli
        .interface
        .clone()
        .or_else(|| settings.interface.clone())
        .context("no interface selected: pass -I <iface> or set Interface in Responder.conf")?;

    let mut services = Vec::new();
    for s in Service::all() {
        let mut enabled = settings.service_enabled(*s);
        match s {
            Service::Dhcp => enabled = cli.dhcp || enabled,
            Service::Dhcpv6 => enabled = cli.dhcpv6 || enabled,
            Service::Wpad => enabled = cli.wpad || settings.service_enabled(Service::Http),
            _ => {}
        }
        services.push(ServiceConfiguration::new(*s, enabled));
    }

    let ttl = parse_ttl(cli.ttl.as_deref().unwrap_or(settings.ttl.as_str()));

    let domain = if settings.dns_domain.trim().is_empty() {
        settings.dhcpv6_domain.trim().to_string()
    } else {
        settings.dns_domain.trim().to_string()
    };
    let dns_domains = if domain.is_empty() {
        Vec::new()
    } else {
        vec![domain]
    };

    // `-D` (DHCP-DNS) disables WPAD injection so DHCP hands out our DNS server instead.
    let wpad = cli.wpad && !cli.dhcp_dns;

    Ok(RunConfiguration {
        interface,
        analyze: cli.analyze,
        wpad,
        force_wpad_auth: cli.force_wpad_auth,
        force_basic_only: cli.basic,
        proxy_auth: cli.proxy_auth,
        upstream_proxy: cli.upstream_proxy.clone(),
        external_ip: cli.external_ip,
        external_ipv6: cli.external_ip6.or(settings.bind_ipv6),
        local_ip: cli.local_ip.map(std::net::IpAddr::V4),
        answer_name: cli.answer_name.clone(),
        ttl,
        error_code: cli.error_code.clone(),
        lm_downgrade: cli.lm,
        disable_ess: cli.disable_ess,
        verbose: cli.verbose > 0 || settings.verbose,
        quiet: cli.quiet,
        db_file: settings.database.clone(),
        log_dir: "logs".to_string(),
        html_filename: settings.html_filename.clone(),
        ssl_cert: settings.ssl_cert.clone(),
        ssl_key: settings.ssl_key.clone(),
        dns_domains,
        services,
    })
}

/// Convenience for tests and `-i`/`-e` overrides.
pub fn effective_answer_ip(cfg: &RunConfiguration, iface_ip: Ipv4Addr) -> Ipv4Addr {
    cfg.external_ip.unwrap_or(iface_ip)
}
