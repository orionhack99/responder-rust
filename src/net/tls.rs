//! TLS material management for the rogue HTTPS/IMAPS/LDAPS/WinRM-S servers.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// Generate a self-signed certificate/key and write them as PEM files.
pub fn generate_self_signed(cert_path: impl AsRef<Path>, key_path: impl AsRef<Path>) -> Result<()> {
    let names = vec![
        "localhost".to_string(),
        "wpad".to_string(),
        "wpad.local".to_string(),
    ];
    let key = rcgen::generate_simple_self_signed(names)?;
    std::fs::write(cert_path.as_ref(), key.cert.pem())
        .with_context(|| format!("writing {}", cert_path.as_ref().display()))?;
    std::fs::write(key_path.as_ref(), key.signing_key.serialize_pem())
        .with_context(|| format!("writing {}", key_path.as_ref().display()))?;
    Ok(())
}

/// Build a rustls server config from PEM files, generating a self-signed pair if missing.
pub fn server_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>> {
    if !Path::new(cert_path).exists() || !Path::new(key_path).exists() {
        generate_self_signed(cert_path, key_path)?;
    }
    let cert_chain = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .context("building rustls server config")?;
    Ok(Arc::new(config))
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let pem = std::fs::read(path).with_context(|| format!("reading cert {path}"))?;
    let mut reader = std::io::BufReader::new(&pem[..]);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("parsing certificates")?;
    Ok(certs)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let pem = std::fs::read(path).with_context(|| format!("reading key {path}"))?;
    let mut reader = std::io::BufReader::new(&pem[..]);
    let key = rustls_pemfile::private_key(&mut reader).context("parsing private key")?;
    key.ok_or_else(|| anyhow::anyhow!("no private key found in {path}"))
        .map(|k| match k {
            // Normalize to a Pkcs8 key so the type is owned/'static.
            PrivateKeyDer::Pkcs8(k) => PrivateKeyDer::Pkcs8(k),
            other => other,
        })
}

/// Install the process-default crypto provider (idempotent).
pub fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// In-memory self-signed config (used by tests to avoid touching disk).
pub fn ephemeral_config() -> Result<Arc<ServerConfig>> {
    install_crypto_provider();
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert = CertificateDer::from(key.cert.der().to_vec());
    let priv_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()));
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], priv_key)?;
    Ok(Arc::new(config))
}
