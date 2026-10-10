//! Rogue WinRM server (HTTP 5985 / HTTPS 5986). Delegates to the HTTP auth handler.

use std::sync::Arc;

use anyhow::Result;
use tokio::net::TcpListener;

use super::ServerContext;
use super::http;

pub async fn serve(listener: TcpListener, ctx: Arc<ServerContext>, tls_mode: bool) -> Result<()> {
    http::serve_winrm(listener, ctx, tls_mode).await
}
