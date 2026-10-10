//! Binary entry point: wires the CLI, configuration, capture pipeline and servers together.

use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use responder::capture::spawn_writer;
use responder::cli::Cli;
use responder::config::{Settings, resolve};
use responder::logger::Logger;
use responder::net::{iface, tls};
use responder::report;
use responder::servers::{self, ServerContext};
use responder::store::Store;

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Console logging via tracing (used by internal `tracing::debug!` calls).
    let level = if cli.quiet {
        "error"
    } else if cli.verbose > 0 {
        "debug"
    } else {
        "info"
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(level)
        .with_target(false)
        .try_init();

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("[!] failed to start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[!] {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let (settings, existed) = Settings::load(&cli.config)?;
    if !existed {
        eprintln!(
            "[!] config {} not found; using documented defaults",
            cli.config
        );
    }
    let cfg = resolve(&cli, &settings)?;

    // Interface / address resolution.
    let interfaces = iface::resolve(&cfg.interface)?;
    let primary = interfaces.first().expect("at least one interface");
    let iface_name = primary.name.clone();
    let iface_ipv4 = primary
        .ipv4()
        .ok_or_else(|| anyhow::anyhow!("interface {iface_name} has no IPv4 address"))?;
    let answer_ip = cfg.external_ip.unwrap_or(iface_ipv4);

    // Capture pipeline.
    let logger = Arc::new(Logger::new(
        &cfg.log_dir,
        settings.session_log,
        cfg.verbose,
        cfg.quiet,
    )?);
    let store = Arc::new(Store::open(&cfg.db_file)?);
    let run_id = store.start_run(&cfg.interface, cfg.analyze)?;
    let (sink, _writer) = spawn_writer(logger.clone(), store.clone(), run_id.clone(), 4096);

    tls::install_crypto_provider();

    if cfg.analyze {
        logger.info("Analyze mode: observing name resolution without responding");
    }

    let ctx = Arc::new(ServerContext::new(
        cfg.clone(),
        sink,
        logger.clone(),
        answer_ip,
    ));
    let outcomes = servers::spawn_all(ctx).await;
    let (ok, failed) = report::summarize(&outcomes);
    print!(
        "{}",
        report::format_summary(&iface_name, cfg.analyze, &outcomes)
    );
    logger.info(&format!("{ok} service(s) listening, {failed} failed"));

    // Wait for Ctrl-C, then shut down cleanly.
    if let Err(e) = tokio::signal::ctrl_c().await {
        logger.warn(&format!("failed to listen for ctrl-c: {e}"));
    }
    logger.info("shutting down; flushing captures");
    // Give the writer task a moment to drain queued events before the runtime stops.
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    let _ = store.finish_run(&run_id);
    Ok(())
}
