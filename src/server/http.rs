//! `envy serve`: the HTTP layer over [`ServerCore`]. It only moves JSON between the network
//! and the core, adds TLS when given a certificate, and decides which client address the
//! rate limiting sees. Every rule lives in the core.

use std::{
    fs,
    io::Write,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use axum::{
    Router,
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use axum_server::{Handle, tls_rustls::RustlsConfig};

use super::{ServerCore, sqlite::SqliteStore};
use crate::{
    cli::ServeArgs,
    clock::SystemClock,
    remote::protocol::{HEALTH_PATH, MAX_BODY, RPC_PATH},
};

struct App {
    core: ServerCore,
    behind_proxy: bool,
}

pub fn serve(args: &ServeArgs, out: &mut dyn Write) -> Result<()> {
    let core = open(&args.data, args.session_ttl)?;
    if args.init {
        let token = core.init()?;
        return hand_over_root_token(&token, args.init_output.as_deref(), out);
    }
    if args.new_root_token {
        let token = core.new_root_token()?;
        return hand_over_root_token(&token, None, out);
    }
    if core.store().meta("server_id")?.is_none() {
        bail!(
            "{} holds no Envy server yet; run `envy serve --init` first.",
            args.data.display()
        );
    }

    let address: SocketAddr = args
        .listen
        .parse()
        .with_context(|| format!("'{}' is not an address like 127.0.0.1:8443", args.listen))?;
    let tls = args.tls_cert.as_deref().zip(args.tls_key.as_deref());
    if tls.is_none() && !args.behind_proxy && !address.ip().is_loopback() {
        bail!(
            "Without TLS the server only listens on a loopback address. Give --tls-cert and --tls-key, or --behind-proxy when a TLS proxy is in front of it."
        );
    }
    let app = Arc::new(App {
        core,
        behind_proxy: args.behind_proxy,
    });
    writeln!(
        out,
        "Envy server on {}://{address}",
        if tls.is_some() { "https" } else { "http" }
    )?;
    out.flush()?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(app, address, tls))
}

fn open(data: &Path, session_ttl: u32) -> Result<ServerCore> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(data)
        .with_context(|| format!("Could not create {}", data.display()))?;
    let store = SqliteStore::open(&data.join("envy.db"))?;
    Ok(ServerCore::new(
        Box::new(store),
        Box::new(SystemClock),
        chrono::Duration::hours(i64::from(session_ttl)),
    ))
}

/// The root token is shown once: printed, or written to a new file only its owner can read
/// (for containers, whose output may be collected by a log system).
fn hand_over_root_token(token: &str, file: Option<&Path>, out: &mut dyn Write) -> Result<()> {
    let Some(file) = file else {
        writeln!(out, "Root token (shown only once): {token}")?;
        writeln!(
            out,
            "The first admin runs: envy login <url> --root-token <token> --name <name>"
        )?;
        return Ok(());
    };
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut handle = options
        .open(file)
        .with_context(|| format!("Could not create {} (it must not exist)", file.display()))?;
    writeln!(handle, "{token}")?;
    writeln!(out, "Root token written to {}.", file.display())?;
    Ok(())
}

async fn run(app: Arc<App>, address: SocketAddr, tls: Option<(&Path, &Path)>) -> Result<()> {
    let router = Router::new()
        .route(RPC_PATH, post(rpc))
        .route(HEALTH_PATH, get(health))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(app)
        .into_make_service_with_connect_info::<SocketAddr>();
    let handle = Handle::new();
    tokio::spawn(shutdown_on_signal(handle.clone()));
    match tls {
        Some((cert, key)) => {
            let config = RustlsConfig::from_pem_file(cert, key)
                .await
                .context("Could not load the TLS certificate and key")?;
            axum_server::bind_rustls(address, config)
                .handle(handle)
                .serve(router)
                .await?;
        }
        None => {
            axum_server::bind(address)
                .handle(handle)
                .serve(router)
                .await?;
        }
    }
    Ok(())
}

async fn shutdown_on_signal(handle: Handle<SocketAddr>) {
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        () = terminate => {}
    }
    handle.graceful_shutdown(Some(Duration::from_secs(10)));
}

async fn health() -> &'static str {
    "ok"
}

/// Behind a proxy the peer is the proxy, so the client is the last `X-Forwarded-For`
/// address: the one the proxy added. The earlier ones come from the client, which could
/// send a new one with every attempt and never be rate limited (nginx and Traefik append to
/// the header they receive). Without `--behind-proxy` the header is ignored: anyone could
/// forge it.
fn forwarded_client(behind_proxy: bool, peer: SocketAddr, headers: &HeaderMap) -> String {
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .and_then(|value| value.trim().parse::<IpAddr>().ok());
    match forwarded {
        Some(ip) if behind_proxy => ip.to_string(),
        _ => peer.ip().to_string(),
    }
}

async fn rpc(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let client = forwarded_client(app.behind_proxy, peer, &headers);
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_string);
    let result =
        tokio::task::spawn_blocking(move || app.core.handle_json(&client, token.as_deref(), &body))
            .await;
    let (status, reply) = result.unwrap_or_else(|_| (500, br#"{"status":500,"code":"internal","message":"The server could not complete the request."}"#.to_vec()));
    (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        [(header::CONTENT_TYPE, "application/json")],
        reply,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behind_a_proxy_the_client_is_the_address_the_proxy_added() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "6.6.6.6, 7.7.7.7, 203.0.113.9".parse().unwrap(),
        );
        let peer: SocketAddr = "10.0.0.2:4000".parse().unwrap();
        assert_eq!(forwarded_client(true, peer, &headers), "203.0.113.9");
        assert_eq!(
            forwarded_client(false, peer, &headers),
            "10.0.0.2",
            "without --behind-proxy the header is ignored"
        );
        assert_eq!(forwarded_client(true, peer, &HeaderMap::new()), "10.0.0.2");
    }
}
