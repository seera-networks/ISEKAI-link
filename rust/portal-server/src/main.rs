//! The side with the services.
//!
//! Declares what exists, waits for a client the proxy says is authorised, and
//! forwards each requested service to its target. Phase 1c-iii-c-ii of
//! `docs/portal_plan.md`.
//!
//! ```text
//! portal-server --identity-url … --proxy-url … --key ep.pem \
//!               --service db=10.0.0.5:5432 --allow ep:abc…
//! ```
//!
//! # The target never crosses the wire
//!
//! Services are named here and asked for **by name** (plan §4.3). A client that
//! could name a host and port would turn this into an open proxy into whatever
//! network it sits on — every device on that LAN, every link-local metadata
//! endpoint, every `127.0.0.1` service the operator never meant to expose. A
//! Grant says *these two Endpoints may talk*; it says nothing about what may be
//! reached, and it was never meant to.
//!
//! `--service` is where phase 2 puts a file instead.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context as _;
use argh::FromArgs;
use isekai_p2p::{load_or_generate_key, AcceptPolicy, P2pConfig};
use portal_core::server::Catalogue;
use tokio_util::sync::CancellationToken;

/// Forward local TCP services to authorised peers over ISEKAI link.
#[derive(FromArgs)]
struct Args {
    /// identity API base URL (HTTPS), e.g. https://identity.isekai.link:8443
    #[argh(option)]
    identity_url: String,
    /// reach the Identity API over HTTP/3 instead of HTTP/1.1 + HTTP/2
    #[argh(switch)]
    identity_http3: bool,
    /// proxy base URL, e.g. https://proxy.isekai.link:8443
    #[argh(option)]
    proxy_url: String,
    /// auth0 access token, used only to obtain the Endpoint Token
    #[argh(option)]
    auth0_token: String,
    /// P2P protocol string
    #[argh(option, default = "String::from(\"isekai-portal-v1\")")]
    protocol: String,
    /// register the Endpoint before issuing a token (needed on first use of a
    /// freshly generated key)
    #[argh(switch)]
    register: bool,
    /// device display name recorded at registration
    #[argh(option)]
    device_name: Option<String>,
    /// path to this Endpoint's signing key; generated if absent
    #[argh(option)]
    key: PathBuf,
    /// path to the certificate key this device keeps. Defaults to the Endpoint
    /// key's name with `-portal-cert` appended -- a separate key on purpose,
    /// since the Endpoint key is a signing identity and should never be handed
    /// to a QUIC stack
    #[argh(option)]
    cert_key: Option<PathBuf>,
    /// a service to offer, as `name=host:port`. Repeatable
    #[argh(option)]
    service: Vec<String>,
    /// an Endpoint ID to issue a capability for at startup, printed on stdout.
    /// Repeatable
    #[argh(option)]
    allow: Vec<String>,
    /// how long an issued capability lasts, in seconds
    #[argh(option)]
    capability_ttl: Option<u64>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args: Args = argh::from_env();

    let catalogue = catalogue(&args.service)?;
    if catalogue.is_empty() {
        anyhow::bail!("no services offered; pass at least one --service name=host:port");
    }

    let cert_key = args.cert_key.clone().unwrap_or_else(|| {
        let mut path = args.key.clone();
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "endpoint".to_owned());
        path.set_file_name(format!("{stem}-portal-cert.pem"));
        path
    });

    let cfg = P2pConfig {
        identity_url: args.identity_url,
        identity_http3: args.identity_http3,
        proxy_url: args.proxy_url,
        auth0_token: args.auth0_token,
        auth0: None,
        protocol: args.protocol,
        register: args.register,
        device_name: args.device_name,
        token_ttl: None,
        key: load_or_generate_key(&args.key)?,
    };

    let shutdown = CancellationToken::new();
    // `AutoNotify` rather than `Manual`: there is no operator watching a window
    // here, and the Grant the proxy checked is the authorization. It still says
    // who arrived, which is the difference from plain `Auto`.
    let server = portal_core::session::serve(
        cfg,
        &cert_key,
        catalogue,
        AcceptPolicy::AutoNotify,
        shutdown.clone(),
    )
    .await
    .context("stand the portal server up")?;

    println!("listener id : {}", server.info.listener_id);
    println!("endpoint id : {}", server.info.endpoint_id);
    for endpoint in &args.allow {
        let capability = server
            .issue_capability(endpoint, args.capability_ttl)
            .await
            .with_context(|| format!("issue a capability for {endpoint}"))?;
        println!("capability  : {capability}   (for {endpoint})");
    }
    println!("\nGive the client the listener id and its capability.");

    let mut events = server.signaling.subscribe();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            event = events.recv() => match event {
                Ok(event) => tracing::info!("signaling: {event:?}"),
                // Lagged only loses log lines; the session is unaffected.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("missed {n} signaling events");
                }
                Err(_) => break,
            },
        }
    }
    shutdown.cancel();
    Ok(())
}

/// Parse `name=host:port` into the catalogue.
fn catalogue(services: &[String]) -> anyhow::Result<Catalogue> {
    let mut catalogue = Catalogue::new();
    for service in services {
        let (name, target) = service
            .split_once('=')
            .with_context(|| format!("--service wants `name=host:port`, got `{service}`"))?;
        let target: SocketAddr = target
            .parse()
            .with_context(|| format!("`{target}` is not a host:port"))?;
        catalogue = catalogue.with(name, target);
    }
    Ok(catalogue)
}
