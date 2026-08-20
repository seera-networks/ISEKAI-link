//! The side with the local ports.
//!
//! Connects to a portal server and maps local TCP ports onto the services it
//! offers. Phase 1c-iii-c-ii of `docs/portal_plan.md`.
//!
//! ```text
//! portal-client --identity-url … --proxy-url … --key ep.pem \
//!               --listener pl_… --capability … --map 5432:db
//! ```
//!
//! **The local ports are this side's own business** (plan §4.3): nothing about
//! `--map` reaches the server, which only ever sees the service name.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context as _;
use argh::FromArgs;
use isekai_p2p::{load_or_generate_key, P2pConfig};
use tokio_util::sync::CancellationToken;

/// Map local TCP ports onto a portal server's services over ISEKAI link.
#[derive(FromArgs)]
struct Args {
    /// identity API base URL (HTTPS), e.g. https://identity.isekai.link:8443.
    /// Not needed with --whoami
    #[argh(option)]
    identity_url: Option<String>,
    /// reach the Identity API over HTTP/3 instead of HTTP/1.1 + HTTP/2
    #[argh(switch)]
    identity_http3: bool,
    /// proxy base URL, e.g. https://proxy.isekai.link:8443. Not needed with
    /// --whoami
    #[argh(option)]
    proxy_url: Option<String>,
    /// auth0 access token, used only to obtain the Endpoint Token. Not needed
    /// with --whoami
    #[argh(option)]
    auth0_token: Option<String>,
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
    /// print this Endpoint's ID and exit -- what the server needs for --allow
    #[argh(switch)]
    whoami: bool,
    /// the server's listener id
    #[argh(option)]
    listener: Option<String>,
    /// the capability the server issued for this Endpoint
    #[argh(option)]
    capability: Option<String>,
    /// a local port to map onto a service, as `port:name`. Repeatable
    #[argh(option)]
    map: Vec<String>,
    /// the address to bind mapped ports on. Loopback by default, because a
    /// forward reachable from the network is a second open door onto the
    /// server's services
    #[argh(option, default = "std::net::IpAddr::from([127, 0, 0, 1])")]
    bind: std::net::IpAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args: Args = argh::from_env();

    let key = load_or_generate_key(&args.key)?;
    if args.whoami {
        // Before any network call: this is what the operator needs in order to
        // ask the other side for a capability, and it costs nothing to answer.
        println!("{}", key.endpoint_id());
        return Ok(());
    }

    let maps = maps(&args.map, args.bind)?;
    if maps.is_empty() {
        anyhow::bail!("nothing to forward; pass at least one --map port:service");
    }
    let listener = args
        .listener
        .clone()
        .context("--listener is required (the server prints it)")?;
    let capability = args
        .capability
        .clone()
        .context("--capability is required (the server issues it for this Endpoint)")?;

    let cfg = P2pConfig {
        identity_url: args.identity_url.context("--identity-url is required")?,
        identity_http3: args.identity_http3,
        proxy_url: args.proxy_url.context("--proxy-url is required")?,
        auth0_token: args.auth0_token.context("--auth0-token is required")?,
        auth0: None,
        protocol: args.protocol,
        register: args.register,
        device_name: args.device_name,
        token_ttl: None,
        key,
    };

    let shutdown = CancellationToken::new();
    let connected = portal_core::session::connect(&cfg, &capability, &listener, &shutdown)
        .await
        .context("connect to the portal server")?;
    println!("connection id: {}", connected.session.connection_id());

    for (local, service) in maps {
        let forwarding = portal_core::client::forward(
            connected.peer.connection().clone(),
            local,
            service.clone(),
            shutdown.clone(),
        )
        .await
        .with_context(|| format!("forward {local} to `{service}`"))?;
        println!("{forwarding} -> {service}");
    }

    // **Both ways this can end without us**, and watching only one of them is
    // the worse failure: the forwarded ports stay bound over a connection that
    // is gone, so anything connecting to them is accepted and then goes quiet
    // rather than being refused.
    //
    // `ended` is the proxy withdrawing the session -- a revoked Grant, a lease
    // that could not be renewed. The connection ending is the server exiting.
    //
    // `ended()` is bound rather than awaited inline because it hands back an
    // owned token, and a temporary inside the `select!` is dropped before it is
    // polled.
    let ended = connected.session.ended();
    let peer = connected.peer.connection().clone();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = ended.cancelled() => {
            tracing::warn!("the session ended; the forwards are going with it");
        }
        _ = closed(&peer) => {
            tracing::warn!("the peer connection closed; the forwards are going with it");
        }
    }
    connected.close().await;
    Ok(())
}

/// Resolves when the peer connection is no longer usable.
///
/// Its event stream ending is the signal: msquic reports the shutdown as an
/// event and then the stream errors, so this needs no timer of its own.
async fn closed(conn: &msquic_async::Connection) {
    while std::future::poll_fn(|cx| conn.poll_event(cx)).await.is_ok() {}
}

/// Parse `port:name` into the local address to bind and the service to ask for.
///
/// The address is assembled rather than formatted and re-parsed, which is what
/// lets `--bind ::1` work: an IPv6 address needs brackets in a `host:port`
/// string and does not have them here.
fn maps(maps: &[String], bind: std::net::IpAddr) -> anyhow::Result<Vec<(SocketAddr, String)>> {
    maps.iter()
        .map(|m| {
            let (port, service) = m
                .split_once(':')
                .with_context(|| format!("--map wants `port:service`, got `{m}`"))?;
            let port: u16 = port
                .parse()
                .with_context(|| format!("`{port}` is not a port"))?;
            Ok((SocketAddr::new(bind, port), service.to_owned()))
        })
        .collect()
}
