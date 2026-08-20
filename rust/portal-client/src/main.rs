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
    #[argh(option, default = "String::from(\"127.0.0.1\")")]
    bind: String,
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

    let maps = maps(&args.map, &args.bind)?;
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
        identity_url: args.identity_url,
        identity_http3: args.identity_http3,
        proxy_url: args.proxy_url,
        auth0_token: args.auth0_token,
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

    // The session holds the relay leg; the peer connection rides it. Ending is
    // what `close` is for -- see `portal_core::session::Connected`.
    //
    // Bound rather than awaited inline: `ended()` hands back an owned token, and
    // a temporary inside the `select!` is dropped before it is polled.
    let ended = connected.session.ended();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = ended.cancelled() => {
            tracing::warn!("the session ended; the forwards are going with it");
        }
    }
    shutdown.cancel();
    connected.close().await;
    Ok(())
}

/// Parse `port:name` into the local address to bind and the service to ask for.
fn maps(maps: &[String], bind: &str) -> anyhow::Result<Vec<(SocketAddr, String)>> {
    maps.iter()
        .map(|m| {
            let (port, service) = m
                .split_once(':')
                .with_context(|| format!("--map wants `port:service`, got `{m}`"))?;
            let port: u16 = port
                .parse()
                .with_context(|| format!("`{port}` is not a port"))?;
            let local: SocketAddr = format!("{bind}:{port}")
                .parse()
                .with_context(|| format!("`{bind}:{port}` is not an address"))?;
            Ok((local, service.to_owned()))
        })
        .collect()
}
