//! The side with the local ports.
//!
//! Connects to a portal server and maps local ports onto the services it
//! offers. Phase 1c-iii-c-ii of `docs/portal_plan.md`, and UDP since 3b.
//!
//! ```text
//! portal-client --auth0-token … --key ep.pem \
//!               --listener pl_… --capability … \
//!               --map 5432:db --map udp:5353:dns
//! ```
//!
//! **The local ports are this side's own business** (plan §4.3): nothing about
//! `--map` reaches the server, which only ever sees the service name.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context as _;
use argh::FromArgs;
use isekai_p2p::{load_or_generate_key, P2pConfig};
use portal_core::server::Protocol;
use tokio_util::sync::CancellationToken;

/// Map local TCP and UDP ports onto a portal server's services over ISEKAI
/// link.
///
/// A service is asked for **by name**. Which local port stands for which name
/// is this machine's business and nothing about it is sent, so the mapping can
/// be whatever suits you.
#[derive(FromArgs)]
#[argh(
    example = "\
portal-client --login

portal-client --pair ABCD-1234

portal-client --map 5432:db --map udp:5353:dns",
    note = "\
Sign in once with --login. It runs the Auth0 device flow -- a code and a URL to
open -- and saves tokens beside the Endpoint key that refresh from then on, so
nothing else here needs a token.

--auth0-token still works and cannot be refreshed: when it expires the session
ends a few minutes later, mid-forward.
",
    note = "\
--map takes `port:service`, or `udp:port:service` for a UDP one. TCP without
the prefix. Repeatable, and the port is yours to choose:

  --map 5432:db           reach `db` at 127.0.0.1:5432
  --map 15432:db          the same service on a port that is free
  --map udp:5353:dns      reach `dns` at 127.0.0.1:5353

The protocol has to be said and cannot be guessed: the server looks a name up
under a protocol, so asking for `dns` over TCP is refused with the same answer
as a name that does not exist.

Forwarded ports bind to loopback unless --bind says otherwise, because a
forward reachable from your network is a second door onto the server's
services.
",
    note = "\
The server's operator has to let you in first, and there are two ways in.

PAIRING, which is the one to use: they run `portal-server --pair` and read you
the code; you run `--pair <code>` once. That makes a standing grant, and after
it every connect needs only --map -- the current listener is looked up for you,
so the server can restart without breaking anything.

A CAPABILITY, for being let in once: run --whoami, send them the Endpoint ID,
and they issue one with --allow. Pass it with --capability and --listener. It
is one-shot and expires in 300 seconds at most, so have the command ready
before they issue it.

--whoami needs nothing but --key and makes no network call."
)]
struct Args {
    /// identity API base URL (HTTPS). Defaults to the deployment the camera
    /// apps use
    #[argh(
        option,
        default = "String::from(\"https://identity.isekai.tools:9443\")"
    )]
    identity_url: String,
    /// reach the Identity API over HTTP/3 instead of HTTP/1.1 + HTTP/2
    #[argh(switch)]
    identity_http3: bool,
    /// proxy base URL. Defaults to the deployment the camera apps use
    #[argh(
        option,
        default = "String::from(\"https://tokyo.link.isekai.tools:8443\")"
    )]
    proxy_url: String,
    /// auth0 access token, used only to obtain the Endpoint Token. Cannot be
    /// refreshed -- `--login` is the way to stay signed in. Not needed with
    /// --whoami
    #[argh(option)]
    auth0_token: Option<String>,
    /// sign in to Auth0 once, saving tokens that refresh from then on, and
    /// exit. This is what lets a server be left running: an --auth0-token
    /// expires and takes the session with it
    #[argh(switch)]
    login: bool,
    /// where the saved sign-in lives. Defaults to the Endpoint key's name with
    /// `-auth0.json` in place of its extension
    #[argh(option)]
    auth0_tokens: Option<PathBuf>,
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
    /// path to this Endpoint's signing key. Generated on first use; keep it,
    /// because a new one is a new Endpoint ID and the capability you were
    /// issued stops meaning anything
    #[argh(option, default = "PathBuf::from(\"portal-client.pem\")")]
    key: PathBuf,
    /// print this Endpoint's ID and exit -- what the server needs for --allow
    #[argh(switch)]
    whoami: bool,
    /// redeem a pairing code the server's operator showed, and exit. What it
    /// makes is a standing grant: after this, connecting needs neither
    /// --listener nor --capability, and survives the server restarting
    #[argh(option)]
    pair: Option<String>,
    /// a name for this device, recorded with the grant so the operator can see
    /// what they let in
    #[argh(option)]
    label: Option<String>,
    /// which paired server to connect to, by its Endpoint ID. Only needed when
    /// paired with more than one
    #[argh(option)]
    peer: Option<String>,
    /// the server's listener id. Only for the one-shot --capability path; a
    /// grant finds the current listener itself
    #[argh(option)]
    listener: Option<String>,
    /// a one-shot capability the server issued for this Endpoint. --pair is
    /// what standing access wants
    #[argh(option)]
    capability: Option<String>,
    /// a local port to map onto a service, as `port:name` or
    /// `udp:port:name`. TCP without the prefix. Repeatable
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
    // **stderr, and `info` unless `RUST_LOG` says otherwise.**
    //
    // Two fixes in one. `fmt()` writes to *stdout* by default, which puts log
    // lines in among the ids this program prints for the operator to copy —
    // every other binary in this workspace sets stderr and this one did not.
    //
    // And `from_default_env()` defaults to `ERROR`, so `warn!` and below were
    // dropped: a service refused, a target that would not answer, a datagram
    // too large to send. `from_env_lossy` rather than `try_from_default_env`
    // keeps the old leniency — one bad directive in `RUST_LOG` skips that
    // directive rather than throwing the whole variable away, which matters
    // because reaching for `RUST_LOG` is what somebody does when confused
    // already.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();
    let args: Args = argh::from_env();
    // **Every path out of `run` goes through the same wind-down**, which is the
    // only shape that works here: `PeerDirectory`, the sessions and the
    // one-shot commands all open control-plane transports on the shared msquic
    // registration, and a process that returns while those handles are live
    // drops the registration into `RegistrationClose` and aborts. Hardware
    // found it twice — once after a successful pairing, once on a connect that
    // was correctly refused — and both times the exit code contradicted what
    // had been printed a line earlier.
    let outcome = run(args).await;
    if !isekai_p2p::agent::shutdown_msquic(SHUTDOWN_TIMEOUT).await {
        tracing::debug!("msquic still had live handles on the way out");
    }
    outcome
}

/// How long to wait for msquic before leaving it to the operating system.
const SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

async fn run(args: Args) -> anyhow::Result<()> {
    // **Said out loud, because a generated key looks exactly like a loaded one
    // until it fails.** `--key` has a default, so running from a different
    // directory than last time silently makes a *second* Endpoint — and the
    // failure is `capability-endpoint-mismatch` from the proxy, several steps
    // later, naming nothing that points back here.
    if !args.key.exists() {
        tracing::info!(path = %args.key.display(), "generating a new Endpoint key");
    }
    let key = load_or_generate_key(&args.key)?;
    if args.whoami {
        // Before any network call: this is what the operator needs in order to
        // ask the other side for a capability, and it costs nothing to answer.
        println!("{}", key.endpoint_id());
        return Ok(());
    }

    let tokens = args
        .auth0_tokens
        .clone()
        .unwrap_or_else(|| portal_core::login::tokens_beside(&args.key));
    if args.login {
        return portal_core::login::sign_in(&tokens).await;
    }

    if let Some(code) = &args.pair {
        return redeem(&args, &tokens, key, code).await;
    }

    let maps = maps(&args.map, args.bind)?;
    if maps.is_empty() {
        anyhow::bail!("nothing to forward; pass at least one --map port:service");
    }
    // **A grant unless a capability was handed over.** The two are not
    // alternatives of equal standing: a grant is what an installation should be
    // running on, and the capability path is for the guest who was let in once.
    let reach = match (&args.capability, &args.listener) {
        (Some(capability), Some(listener_id)) => portal_core::session::Reach::Capability {
            capability,
            listener_id,
        },
        (Some(_), None) => {
            anyhow::bail!("--capability needs --listener, which names the one it is for")
        }
        (None, Some(_)) => anyhow::bail!(
            "--listener is only for the --capability path. On a grant the current listener \
             is found for you -- drop it, or add --capability"
        ),
        (None, None) => portal_core::session::Reach::Grant {
            peer: args.peer.as_deref(),
        },
    };

    let cfg = config(&args, &tokens, key).await?;
    let shutdown = CancellationToken::new();
    let connected = portal_core::session::connect(&cfg, reach, &shutdown)
        .await
        .context("connect to the portal server")?;
    println!("connection id: {}", connected.session.connection_id());

    for (protocol, local, service) in maps {
        let forwarding = match protocol {
            Protocol::Tcp => {
                portal_core::client::forward(
                    connected.peer.connection().clone(),
                    local,
                    service.clone(),
                    shutdown.clone(),
                )
                .await
            }
            // `Arc::clone` and not a binding kept here: `Connected::close`
            // drops the last one before it waits for msquic, and one held by
            // this loop would make that wait time out.
            Protocol::Udp => {
                portal_core::udp::forward(
                    std::sync::Arc::clone(&connected.sessions),
                    local,
                    service.clone(),
                    shutdown.clone(),
                )
                .await
            }
        }
        .with_context(|| format!("forward {protocol} {local} to `{service}`"))?;
        println!("{protocol} {forwarding} -> {service}");
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
        // **Both jobs, one task.** This moves the forwards onto a direct path
        // when one turns up, and returns when the connection is no longer
        // usable — which is what this arm is here for. They cannot be two
        // tasks: a connection's events are a single queue, so a second poller
        // would take events belonging to the first.
        _ = portal_core::path::keep_on_the_best_path(peer, shutdown.clone()) => {
            tracing::warn!("the peer connection closed; the forwards are going with it");
        }
    }
    connected.close().await;
    Ok(())
}

/// Redeem a pairing code, and say what it paired with.
async fn redeem(
    args: &Args,
    tokens: &std::path::Path,
    key: isekai_p2p::agent::EndpointKey,
    code: &str,
) -> anyhow::Result<()> {
    let cfg = config(args, tokens, key).await?;
    // Whatever was scanned, pasted or typed: a URI from a QR, or the eight
    // characters with or without their dash.
    let code = isekai_p2p::agent::pairing_code_from_input(code);
    let directory = isekai_p2p::PeerDirectory::open(&cfg)
        .await
        .context("open the proxy control plane")?;
    let grant = directory
        .pair(&code, args.label.as_deref())
        .await
        .context("redeem the pairing code")?;
    println!("paired with : {}", grant.owner_endpoint);
    println!("grant       : {}", grant.grant_id);
    println!("\nConnect with --map alone; the listener is found for you.");
    Ok(())
}

/// The P2P configuration these arguments describe.
///
/// Built in one place because three paths need it — pairing, a grant connect
/// and a capability connect — and only the last of those used to exist.
async fn config(
    args: &Args,
    tokens: &std::path::Path,
    key: isekai_p2p::agent::EndpointKey,
) -> anyhow::Result<P2pConfig> {
    let auth = portal_core::login::authenticate(tokens, args.auth0_token.as_deref()).await?;
    Ok(P2pConfig {
        identity_url: args.identity_url.clone(),
        identity_http3: args.identity_http3,
        proxy_url: args.proxy_url.clone(),
        auth0_token: auth.token,
        // **The whole point.** The Endpoint Token renewal runs every few
        // minutes for the life of the session and needs a current Auth0 token
        // each time; without this it reuses one that expires.
        auth0: auth.source,
        protocol: args.protocol.clone(),
        register: args.register,
        device_name: args.device_name.clone(),
        token_ttl: None,
        key,
    })
}

/// Parse `port:name` or `udp:port:name` into what to bind and what to ask for.
///
/// The address is assembled rather than formatted and re-parsed, which is what
/// lets `--bind ::1` work: an IPv6 address needs brackets in a `host:port`
/// string and does not have them here.
///
/// **The protocol has to be said and cannot be inferred.** The server looks a
/// name up under a protocol, so a `--map` that guessed wrong would be refused
/// with the same byte as a name that does not exist — a correct catalogue entry
/// reported as "the peer does not offer it". The prefix is optional only because
/// TCP is the common case; it is never ambiguous, since `udp` and `tcp` are not
/// port numbers.
fn maps(
    maps: &[String],
    bind: std::net::IpAddr,
) -> anyhow::Result<Vec<(Protocol, SocketAddr, String)>> {
    maps.iter()
        .map(|m| {
            let (protocol, rest) = match m.split_once(':') {
                Some(("tcp", rest)) => (Protocol::Tcp, rest),
                Some(("udp", rest)) => (Protocol::Udp, rest),
                _ => (Protocol::Tcp, m.as_str()),
            };
            let (port, service) = rest.split_once(':').with_context(|| {
                format!("--map wants `port:service` or `udp:port:service`, got `{m}`")
            })?;
            let port: u16 = port
                .parse()
                .with_context(|| format!("`{port}` is not a port, in --map `{m}`"))?;
            Ok((protocol, SocketAddr::new(bind, port), service.to_owned()))
        })
        .collect()
}
