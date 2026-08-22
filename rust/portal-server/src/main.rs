//! The side with the services.
//!
//! Declares what exists, waits for a client the proxy says is authorised, and
//! forwards each requested service to its target. Phase 1c-iii-c-ii of
//! `docs/portal_plan.md`.
//!
//! ```text
//! portal-server --auth0-token … --key ep.pem \
//!               --config portal-server.toml --allow ep:abc…
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
//! The catalogue is that file, and reading it is `portal_core::config`, which
//! is where the format and the reasoning live.
//!
//! # UDP services carry a size limit the file cannot raise
//!
//! `protocol = "udp"` is forwarded as of phase 3b, up to about 1200 bytes per
//! datagram; anything larger is dropped and counted rather than split.
//! `portal_core::datagram::MAX_PAYLOAD` has the arithmetic and the case to know
//! about, which is a large DNS response.

use std::path::PathBuf;

use anyhow::Context as _;
use argh::FromArgs;
use isekai_p2p::{load_or_generate_key, AcceptPolicy, P2pConfig};
use tokio_util::sync::CancellationToken;

/// Forward local TCP and UDP services to authorised peers over ISEKAI link.
///
/// A peer asks for a service **by name**. What each name means is this file's
/// business and never crosses the wire, so a caller cannot reach anything the
/// catalogue does not offer.
#[derive(FromArgs)]
#[argh(
    example = "\
portal-server --auth0-token $TOKEN --key ./portal-server.pem --register \\
              --config ./portal-server.toml --allow ep:1a2b3c… --capability-ttl 300",
    note = "\
The catalogue (--config), which is the whole of what may be reached:

  [service.db]
  protocol = \"tcp\"
  target   = \"10.0.0.5:5432\"

  [service.dns]
  protocol = \"udp\"
  target   = \"10.0.0.1:53\"

`target` is an address, never a hostname: resolving one would put a DNS answer
in charge of where forwarded traffic goes. `--example-config` writes a starter
file to stdout.

UDP payloads over about 1200 bytes are dropped rather than split, and counted.
The case to know is a large DNS response; docs/portal.md has the arithmetic.
",
    note = "\
Getting a peer connected takes one exchange, because the proxy will not let two
Endpoints talk until a Grant says so:

  1. the peer runs `portal-client --whoami` and tells you its Endpoint ID;
  2. you pass that to --allow, and this prints a capability;
  3. you give the peer that capability and the listener id printed here.

Both are printed on stdout at startup. **A capability is one-shot and lasts
300 seconds at most**, so start this with the peer already standing by --
and a peer that reconnects needs another one, which today means restarting
(issue #166)."
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
    /// auth0 access token, used only to obtain the Endpoint Token. Not needed
    /// with --example-config
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
    /// path to this Endpoint's signing key. Generated on first use; keep it,
    /// because a new one is a new Endpoint ID and every capability issued for
    /// the old one stops meaning anything. Not needed with --example-config
    #[argh(option, default = "PathBuf::from(\"portal-server.pem\")")]
    key: PathBuf,
    /// path to the certificate key this device keeps. Defaults to the Endpoint
    /// key's name with `-portal-cert` appended -- a separate key on purpose,
    /// since the Endpoint key is a signing identity and should never be handed
    /// to a QUIC stack
    #[argh(option)]
    cert_key: Option<PathBuf>,
    /// path to the service catalogue: what may be reached, and under what
    /// name. See the note below, or --example-config
    #[argh(option, default = "PathBuf::from(\"portal-server.toml\")")]
    config: PathBuf,
    /// print a starter catalogue on stdout and exit
    #[argh(switch)]
    example_config: bool,
    /// an Endpoint ID to issue a capability for at startup, printed on stdout.
    /// Repeatable
    #[argh(option)]
    allow: Vec<String>,
    /// how long an issued capability lasts, in seconds. The proxy clamps this
    /// to 30..=300 and defaults to 30, which is not long enough to send one to
    /// a person -- pass 300 unless the peer is already waiting
    #[argh(option)]
    capability_ttl: Option<u64>,
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

    if args.example_config {
        // Before the key, the token and the catalogue: this is what somebody
        // runs when they have none of the three yet.
        print!("{}", portal_core::config::EXAMPLE);
        return Ok(());
    }

    // Read before anything else touches the network: a typo in the catalogue
    // should cost a message, not a registered Endpoint and a listener nobody
    // can use.
    let catalogue = portal_core::config::load(&args.config)?;

    let cert_key = args.cert_key.clone().unwrap_or_else(|| {
        let mut path = args.key.clone();
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "endpoint".to_owned());
        path.set_file_name(format!("{stem}-portal-cert.pem"));
        path
    });

    // **Said out loud, because a generated key looks exactly like a loaded one
    // until it fails.** `--key` has a default, so running from a different
    // directory than last time silently makes a *second* Endpoint — and the
    // failure is `capability-endpoint-mismatch` from the proxy, several steps
    // later, naming nothing that points back here.
    if !args.key.exists() {
        tracing::info!(path = %args.key.display(), "generating a new Endpoint key");
    }

    let cfg = P2pConfig {
        identity_url: args.identity_url,
        identity_http3: args.identity_http3,
        proxy_url: args.proxy_url,
        auth0_token: args.auth0_token.context("--auth0-token is required")?,
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
    // Not just `shutdown.cancel()`: returning from `main` drops the runtime, and
    // the session withdraws the Peer Listener on its way out. Cancel-and-return
    // leaves it listed for its whole lease, pointing at a process that is gone.
    server.close().await;
    Ok(())
}
