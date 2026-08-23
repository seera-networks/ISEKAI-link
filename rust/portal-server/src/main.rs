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
portal-server --login

portal-server --key ./portal-server.pem --register \\
              --config ./portal-server.toml --pair

portal-server --grants",
    note = "\
Sign in once with --login. It runs the Auth0 device flow -- a code and a URL to
open -- and saves tokens beside the Endpoint key that refresh from then on, so
nothing else here needs a token.

--auth0-token still works and cannot be refreshed: when it expires the Endpoint
Token renewal stops being authorised and the session ends a few minutes later.
For a server meant to be left running that is the thing --login exists to fix.
",
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
The proxy will not let two Endpoints talk until this side has authorised them,
and there are two ways to do it. They are not alternatives of equal standing.

--pair shows a code. Whoever redeems it gets a GRANT, which is reusable, has no
expiry unless one is set, and -- because a Grant's key does not name a listener
(spec 8.8) -- keeps working when this server restarts onto a new listener id.
That is what an installation should run on. Use --grants to see who is in and
--revoke to take it away.

--allow issues a CAPABILITY for one Endpoint. It is one-shot and lasts 300
seconds at most, so it is for letting a guest in once. A peer that reconnects
on one needs another."
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
    /// refreshed -- `--login` is what keeps a long-running server working.
    /// Not needed with --example-config
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
    /// show a pairing code and let whoever redeems it in for good. This is
    /// the one to use: a redeemed code is a Grant, which is reusable and
    /// survives this server restarting
    #[argh(switch)]
    pair: bool,
    /// how long the pairing code lasts, in seconds. Clamped to 60..=300
    #[argh(option)]
    pairing_ttl: Option<u64>,
    /// print who may reach this Endpoint, and exit
    #[argh(switch)]
    grants: bool,
    /// take a grant away, by the id --grants prints
    #[argh(option)]
    revoke: Option<String>,
    /// an Endpoint ID to issue a one-shot capability for at startup, printed
    /// on stdout. For letting a guest in once; --pair is what standing access
    /// wants. Repeatable
    #[argh(option)]
    allow: Vec<String>,
    /// how long an issued capability lasts, in seconds. The proxy clamps this
    /// to 30..=300 and defaults to 30, which is not long enough to send one to
    /// a person -- pass 300 unless the peer is already waiting
    #[argh(option)]
    capability_ttl: Option<u64>,
}

/// Answer `--grants` and `--revoke`, which need no listener.
///
/// **Its own path, and it exits.** These are questions about who may reach this
/// Endpoint, and the answer lives on the proxy — a Peer Listener is what a peer
/// connects *through*, and standing one up to ask would put a second row under
/// this Endpoint for every client that then looks one up.
async fn administer_grants(args: &Args, tokens: &std::path::Path) -> anyhow::Result<()> {
    let cfg = config(args, tokens).await?;
    grant_admin(args, &cfg).await
}

/// The P2P configuration these arguments describe, authenticated however this
/// installation is.
async fn config(args: &Args, tokens: &std::path::Path) -> anyhow::Result<P2pConfig> {
    // **Authentication first, then the key.** The struct literal this replaced
    // evaluated the token before the key, so a run with neither a sign-in nor a
    // token bailed without writing anything; passing the key in as an argument
    // quietly reversed that and left a new Endpoint identity on disk before
    // failing.
    let auth = portal_core::login::authenticate(tokens, args.auth0_token.as_deref()).await?;
    let key = load_or_generate_key(&args.key)?;
    Ok(P2pConfig {
        identity_url: args.identity_url.clone(),
        identity_http3: args.identity_http3,
        proxy_url: args.proxy_url.clone(),
        auth0_token: auth.token,
        // **The whole point.** With this the Endpoint Token renewal, which runs
        // every few minutes for the life of the session, asks for a current
        // Auth0 token instead of reusing one that has expired.
        auth0: auth.source,
        protocol: args.protocol.clone(),
        register: args.register,
        device_name: args.device_name.clone(),
        token_ttl: None,
        key,
    })
}

async fn grant_admin(args: &Args, cfg: &P2pConfig) -> anyhow::Result<()> {
    let token = isekai_p2p::issue_endpoint_token(cfg).await?.endpoint_token;
    let proxy = isekai_p2p::proxy_client(cfg, &token)?;

    if let Some(grant_id) = &args.revoke {
        proxy
            .revoke_grant(grant_id)
            .await
            .with_context(|| format!("revoke {grant_id}"))?;
        println!("revoked     : {grant_id}");
    }
    if args.grants {
        let grants = proxy.list_grants().await.context("list grants")?;
        if grants.is_empty() {
            println!("Nobody is paired with this Endpoint.");
        }
        for grant in &grants {
            println!(
                "grant       : {}  {}  ({}{})",
                grant.grant_id,
                grant.allowed_endpoint,
                grant.origin,
                grant
                    .label
                    .as_deref()
                    .map(|l| format!(", {l}"))
                    .unwrap_or_default(),
            );
        }
    }
    Ok(())
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
    // **Never returns**, and that is the fix for Ctrl+C not stopping these
    // programs once traffic had started: returning from `main` drops the
    // runtime and then the registrations, and `RegistrationClose` blocks
    // uninterruptibly on a configuration's rundown reference that no timeout
    // covers. `portal_core::shutdown` has the whole of it.
    let code = match run(args).await {
        Ok(()) => 0,
        Err(e) => {
            // Printed here because `_exit` skips the reporting `main` would
            // have done by returning the error.
            eprintln!("Error: {e:#}");
            1
        }
    };
    portal_core::shutdown::leave(code).await
}

async fn run(args: Args) -> anyhow::Result<()> {
    if args.example_config {
        // Before the key, the token and the catalogue: this is what somebody
        // runs when they have none of the three yet.
        print!("{}", portal_core::config::EXAMPLE);
        return Ok(());
    }

    // **Before the catalogue and before any listener**, because neither is
    // needed to answer them: grants belong to this Endpoint rather than to a
    // listener (spec §8.8), so listing and revoking are Endpoint-token calls on
    // the control plane and nothing more.
    //
    // Standing a listener up for them would be worse than wasteful. A second
    // listener on this Endpoint and protocol is exactly what a client on a
    // grant then has to choose between, so an operator asking "who is in?"
    // would be making the connections they are asking about ambiguous.
    let tokens = args
        .auth0_tokens
        .clone()
        .unwrap_or_else(|| portal_core::login::tokens_beside(&args.key));
    if args.login {
        // Before the key, the catalogue and the network: this is what somebody
        // runs when they have none of them.
        return portal_core::login::sign_in(&tokens).await;
    }

    if args.grants || args.revoke.is_some() {
        return administer_grants(&args, &tokens).await;
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

    let cfg = config(&args, &tokens).await?;

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

    println!("endpoint id : {}", server.info.endpoint_id);
    // **The listener id is printed for diagnostics, not for carrying.** A
    // client on a grant looks the current one up for itself; only the
    // capability path needs it by hand, and only until the connect it is for.
    println!("listener id : {}", server.info.listener_id);

    if args.pair {
        // **`close()` on the way out of a failure, not `?`.** A listener this
        // process registered and did not withdraw stays listed for its whole
        // lease, and since phase 6 that is not merely untidy: it is a second row
        // under this Endpoint for every client that connects on a grant.
        let code = match server.show_pairing_code(args.pairing_ttl).await {
            Ok(code) => code,
            Err(e) => {
                server.close().await;
                return Err(e.context("mint a pairing code"));
            }
        };
        println!("\npairing code: {}", code.code);
        println!(
            "  or the URI: {}",
            isekai_p2p::agent::pairing_uri(&code.code)
        );
        println!("  expires at: {}", code.expires_at);
        println!("\nThe peer runs: portal-client --pair {}", code.code);
        println!("Once redeemed they can reconnect without asking again, and this");
        println!("server can restart without breaking it.");
    }

    for endpoint in &args.allow {
        let capability = match server.issue_capability(endpoint, args.capability_ttl).await {
            Ok(capability) => capability,
            Err(e) => {
                server.close().await;
                return Err(e.context(format!("issue a capability for {endpoint}")));
            }
        };
        println!("\ncapability  : {capability}   (for {endpoint})");
        println!("One-shot, and it expires -- give the client this and the listener id now.");
    }

    let mut events = server.signaling.subscribe();
    // **Made once, outside the loop.** `ctrl_c()` builds a future over signals
    // that arrive *after* it is created, so calling it inside the select meant
    // a fresh one every time a signaling event woke this loop — and a Ctrl+C
    // landing in the gap between one iteration ending and the next future
    // being built was simply not seen. Pinned so the same future is polled
    // across iterations rather than restarted.
    let signalled = tokio::signal::ctrl_c();
    tokio::pin!(signalled);
    // Only an interrupt arms the hatch: the loop also ends when the signaling
    // stream breaks, and turning a user's *first* press into a hard exit there
    // would skip withdrawing the Peer Listener — the one thing the comment
    // below says must not be skipped.
    let mut interrupted = false;
    loop {
        tokio::select! {
            _ = &mut signalled => { interrupted = true; break }
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
    if interrupted {
        portal_core::shutdown::hard_exit_on_second_interrupt();
    }
    // Not just `shutdown.cancel()`: returning from `main` drops the runtime, and
    // the session withdraws the Peer Listener on its way out. Cancel-and-return
    // leaves it listed for its whole lease, pointing at a process that is gone.
    server.close().await;
    Ok(())
}
