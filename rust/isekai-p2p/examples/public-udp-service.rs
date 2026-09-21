//! Publish a UDP service at an address the world can reach
//! (`docs/public_listener_client_plan.md` P4).
//!
//! ```text
//!   anyone, from anywhere            ← the point: these are strangers
//!        ↕ UDP to the published ip:port
//!   the data plane holding that port
//!        ↕ CONNECT-UDP (MASQUE)
//!   this process
//!        ↕ local UDP
//!   an echo server this process runs
//! ```
//!
//! **The echo is here so the last hop proves something.** What P4 has to show
//! is that a datagram sent to the published address arrives *in this process*,
//! and that needs a service anyone can call — `nc -u`, `socat`, a phone on
//! mobile data. Anything speaking UDP can take its place; it is the
//! `--forward-to` of a real deployment.
//!
//! ## Running it
//!
//! ```sh
//! # once, to sign in (portal-client writes the same token store)
//! portal-client --login --organization org_…
//!
//! cargo run -p isekai-p2p --example public-udp-service -- \
//!     --auth0-tokens portal-client-auth0.json --key public-udp.pem --register
//! ```
//!
//! It prints the address to send to. From anywhere:
//!
//! ```sh
//! echo hello | nc -u -w1 203.0.113.9 10042
//! ```
//!
//! **Send from a few different source ports** and watch the log: one forwarding
//! socket appears per source, which is what `ForwardLimits` bounds. That is the
//! other thing only this example can show — a relay leg has one peer, so the
//! behaviour does not arise there at all.
//!
//! ```sh
//! RUST_LOG=info,isekai_p2p=debug cargo run …
//! ```
//!
//! pairs each sender with the socket it cost. **At `info` the sender's address
//! is nowhere**: what the forwarded service sees is the loopback socket, and
//! nothing downstream of the tunnel knows who is on the other end of it.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context as _;
use argh::FromArgs;
use isekai_p2p::auth0::RefreshingAuth0Token;
use isekai_p2p::proxy_client;
use isekai_p2p::public::{publish, PublishOptions};
use isekai_p2p_core::proxy::{PublicAddress, PublicTarget};

/// Publish a UDP echo service at a public address.
#[derive(FromArgs)]
struct Args {
    /// the control plane
    #[argh(option, default = "String::from(\"https://link.isekai.tools:6443\")")]
    proxy_url: String,
    /// where Endpoint Tokens come from
    #[argh(
        option,
        default = "String::from(\"https://identity.isekai.tools:9443\")"
    )]
    identity_url: String,
    /// the Auth0 token store written by `portal-client --login`
    #[argh(option)]
    auth0_tokens: PathBuf,
    /// this Endpoint's signing key, generated on first use
    #[argh(option, default = "PathBuf::from(\"public-udp.pem\")")]
    key: PathBuf,
    /// register the Endpoint before issuing a token (first run with a new key)
    #[argh(switch)]
    register: bool,
    /// what to tell the world is behind this address. **Metadata**: the proxy
    /// does not interpret it (§7.7.3), and the forwarding below is what
    /// actually carries traffic
    #[argh(option, default = "String::from(\"127.0.0.1:7\")")]
    target: String,
    /// which region the address should be in, on the first allocation this
    /// account ever gets
    #[argh(option)]
    region: Option<String>,
    /// how long the Listener lives, in seconds (60..=86400)
    #[argh(option)]
    ttl: Option<u64>,
    /// where to keep the address this published last time, so a move can be
    /// noticed across restarts
    #[argh(option, default = "PathBuf::from(\"public-udp-address.json\")")]
    state: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();
    let args: Args = argh::from_env();

    // The service being published. A real one is already running somewhere;
    // this example brings its own so there is something to answer.
    let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let forward_to = echo.local_addr()?;
    tokio::spawn(echo_forever(echo));

    let tokens = RefreshingAuth0Token::load(&args.auth0_tokens).with_context(|| {
        format!(
            "no Auth0 tokens at {}. Run `portal-client --login` first",
            args.auth0_tokens.display(),
        )
    })?;
    let source = RefreshingAuth0Token::new(
        isekai_p2p::auth0::Auth0Config::default(),
        tokens,
        Some(args.auth0_tokens.clone()),
    );
    let cfg = isekai_p2p::P2pConfig {
        identity_url: args.identity_url.clone(),
        identity_http3: false,
        proxy_url: args.proxy_url.clone(),
        credential: isekai_p2p::Credential::auth0(
            isekai_p2p::Auth0TokenSource::auth0_token(source.as_ref()).await?,
            Some(source.clone()),
            args.register,
        ),
        protocol: "isekai-portal-v1".to_owned(),
        device_name: Some("public-udp-service".to_owned()),
        token_ttl: None,
        key: isekai_p2p::load_or_generate_key(&args.key)?,
        narrowing: Default::default(),
    };

    let token = isekai_p2p::issue_endpoint_token(&cfg).await?;
    let proxy = proxy_client(&cfg, &token.endpoint_token)?;
    // **The renewal is what keeps this running past the token's few minutes.**
    // A public session is not cut when its lease lapses, but every *next*
    // ticket is an authenticated call, so a stale token ends the ability to
    // reconnect rather than the session in hand.
    let _renewal =
        isekai_p2p::config::spawn_token_renewal(cfg.clone(), proxy.clone(), Some(token.expires_in));

    let target: SocketAddr = args.target.parse().context("--target is an ip:port")?;
    let published = read_published(&args.state);
    let endpoint = publish(
        &cfg,
        &proxy,
        PublicTarget {
            host: target.ip().to_string(),
            port: target.port(),
        },
        forward_to,
        PublishOptions {
            // **Stable across restarts, and about what is published** — which
            // is why the target is in it. A fresh key per run makes every
            // restart another Listener and eight of those is the quota; a key
            // that ignores what changed hands back the old Listener for 24
            // hours, still advertising the target that was asked for last time.
            idempotency_key: &format!(
                "public-udp-service:{}:{target}:{}",
                cfg.key.endpoint_id(),
                args.ttl.map(|t| t.to_string()).unwrap_or_default(),
            ),
            region: args.region.as_deref(),
            ttl: args.ttl,
            published: published.as_ref(),
        },
    )
    .await?;

    if let Some(moved) = endpoint.moved() {
        println!(
            "The address MOVED: it was {}, and is now {}.",
            moved.from, moved.to
        );
        println!("Anything holding the old one is talking to nothing.");
    }
    let address = endpoint.advertised().clone();
    // **Not fatal.** The Listener exists and the session is carrying traffic;
    // failing here loses the comparison this note enables on the next run, and
    // exiting would throw away the publish as well — which is the trade
    // `read_published` already refuses to make in the other direction.
    if let Err(e) = write_published(&args.state, &address) {
        tracing::warn!("could not remember this address; a move will go unnoticed: {e:#}");
    }

    println!("listener  : {}", endpoint.listener_id());
    println!("address   : {address}");
    println!();
    println!("Send it something, from anywhere:");
    println!("    echo hello | nc -u -w1 {} {}", address.ip, address.port);
    println!();
    println!("Ctrl-C to stop. The Listener is left in place; it lapses with its TTL.");

    // **Both ways this ends.** Waiting only on Ctrl-C would leave the process
    // sitting on an address that forwards nothing if the session dies — a data
    // plane restarting, a QUIC connection lost — which looks exactly like a
    // quiet afternoon. The watch's sender lives in the task that drives the
    // session, so its closing is that task's ending.
    let mut alive = endpoint.reported();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        // **Until the sender is gone, not until the value moves.** A receiver
        // cloned after the address was reported has not seen it yet, so its
        // first `changed()` returns at once — which ended this example a
        // moment after it started. What is being waited for is the task that
        // holds the sender ending, which is `Err`.
        _ = async { while alive.changed().await.is_ok() {} } => {
            println!("The session ended; this address is no longer carrying anything.");
        }
    }
    endpoint.close().await;
    leave().await
}

/// Stop, without running the destructors that can refuse to.
///
/// **Returning from `main` was not an exit.** Dropping the msquic registration
/// runs `RegistrationClose`, which blocks uninterruptibly on any handle still
/// outstanding — the first version of this example ended in a core dump, and
/// the second hung after Ctrl-C with "still has live handles". Draining first
/// and then leaving through `_exit` is what every binary in this workspace
/// does, for exactly this.
async fn leave() -> ! {
    if !isekai_p2p::agent::drain_msquic(std::time::Duration::from_secs(5)).await {
        tracing::debug!("msquic still had live handles; leaving anyway");
    }
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    // SAFETY: `_exit` ends the process; nothing after it runs, which is the
    // point.
    unsafe { libc_exit(0) }
}

unsafe extern "C" {
    #[link_name = "_exit"]
    fn libc_exit(code: i32) -> !;
}

/// Answer every datagram with what it said.
///
/// **One socket, many senders**, which is the shape of the thing being
/// published: the replies go back where each came from.
async fn echo_forever(socket: tokio::net::UdpSocket) {
    let mut buf = vec![0u8; 2048];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, via)) => {
                // **`via`, not `from`.** This is the loopback socket the
                // forward bound for one remote source — not the sender, whose
                // address never reaches this far. A distinct `via` per sender
                // is the thing `ForwardLimits` bounds; `RUST_LOG=isekai_p2p=debug`
                // shows which sender each belongs to.
                tracing::info!(%via, len, "a datagram arrived through the tunnel");
                if let Err(e) = socket.send_to(&buf[..len], via).await {
                    tracing::warn!(%via, "could not answer: {e}");
                }
            }
            Err(e) => {
                tracing::error!("the echo socket failed: {e}");
                return;
            }
        }
    }
}

/// The address published last time, if this has run before.
///
/// **A missing or unreadable file is "no previous address"**, not an error: it
/// is what a first run looks like, and refusing to start over a note-to-self
/// would be worse than losing the comparison it enables.
fn read_published(path: &std::path::Path) -> Option<PublicAddress> {
    let raw = std::fs::read(path).ok()?;
    match serde_json::from_slice(&raw) {
        Ok(address) => Some(address),
        Err(e) => {
            tracing::warn!(path = %path.display(), "ignoring an unreadable address note: {e}");
            None
        }
    }
}

fn write_published(path: &std::path::Path, address: &PublicAddress) -> anyhow::Result<()> {
    std::fs::write(path, serde_json::to_vec_pretty(address)?)
        .with_context(|| format!("remember this address in {}", path.display()))
}
