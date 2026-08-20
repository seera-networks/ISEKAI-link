//! ISEKAI P2P Connect agent CLI.
//!
//! Ties together the Endpoint identity, the Identity API client, the proxy
//! control-plane client and the MASQUE relay legs. Each subcommand performs one
//! step of the flow so they can be chained. The multi-step in-process flows
//! (obtaining a token, and connect-then-relay) run through the `isekai-p2p`
//! session facades; the single control-plane calls use the `isekai-p2p-core`
//! primitives directly.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context};
use argh::FromArgs;
use isekai_p2p::config::{issue_endpoint_token, P2pConfig};
use isekai_p2p::initiator::InitiatorSession;
use isekai_p2p_core::endpoint::EndpointKey;
use isekai_p2p_core::proxy::{Candidate, CandidateType, ControlPlaneTransport, ProxyClient};
use isekai_p2p_core::transport::{shutdown_msquic, MasqueH3Transport};

/// ISEKAI P2P Connect agent.
#[derive(FromArgs)]
struct Cli {
    #[argh(subcommand)]
    cmd: Command,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Command {
    Keygen(Keygen),
    Token(Token),
    CreateListener(CreateListener),
    IssueCapability(IssueCapability),
    Connect(Connect),
    GetConnection(GetConnection),
    ReportState(ReportState),
    Bind(Bind),
}

/// Generate an Endpoint keypair and print its id / JWK.
#[derive(FromArgs)]
#[argh(subcommand, name = "keygen")]
struct Keygen {
    /// path to write the PKCS#8 PEM private key
    #[argh(option)]
    out: PathBuf,
}

/// Register (optionally) and obtain an Endpoint Token from the Identity API.
#[derive(FromArgs)]
#[argh(subcommand, name = "token")]
struct Token {
    /// identity API base URL (HTTPS only, e.g. https://identity.isekai.tools:9443)
    #[argh(option)]
    identity_url: String,
    /// talk to the Identity API over HTTP/3 (QUIC) instead of HTTP/1.1 + HTTP/2
    #[argh(switch)]
    identity_http3: bool,
    /// auth0 access token (Bearer)
    #[argh(option)]
    auth0_token: String,
    /// path to the Endpoint PKCS#8 PEM key
    #[argh(option)]
    key: PathBuf,
    /// also register the Endpoint first (challenge + register)
    #[argh(switch)]
    register: bool,
    /// device display name (for registration)
    #[argh(option)]
    device_name: Option<String>,
    /// requested token TTL in seconds
    #[argh(option)]
    ttl: Option<i64>,
}

/// Create a Private Peer Listener.
#[derive(FromArgs)]
#[argh(subcommand, name = "create-listener")]
struct CreateListener {
    /// proxy base URL (e.g. https://tokyo.link.isekai.tools:8443)
    #[argh(option)]
    proxy_url: String,
    /// path to the Endpoint PKCS#8 PEM key (for PoP)
    #[argh(option)]
    key: PathBuf,
    /// endpoint Token (Bearer)
    #[argh(option)]
    token: String,
    /// protocol
    #[argh(option)]
    protocol: String,
    /// listener TTL in seconds
    #[argh(option)]
    ttl: Option<u64>,
}

/// Issue a Capability for an Endpoint on a listener.
#[derive(FromArgs)]
#[argh(subcommand, name = "issue-capability")]
struct IssueCapability {
    /// proxy base URL (e.g. https://tokyo.link.isekai.tools:8443)
    #[argh(option)]
    proxy_url: String,
    /// path to the Endpoint PKCS#8 PEM key (for PoP)
    #[argh(option)]
    key: PathBuf,
    /// endpoint Token (Bearer)
    #[argh(option)]
    token: String,
    /// listener id
    #[argh(option)]
    listener_id: String,
    /// endpoint id allowed to connect
    #[argh(option)]
    allowed_endpoint: String,
    /// protocol
    #[argh(option)]
    protocol: String,
    /// capability TTL in seconds
    #[argh(option)]
    ttl: Option<u64>,
}

/// Initiate a peer connection with a Capability.
#[derive(FromArgs)]
#[argh(subcommand, name = "connect")]
struct Connect {
    /// proxy base URL (e.g. https://tokyo.link.isekai.tools:8443)
    #[argh(option)]
    proxy_url: String,
    /// path to the Endpoint PKCS#8 PEM key (for PoP)
    #[argh(option)]
    key: PathBuf,
    /// endpoint Token (Bearer)
    #[argh(option)]
    token: String,
    /// capability token
    #[argh(option)]
    capability: String,
    /// listener id
    #[argh(option)]
    listener_id: String,
    /// protocol
    #[argh(option)]
    protocol: String,
    /// candidate `type,address,port` (repeatable)
    #[argh(option)]
    candidate: Vec<String>,
    /// open the CONNECT-UDP relay leg after connecting and run it until Ctrl-C.
    /// The data path authenticates with the same Endpoint Token and key as the
    /// control plane (--token / --key)
    #[argh(switch)]
    relay: bool,
    /// local UDP address to bind for the relay leg (default 127.0.0.1:0)
    #[argh(option)]
    relay_local_addr: Option<String>,
}

/// Get a peer connection's current state.
#[derive(FromArgs)]
#[argh(subcommand, name = "get-connection")]
struct GetConnection {
    /// proxy base URL (e.g. https://tokyo.link.isekai.tools:8443)
    #[argh(option)]
    proxy_url: String,
    /// path to the Endpoint PKCS#8 PEM key (for PoP)
    #[argh(option)]
    key: PathBuf,
    /// endpoint Token (Bearer)
    #[argh(option)]
    token: String,
    /// connection id
    #[argh(option)]
    connection_id: String,
}

/// Report a peer connection's state (and candidates).
#[derive(FromArgs)]
#[argh(subcommand, name = "report-state")]
struct ReportState {
    /// proxy base URL (e.g. https://tokyo.link.isekai.tools:8443)
    #[argh(option)]
    proxy_url: String,
    /// path to the Endpoint PKCS#8 PEM key (for PoP)
    #[argh(option)]
    key: PathBuf,
    /// endpoint Token (Bearer)
    #[argh(option)]
    token: String,
    /// connection id
    #[argh(option)]
    connection_id: String,
    /// state: relay | hole_punching | direct | closed
    #[argh(option)]
    state: String,
    /// candidate `type,address,port` (repeatable)
    #[argh(option)]
    candidate: Vec<String>,
}

/// Open a MASQUE bind session for a connection and relay to a local address.
#[derive(FromArgs)]
#[argh(subcommand, name = "bind")]
struct Bind {
    /// proxy base URL
    #[argh(option)]
    proxy_url: String,
    /// path to the Endpoint PKCS#8 PEM key (for PoP)
    #[argh(option)]
    key: PathBuf,
    /// endpoint Token (Bearer) — the MASQUE data path authenticates with the
    /// Endpoint Token + PoP, not with an Auth0 token
    #[argh(option)]
    token: String,
    /// connection id to tag the bind session with
    #[argh(option)]
    connection_id: String,
    /// local UDP address to forward inbound relay traffic to
    #[argh(option)]
    forward_to: SocketAddr,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_env("SEERA_LOG"))
        .with_writer(std::io::stderr)
        .init();

    let cli: Cli = argh::from_env();

    let runtime = tokio::runtime::Runtime::new().expect("failed to build tokio runtime");
    let (result, drained) = runtime.block_on(async {
        let result = dispatch(cli).await;
        // `dispatch` has returned, so every transport, bind session and relay
        // leg it built is dropped and the only msquic handles left are the ones
        // held by the background h3 drivers. Draining the registration ends
        // those drivers and closes their connections, after which
        // `RegistrationClose` returns promptly.
        let drained = shutdown_msquic(MSQUIC_DRAIN_TIMEOUT).await;
        (result, drained)
    });
    // Join the worker threads before exiting: msquic's `MsQuicClose` runs from a
    // process destructor, and it must not race tokio tasks that could still be
    // touching msquic.
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);

    use std::io::Write as _;
    let code = match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Error: {e:#}");
            1
        }
    };
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();

    if drained {
        std::process::exit(code);
    }

    // The drain timed out, so msquic handles are still live and its worker
    // threads are still running. Returning normally would hang this one-shot CLI
    // (and any script driving it), and `std::process::exit` would run libc
    // atexit / msquic's C++ static destructors, which race those threads and
    // abort with SIGABRT. `_exit(2)` terminates immediately, skipping
    // destructors — safe here because output is already flushed above.
    tracing::warn!("msquic drain timed out; exiting without running destructors");
    unsafe { libc_exit(code) }
}

/// How long to wait for msquic handles to close before giving up and exiting
/// hard. Generous: this only elapses if a handle leaked, and the fallback path
/// is a `_exit(2)` that skips destructors.
const MSQUIC_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to wait for the tokio worker threads to finish after the drain.
const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

// Raw libc `_exit`: immediate process termination without running atexit
// handlers or C++ static destructors (see the note in `main`). Always linked
// (Rust binaries link libc), so no extra dependency is required.
unsafe extern "C" {
    #[link_name = "_exit"]
    fn libc_exit(code: i32) -> !;
}

async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    match cli.cmd {
        Command::Keygen(a) => keygen(a),
        Command::Token(a) => token(a).await,
        Command::CreateListener(a) => {
            let client = proxy_client(&a.proxy_url, &a.key, &a.token)?;
            print_json(&client.create_peer_listener(&a.protocol, a.ttl).await?)
        }
        Command::IssueCapability(a) => {
            let client = proxy_client(&a.proxy_url, &a.key, &a.token)?;
            print_json(
                &client
                    .issue_capability(&a.listener_id, &a.allowed_endpoint, &a.protocol, a.ttl)
                    .await?,
            )
        }
        Command::Connect(a) => connect(a).await,
        Command::GetConnection(a) => {
            let client = proxy_client(&a.proxy_url, &a.key, &a.token)?;
            print_json(&client.get_connection(&a.connection_id).await?)
        }
        Command::ReportState(a) => {
            let client = proxy_client(&a.proxy_url, &a.key, &a.token)?;
            let candidates = parse_candidates(&a.candidate)?;
            print_json(
                &client
                    .report_state(&a.connection_id, &a.state, &candidates)
                    .await?,
            )
        }
        Command::Bind(a) => run_bind(a).await,
    }
}

fn keygen(a: Keygen) -> anyhow::Result<()> {
    let key = EndpointKey::generate();
    let pem = key.to_pkcs8_pem()?;
    write_private(&a.out, &pem)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "endpoint_id": key.endpoint_id(),
            "public_jwk": key.public_jwk(),
            "key_path": a.out,
        }))?
    );
    Ok(())
}

async fn token(a: Token) -> anyhow::Result<()> {
    let cfg = P2pConfig {
        identity_url: a.identity_url,
        identity_http3: a.identity_http3,
        // Unused by token issuance, but the config is shared with the sessions.
        proxy_url: String::new(),
        auth0_token: a.auth0_token,
        protocol: String::new(),
        register: a.register,
        device_name: a.device_name,
        token_ttl: a.ttl,
        auth0: None,
        key: load_key(&a.key)?,
    };
    let token = issue_endpoint_token(&cfg).await?;
    print_json(&serde_json::json!({
        "endpoint_token": token.endpoint_token,
        "expires_in": token.expires_in,
        "endpoint_id": token.endpoint_id,
        "permissions": token.permissions,
        "protocols": token.protocols,
    }))
}

async fn connect(a: Connect) -> anyhow::Result<()> {
    // Without --relay this is a single control-plane call; print and exit.
    if !a.relay {
        let client = proxy_client(&a.proxy_url, &a.key, &a.token)?;
        let candidates = parse_candidates(&a.candidate)?;
        let conn = client
            .peer_connect(&a.capability, &a.listener_id, &a.protocol, &candidates)
            .await?;
        return print_json(&conn);
    }

    // With --relay this is peer-connect + open the relay leg, held until Ctrl-C
    // — exactly an `InitiatorSession`.
    let local_bind: SocketAddr = a
        .relay_local_addr
        .as_deref()
        .unwrap_or("127.0.0.1:0")
        .parse()
        .context("invalid --relay-local-addr")?;
    let cfg = P2pConfig {
        identity_url: String::new(),
        identity_http3: false,
        proxy_url: a.proxy_url,
        auth0_token: String::new(),
        protocol: a.protocol,
        // The token/key came straight from the caller; no Identity round-trip.
        register: false,
        device_name: None,
        token_ttl: None,
        auth0: None,
        key: load_key(&a.key)?,
    };
    let candidates = parse_candidates(&a.candidate)?;
    let session = InitiatorSession::connect_with_token(
        &cfg,
        &a.token,
        &a.capability,
        &a.listener_id,
        &candidates,
        local_bind,
    )
    .await?;
    print_json(&session.connection)?;
    print_json(&serde_json::json!({
        "relay_local_addr": session.local_addr.to_string(),
    }))?;
    tracing::info!(
        "relay leg running; send UDP to {} (Ctrl-C to stop)",
        session.local_addr
    );
    tokio::signal::ctrl_c()
        .await
        .context("waiting for Ctrl-C")?;
    session.close().await;
    Ok(())
}

async fn run_bind(a: Bind) -> anyhow::Result<()> {
    let key = load_key(&a.key)?;
    let mut session = isekai_p2p_core::bind::open_bind_session(
        &a.proxy_url,
        &a.token,
        &key,
        &a.connection_id,
        a.forward_to,
        // The CLI does not migrate paths, so the leg keeps its plain connected
        // socket and its own registration.
        isekai_p2p_core::bind::RelayOptions::default(),
    )
    .await?;
    eprintln!(
        "bind session open for connection {} (forwarding to {}); Ctrl-C to stop",
        a.connection_id, a.forward_to
    );
    loop {
        tokio::select! {
            event = session.events.recv() => match event {
                Some(event) => println!("{event:?}"),
                None => break,
            },
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    session.close().await;
    Ok(())
}

fn proxy_client(
    proxy_url: &str,
    key: &PathBuf,
    token: &str,
) -> anyhow::Result<ProxyClient<impl ControlPlaneTransport>> {
    let key = load_key(key)?;
    let transport = MasqueH3Transport::connect(proxy_url)?;
    Ok(ProxyClient::new(transport, key, token))
}

fn load_key(path: &PathBuf) -> anyhow::Result<EndpointKey> {
    let pem = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read Endpoint key at {}", path.display()))?;
    EndpointKey::from_pkcs8_pem(&pem).map_err(anyhow::Error::from)
}

fn write_private(path: &PathBuf, contents: &str) -> anyhow::Result<()> {
    std::fs::write(path, contents)
        .with_context(|| format!("failed to write key at {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Parse a `type,address,port` candidate (comma-separated so IPv6 colons are ok).
fn parse_candidates(specs: &[String]) -> anyhow::Result<Vec<Candidate>> {
    specs.iter().map(|s| parse_candidate(s)).collect()
}

fn parse_candidate(spec: &str) -> anyhow::Result<Candidate> {
    let parts: Vec<&str> = spec.splitn(3, ',').collect();
    let [ty, address, port] = parts.as_slice() else {
        bail!("candidate must be `type,address,port`: {spec:?}");
    };
    let r#type = match *ty {
        "host" => CandidateType::Host,
        "srflx" => CandidateType::Srflx,
        "relay" => CandidateType::Relay,
        other => bail!("unknown candidate type {other:?}"),
    };
    Ok(Candidate {
        r#type,
        address: (*address).to_owned(),
        port: port
            .parse()
            .with_context(|| format!("invalid port in {spec:?}"))?,
    })
}

fn print_json<T: serde::Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
