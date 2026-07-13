//! ISEKAI P2P Connect agent CLI.
//!
//! Ties together the Endpoint identity, the Identity API client, the proxy
//! control-plane client (over msquic HTTP/3) and the MASQUE bind session. Each
//! subcommand performs one step of the flow so they can be chained (like the
//! server repo's `flow.sh`, but as the real client).

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, bail};
use argh::FromArgs;
use isekai_agent::bind::{open_bind_session, open_connect_relay};
use isekai_agent::endpoint::EndpointKey;
use isekai_agent::identity::IdentityClient;
use isekai_agent::proxy::{Candidate, CandidateType, ControlPlaneTransport, ProxyClient};
use isekai_agent::transport::MasqueH3Transport;

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
    /// identity API base URL (e.g. https://identity.isekai.link)
    #[argh(option)]
    identity_url: String,
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
    /// proxy base URL (e.g. https://proxy.isekai.link:8443)
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
    /// proxy base URL (e.g. https://proxy.isekai.link:8443)
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
    /// proxy base URL (e.g. https://proxy.isekai.link:8443)
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
    /// auth0 token for the relay data path; when set, opens the CONNECT-UDP
    /// relay leg after connecting and runs it until Ctrl-C
    #[argh(option)]
    auth0_token: Option<String>,
    /// local UDP address to bind for the relay leg (default 127.0.0.1:0)
    #[argh(option)]
    relay_local_addr: Option<String>,
}

/// Get a peer connection's current state.
#[derive(FromArgs)]
#[argh(subcommand, name = "get-connection")]
struct GetConnection {
    /// proxy base URL (e.g. https://proxy.isekai.link:8443)
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
    /// proxy base URL (e.g. https://proxy.isekai.link:8443)
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
    /// auth0 access token (the MASQUE data path authenticates with Auth0)
    #[argh(option)]
    auth0_token: String,
    /// connection id to tag the bind session with
    #[argh(option)]
    connection_id: String,
    /// local UDP address to forward inbound relay traffic to
    #[argh(option)]
    forward_to: SocketAddr,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_env("SEERA_LOG"))
        .with_writer(std::io::stderr)
        .init();

    let cli: Cli = argh::from_env();
    let result = dispatch(cli).await;

    // One-shot CLI over msquic. msquic's `Registration` spawns native worker
    // threads that outlive `main`, so a normal return would hang the process
    // (and thus any script driving the CLI). Going through `std::process::exit`
    // is no good either: it runs libc atexit / msquic's C++ static destructors,
    // which race those worker threads and abort with SIGABRT. `_exit(2)`
    // terminates immediately, skipping destructors — safe here because the
    // command's output is already flushed to stdout/stderr below.
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
    unsafe { libc_exit(code) }
}

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
        Command::Connect(a) => {
            let client = proxy_client(&a.proxy_url, &a.key, &a.token)?;
            let candidates = parse_candidates(&a.candidate)?;
            let conn = client
                .peer_connect(&a.capability, &a.listener_id, &a.protocol, &candidates)
                .await?;
            print_json(&conn)?;
            // When an Auth0 token is supplied, open the CONNECT-UDP relay leg to
            // the returned masque_uri and run it until Ctrl-C.
            if let Some(auth0) = a.auth0_token.as_deref() {
                let relay = conn.relay.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("connect response has no relay info; cannot open relay leg")
                })?;
                let local_bind: SocketAddr = a
                    .relay_local_addr
                    .as_deref()
                    .unwrap_or("127.0.0.1:0")
                    .parse()
                    .context("invalid --relay-local-addr")?;
                let handle = open_connect_relay(
                    &a.proxy_url,
                    auth0,
                    &conn.connection_id,
                    &relay.masque_uri,
                    local_bind,
                )
                .await?;
                print_json(&serde_json::json!({
                    "relay_local_addr": handle.local_addr.to_string(),
                }))?;
                tracing::info!(
                    "relay leg running; send UDP to {} (Ctrl-C to stop)",
                    handle.local_addr
                );
                tokio::signal::ctrl_c()
                    .await
                    .context("waiting for Ctrl-C")?;
                handle.close().await;
            }
            Ok(())
        }
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
    let key = load_key(&a.key)?;
    let client = IdentityClient::new(&a.identity_url);
    let token = if a.register {
        client
            .register_and_issue(&a.auth0_token, &key, a.device_name.as_deref(), a.ttl)
            .await?
    } else {
        client
            .issue_token(&a.auth0_token, &key, None, None, a.ttl)
            .await?
    };
    print_json(&serde_json::json!({
        "endpoint_token": token.endpoint_token,
        "expires_in": token.expires_in,
        "endpoint_id": token.endpoint_id,
        "permissions": token.permissions,
        "protocols": token.protocols,
    }))
}

async fn run_bind(a: Bind) -> anyhow::Result<()> {
    let mut session =
        open_bind_session(&a.proxy_url, &a.auth0_token, &a.connection_id, a.forward_to)?;
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
