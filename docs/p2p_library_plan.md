# Implementation Plan: a reusable P2P Connect library for the camera apps

## 1. Goal

Make the P2P Connect functionality that today lives only in the `ISEKAI-agent`
CLI usable as a library, and consume it from `camera-server` and
`camera-client` so two peers can stream video **peer-to-peer through the MASQUE
proxy relay** — without the server publishing a reachable public address.

Scope decisions (agreed up front):

- **New crate.** Add an integration crate (working name **`isekai-p2p`**) that
  wraps the `isekai-agent` primitives into a high-level session API. The CLI and
  the camera apps both depend on it.
- **P2P is an added option, not a replacement.** The camera apps keep their
  current `isekai-link-utils` direct/cert path; P2P becomes a second connection
  mode selected in the UI. The two paths stay independent.
- **Manual capability exchange (step 1).** The server app displays the
  `capability` / `listener_id` / `endpoint_id`; the client app takes them as
  pasted input, exactly as the CLI does today. An automated signaling channel is
  out of scope for this plan (see §8).

## 2. Current state

### `ISEKAI-agent` — lib + bin

The crate is already `[lib] isekai_agent` plus a `[[bin]]` gated on the `msquic`
feature. The library exposes **primitives**:

- `identity::IdentityClient<T>` — register + issue Endpoint Token, generic over
  `proxy::ControlPlaneTransport`.
- `https::HttpsTransport` (h1/h2) and `transport::MasqueH3Transport` (h3,
  `msquic`) — the two transports.
- `proxy::ProxyClient<T>` — control plane: `create_peer_listener`,
  `issue_capability`, `peer_connect`, `get_connection`, `report_state`,
  `delete_peer_listener`.
- `bind::{open_bind_session, open_connect_relay}` (`msquic`) — the two relay
  data-path legs, returning a `BindSession` / `ConnectRelay` whose
  `local_addr` a co-located app forwards to.
- `endpoint::EndpointKey`, `pop`.

The **orchestration that ties these together** — register → token →
create-listener → issue-capability, and capability → peer-connect →
open-connect-relay, and the target side's open-bind-session — lives entirely in
`main.rs` as `argh` subcommand handlers (`dispatch`, `token`, `run_bind`, the
`Connect` arm). None of it is callable as a function. That is the gap this plan
closes.

### Camera apps — old model, unrelated to P2P

`camera-server` and `camera-client` use `isekai-link-utils`
(`create_forward_masque_connection`, `get_certificate`, `get_public_address`,
`make_msquic_async_listener`). Auth is an Auth0 JWT typed into the UI; the proxy
issues a per-user cert and a public address; **the client dials that public
`IP:port` directly** over QUIC.

The **video transport** is independent of all that: MJPEG frames, one per QUIC
**unidirectional stream**, ALPN `sample`.

- `camera-server`: accepts on a `msquic_async::Listener` (ALPN `sample`) that
  sits behind the forward-MASQUE connection, and pushes each JPEG as a new uni
  stream (`main.rs`, the `run_isekai_connection` accept loop).
- `camera-client`: `Connection::new` + `start(config, addr, port)` to the public
  address (ALPN `sample`, `NO_CERTIFICATE_VALIDATION`), then
  `accept_inbound_uni_stream` in a loop (`main.rs::connect`).

The key realization: **the video QUIC connection is just UDP**, so it can run
unmodified *over* a P2P relay leg. The relay carries the QUIC packets; neither
the frame format nor the ALPN-`sample` listener/dialer has to change.

## 3. Design

### 3.1 Data flow in P2P mode

```
camera-client                         MASQUE proxy                    camera-server
  QUIC(sample) dial ─► ConnectRelay ─► loopback edge ◄─ BindSession ◄─ QUIC(sample) listen
     (video)          local UDP addr   (relay session)  local UDP addr    (video, MJPEG uni streams)
```

- **Server (target/listener):** binds its ALPN-`sample` QUIC listener on
  `127.0.0.1:S`, then opens a P2P **bind session** whose relay forwards inbound
  UDP to `127.0.0.1:S`.
- **Client (initiator):** opens a P2P **connect relay leg**, gets a local UDP
  address `127.0.0.1:C`, and dials its ALPN-`sample` QUIC connection at
  `127.0.0.1:C` instead of a public address.

Everything between the two loopback sockets is the existing relay data path
(`open_bind_session` / `open_connect_relay`), already authorized per Endpoint
(Endpoint Token + PoP).

### 3.2 New crate `isekai-p2p`

A `msquic`-only integration crate — it always needs the relay legs, so unlike
`isekai-agent` it has no msquic-free build. It re-exports nothing new from the
transport layer; it adds two orchestration facades plus a shared config.

```
rust/isekai-p2p/
├── Cargo.toml        # deps: isekai-agent (features=["msquic"]), anyhow, tokio,
│                     #       tracing, thiserror; workspace edition
└── src/
    ├── lib.rs
    ├── config.rs     # ProxyConfig, IdentityConfig, endpoint-key load/persist
    ├── listener.rs   # ListenerSession  (target side)
    └── initiator.rs  # InitiatorSession (initiator side)
```

**Shared setup (`config.rs`).**

```rust
/// How to reach the two services and which Endpoint key to use.
pub struct P2pConfig {
    pub identity_url: String,      // https://identity...:8443
    pub identity_http3: bool,      // pick the h3 transport
    pub proxy_url: String,         // https://proxy...:8443
    pub auth0_token: String,       // for the Identity API only
    pub protocol: String,          // e.g. "isekai-validator-v1"
    pub key: EndpointKey,          // load_or_generate below
}

/// Load a PKCS#8 PEM key, or generate + persist one (0600) on first use.
pub fn load_or_generate_key(path: &Path) -> anyhow::Result<EndpointKey>;

/// register (if needed) → issue Endpoint Token. Wraps IdentityClient over the
/// selected transport (mirrors `main.rs::token`).
async fn issue_endpoint_token(cfg: &P2pConfig) -> anyhow::Result<String>;
```

**`ListenerSession` (target).** Encapsulates the CLI's create-listener +
issue-capability + bind flow.

```rust
pub struct ListenerSession {
    pub listener_id: String,
    pub endpoint_id: String,          // this peer's; the client needs it? no — see note
    bind: BindSession,                // holds the relay open; drop = stop
    proxy: ProxyClient<...>,
}

impl ListenerSession {
    /// register/token → create private peer-listener → open bind session that
    /// forwards inbound relay UDP to `forward_to` (the local video listener).
    pub async fn start(cfg: &P2pConfig, forward_to: SocketAddr)
        -> anyhow::Result<Self>;

    /// Mint a capability for `allowed_endpoint` (the client's Endpoint ID).
    /// Returns the opaque token to hand out of band.
    pub async fn issue_capability(&self, allowed_endpoint: &str)
        -> anyhow::Result<String>;

    pub async fn close(self);
}
```

**`InitiatorSession` (initiator).** Encapsulates the CLI's `connect` +
open-connect-relay flow.

```rust
pub struct InitiatorSession {
    /// The local UDP address the app dials its video QUIC at.
    pub local_addr: SocketAddr,
    pub connection_id: String,
    relay: ConnectRelay,              // holds the leg open; drop = stop
}

impl InitiatorSession {
    /// register/token → peer-connect(capability, listener_id) →
    /// open connect relay leg. `local_bind` defaults to 127.0.0.1:0.
    pub async fn connect(
        cfg: &P2pConfig,
        capability: &str,
        listener_id: &str,
        local_bind: SocketAddr,
    ) -> anyhow::Result<Self>;

    pub async fn close(self);
}
```

These are thin: each is the exact call sequence already in `main.rs`, moved
behind a struct and returning the session guard instead of blocking on Ctrl-C.
Errors surface as `anyhow::Error` (the apps only need to display them).

### 3.3 What moves out of `ISEKAI-agent/main.rs`

`main.rs` shrinks to argument parsing that builds a `P2pConfig` and calls the
same session facades. Concretely:

- `token` → `config::issue_endpoint_token`.
- the `Connect` arm's control-plane call + `open_connect_relay` →
  `InitiatorSession::connect`.
- `run_bind` (+ the separate `create-listener` / `issue-capability` subcommands)
  → `ListenerSession::start` / `issue_capability`.

The low-level modules (`identity`, `proxy`, `bind`, `transport`, `https`,
`endpoint`, `pop`) **stay in `isekai-agent`** and keep their current API;
`isekai-p2p` builds on top. This keeps the split clean: `isekai-agent` =
protocol primitives, `isekai-p2p` = orchestration.

### 3.4 Camera-app integration

Both apps gain a **"Connection mode"** UI selector: `Direct (legacy)` vs `P2P`.
Direct keeps calling `isekai-link-utils` unchanged. P2P uses `isekai-p2p`.

**`camera-server` (P2P mode).** New UI fields: identity URL, proxy URL, Auth0
token, key path, and — after start — a read-only display of `listener_id` and
`endpoint_id`, plus a text box to paste the **client's** Endpoint ID and an
"Issue capability" button that shows the resulting capability to copy.

Flow, replacing `run_isekai_connection` when mode = P2P:
1. Bind the existing ALPN-`sample` QUIC listener on `127.0.0.1:0` → `S` (reuse
   the current listener/accept/uni-stream push loop verbatim).
2. `ListenerSession::start(cfg, S)`.
3. On operator action, `issue_capability(client_endpoint_id)` → display it.
4. Keep the session alive while streaming; `close()` on stop.

**`camera-client` (P2P mode).** New UI fields: identity URL, proxy URL, Auth0
token, key path, and pasted `capability` + `listener_id` (from the server
operator). Its own `endpoint_id` is shown so it can be sent to the server.

Flow, replacing the direct dial when mode = P2P:
1. `InitiatorSession::connect(cfg, capability, listener_id, 127.0.0.1:0)` →
   `local_addr = C`.
2. Dial the existing ALPN-`sample` QUIC connection at `C` instead of the public
   `IP:port` (reuse the current `accept_inbound_uni_stream` decode loop
   verbatim).

The video code (OpenCV capture, JPEG encode/decode, egui rendering, the uni
stream push/read loops) is untouched in both apps.

### 3.5 Endpoint IDs the peers must exchange

Manual exchange carries three values, all shown in the respective UIs:

| value | produced by | consumed by |
| --- | --- | --- |
| server `listener_id` | `ListenerSession::start` | client (`connect`) |
| client `endpoint_id` | client key | server (`issue_capability`) |
| `capability` | server `issue_capability` | client (`connect`) |

Order: client starts first to reveal its `endpoint_id` → operator gives it to
the server → server issues the capability + `listener_id` → operator gives both
to the client → client connects.

## 4. Auth model

- **Auth0 token** authenticates to the **Identity API only** (to obtain the
  Endpoint Token). It is not sent to the proxy data path.
- The **proxy control plane and relay data path** authenticate with the
  **Endpoint Token + PoP** (already implemented in `proxy`/`bind`). The relay
  edge is authorized per Endpoint (spec §13), so both peers must be parties of
  the connection.
- Dev TLS: `ISEKAI_INSECURE_SKIP_VERIFY` is already honored by both the HTTPS
  and msquic transports; the camera apps document it for self-signed dev certs.

## 5. Workspace changes

- Add `isekai-p2p` to `rust/Cargo.toml` `members` and as a
  `workspace.dependencies` path entry.
- `camera-server` / `camera-client` `Cargo.toml`: add `isekai-p2p` (keep
  `isekai-link-utils` for the legacy path).
- No new git dependencies, so `deny.toml` is unaffected.

## 6. Testing

Unit / integration (no cameras, no network hardware):
- `isekai-p2p`: `config::load_or_generate_key` round-trips and enforces `0600`;
  `issue_endpoint_token` against the cleartext axum mock already used by
  `ISEKAI-agent/tests/identity_flow.rs` (reuse the harness).
- `ISEKAI-agent`: existing tests must still pass after the orchestration move
  (the primitives are unchanged).
- Build both feature configurations: `cargo build -p isekai-agent`
  (msquic-free lib still compiles) and `-p isekai-p2p --features …`.
- CI parity: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`.

End-to-end on the msquic host (the setup already used for prior E2E, `minazuki`):
1. Run the proxy (`bound-udp-server --enable-p2p`) and the HTTPS Identity API
   (`DEV_CERT=1`).
2. Drive the **library** directly with a small example bin (or the two camera
   apps headless): client `InitiatorSession::connect` ↔ server
   `ListenerSession::start` + `issue_capability`, then push a few synthetic
   MJPEG frames over the ALPN-`sample` QUIC connection and assert they arrive.
3. Confirm the proxy logs `bound P2P relay loopback leg` for both legs and that
   an unauthorized Endpoint is rejected (reuse the negative check from the
   earlier data-plane test).

## 7. Rollout order

1. Land `isekai-p2p` with the two session facades + config, and refactor
   `ISEKAI-agent/main.rs` onto them (no behavior change; CLI E2E stays green).
2. Add the P2P mode to `camera-server`.
3. Add the P2P mode to `camera-client`.
4. E2E camera-to-camera over the relay.

Each step is its own PR; step 1 is independently verifiable via the existing CLI
flow, so the camera work never blocks the library refactor.

## 8. Out of scope / follow-ups

- **Automated capability exchange.** A signaling channel (or reusing the
  server's WebRTC signaling) would remove the manual paste; deferred.
- **Direct (hole-punched) upgrade.** The plan uses the relay leg only. Candidate
  exchange + relay→direct promotion (spec §14) is a later optimization.
- **Retiring the legacy `isekai-link-utils` path** once P2P is proven.
- **Key/token lifecycle UX** (token refresh, revocation surfaced in the UI).
