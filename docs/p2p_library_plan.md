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
│                     #       tracing (+ argh/serde/tracing-subscriber for the bin)
└── src/
    ├── lib.rs
    ├── config.rs     # P2pConfig, load_or_generate_key, issue_endpoint_token
    ├── listener.rs   # ListenerSession  (target side)
    ├── initiator.rs  # InitiatorSession (initiator side)
    └── bin/
        └── isekai-agent.rs   # the CLI (moved here; see §3.3)
```

**Shared setup (`config.rs`).**

```rust
/// How to reach the services and which Endpoint key to use.
pub struct P2pConfig {
    pub identity_url: String,      // https://identity...:8443
    pub identity_http3: bool,      // pick the h3 transport
    pub proxy_url: String,         // https://proxy...:8443
    pub auth0_token: String,       // for the Identity API only
    pub protocol: String,          // e.g. "isekai-validator-v1"
    pub register: bool,            // register on first use of a fresh key
    pub device_name: Option<String>,
    pub token_ttl: Option<i64>,
    pub key: EndpointKey,          // load_or_generate below
}

/// Load a PKCS#8 PEM key, or generate + persist one (0600) on first use.
pub fn load_or_generate_key(path: &Path) -> anyhow::Result<EndpointKey>;

/// register (if configured) → issue Endpoint Token, over the selected transport.
pub async fn issue_endpoint_token(cfg: &P2pConfig) -> anyhow::Result<EndpointToken>;
```

**`ListenerSession` (target).** Two-phase (see §3.5): `create` the listener and
issue capabilities up front; `bind` once the initiator's `connection_id` exists.

```rust
pub struct ListenerSession {
    pub listener_id: String,
    pub endpoint_id: String,
    /* proxy client + token + key + forward_to + bind guard */
}

impl ListenerSession {
    /// issue token → create private peer-listener (forward_to = local video listener).
    pub async fn create(cfg: &P2pConfig, forward_to: SocketAddr, ttl: Option<u64>)
        -> anyhow::Result<Self>;

    /// Mint a capability for `allowed_endpoint` (the client's Endpoint ID).
    pub async fn issue_capability(&self, allowed_endpoint: &str, ttl: Option<u64>)
        -> anyhow::Result<Capability>;

    /// Open the relay bind leg for the initiator's connection id.
    pub async fn bind(&mut self, connection_id: &str) -> anyhow::Result<()>;

    pub async fn close(self);
}
```

**`InitiatorSession` (initiator).** `peer_connect` + open the relay connect leg.

```rust
pub struct InitiatorSession {
    /// The local UDP address the app dials its video QUIC at.
    pub local_addr: SocketAddr,
    pub connection: PeerConnection,   // .connection_id, relay info
    relay: ConnectRelay,              // holds the leg open; drop = stop
}

impl InitiatorSession {
    /// issue token → peer-connect(capability, listener_id) → open connect relay.
    pub async fn connect(
        cfg: &P2pConfig, capability: &str, listener_id: &str,
        candidates: &[Candidate], local_bind: SocketAddr,
    ) -> anyhow::Result<Self>;

    /// Same, but with a token the caller already has (skips the Identity call).
    /// Used by the CLI's `connect --relay`.
    pub async fn connect_with_token(
        cfg: &P2pConfig, endpoint_token: &str, capability: &str, listener_id: &str,
        candidates: &[Candidate], local_bind: SocketAddr,
    ) -> anyhow::Result<Self>;

    pub fn connection_id(&self) -> &str;
    pub async fn close(self);
}
```

These are thin: each is the call sequence the CLI already ran, moved behind a
struct and returning the session guard instead of blocking on Ctrl-C.
Errors surface as `anyhow::Error` (the apps only need to display them).

### 3.3 The CLI moves into `isekai-p2p`

The plan first envisioned the CLI staying in `isekai-agent` and depending on
`isekai-p2p`. That would be a dependency **cycle** (`isekai-agent` →
`isekai-p2p` → `isekai-agent`), which Cargo forbids. So the CLI binary moves to
`isekai-p2p` (keeping the `isekai-agent` binary name via `[[bin]]`), and
`isekai-agent` becomes a primitives-only library. This is the split the plan
intended — "the CLI depends on `isekai-p2p`" — realized without the cycle.

The CLI's argument surface is unchanged. Internally:

- `token` → `config::issue_endpoint_token`.
- `connect --relay` → `InitiatorSession::connect_with_token` (the token/key come
  from `--token` / `--key`, so no Identity round-trip).
- `connect` without `--relay`, and `create-listener` / `issue-capability` /
  `get-connection` / `report-state` / `bind`: single one-shot control-plane or
  relay calls, so they keep using the `isekai-agent` primitives directly. The
  `ListenerSession` facade (create + capability + bind in one process) doesn't
  fit these separate one-shot invocations, so it isn't used by the CLI — only by
  the camera apps.

The low-level modules (`identity`, `proxy`, `bind`, `transport`, `https`,
`endpoint`, `pop`) **stay in `isekai-agent`** and keep their current API;
`isekai-p2p` builds on top. Split: `isekai-agent` = protocol primitives,
`isekai-p2p` = orchestration + CLI.

### 3.4 Camera-app integration

Both apps gain a **"Connection mode"** UI selector: `Direct (legacy)` vs `P2P`.
Direct keeps calling `isekai-link-utils` unchanged. P2P uses `isekai-p2p`.

**`camera-server` (P2P mode).** New UI fields: identity URL, proxy URL, Auth0
token, key path, and — after start — a read-only display of `listener_id` and
`endpoint_id`, plus a text box to paste the **client's** Endpoint ID and an
"Issue capability" button that shows the resulting capability to copy.

Flow, replacing `run_isekai_connection` when mode = P2P (`ListenerSession` is
**two-phase** — see §3.5 for why):
1. Bind the existing ALPN-`sample` QUIC listener on `127.0.0.1:0` → `S` (reuse
   the current listener/accept/uni-stream push loop verbatim).
2. `ListenerSession::create(cfg, S, ttl)` → `listener_id` (displayed).
3. On operator action, `issue_capability(client_endpoint_id, ttl)` → display it.
4. When the operator pastes the client's `connection_id`,
   `session.bind(connection_id)` attaches the relay leg.
5. Keep the session alive while streaming; `close()` on stop.

**`camera-client` (P2P mode).** New UI fields: identity URL, proxy URL, Auth0
token, key path, and pasted `capability` + `listener_id` (from the server
operator). Its own `endpoint_id` and, after connecting, its `connection_id` are
shown so they can be sent to the server.

Flow, replacing the direct dial when mode = P2P:
1. `InitiatorSession::connect(cfg, capability, listener_id, &[], 127.0.0.1:0)` →
   `local_addr = C`, `connection_id` (displayed for the server).
2. Dial the existing ALPN-`sample` QUIC connection at `C` instead of the public
   `IP:port` (reuse the current `accept_inbound_uni_stream` decode loop
   verbatim).

The video code (OpenCV capture, JPEG encode/decode, egui rendering, the uni
stream push/read loops) is untouched in both apps.

### 3.5 Values the peers must exchange

The relay edge is allocated when the **initiator** connects, and the target's
bind leg must reference that same `connection_id` — so the manual exchange
carries **four** values, not three, and the target's `ListenerSession` is
two-phase (create the listener up front, bind once the `connection_id` exists):

| value | produced by | consumed by |
| --- | --- | --- |
| client `endpoint_id` | client key | server (`issue_capability`) |
| server `listener_id` | `ListenerSession::create` | client (`connect`) |
| `capability` | server `issue_capability` | client (`connect`) |
| client `connection_id` | `InitiatorSession::connect` | server (`bind`) |

Order:
1. client reveals its `endpoint_id`;
2. server `create`s the listener and `issue_capability` for that endpoint,
   revealing `listener_id` + `capability`;
3. client `connect`s with them, revealing `connection_id`;
4. server `bind`s that `connection_id`; the relay is now live.

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
