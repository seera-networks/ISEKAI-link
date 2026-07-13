# Implementation Plan: CONNECT-UDP Relay Leg for `ISEKAI-agent` (channel-masque)

## 1. Goal

`ISEKAI-agent connect` performs the P2P Connect control-plane call
(`POST /v1/peer/connect`) and prints the response, which contains a
`relay.masque_uri` of the RFC 9298 form
`https://proxy.isekai.link/.well-known/masque/udp/{host}/{port}/`. Today the
agent does **nothing** with that URI — it never opens the relay data path.

This plan adds, in the **`channel-masque`** crate, the ability to establish a
CONNECT-UDP session to a concrete `masque_uri` and bridge it to a local UDP
socket, and wires it into the `connect` command. The required behavior is:

1. Open a UDP socket.
2. `recvfrom` on that socket; **record the source address** the datagram came
   from, and send the datagram to the remote through CONNECT-UDP.
3. When a datagram arrives from the remote through CONNECT-UDP, `sendto` the
   socket using the **recorded** address.

This makes the agent a local UDP forward proxy: a co-located application sends
UDP to the agent's socket, the agent tunnels it to the peer via the MASQUE
proxy, and replies are returned to the application.

## 2. Current state

- `channel_masque::MasqueClient::start(mode, shutdown)` opens a MASQUE session
  but **hardcodes** the request line
  `CONNECT /.well-known/masque/udp/%2A/%2A/` with `connect-udp-bind: ?1`
  (`lib.rs::start_impl`). It supports two `MasqueClientMode`s:
  - `Forward(SocketAddr)` — binds a socket and `connect()`s it to a **fixed**
    address; used by `bind.rs::open_bind_session` for the listener leg.
  - `WebRTC` — sends `seera-session-create` and mapped-address capsules.
- Datagrams are `varint(context_id) || payload`; context id `0` is the
  "uncompressed" context (`from_udp_to_quic.rs::uncompressed_context_id`).
  The wildcard/WebRTC paths register per-peer contexts via COMPRESSION_ASSIGN;
  the concrete-target path uses only context `0`.
- The two data-path threads (`masque/from_udp_to_quic.rs`,
  `masque/from_quic_to_udp.rs`) key sockets by `(stream_id, remote_addr)` and,
  for `Forward`, create a socket **connected** to the fixed address. Neither
  models "record the sender and reply to it".
- `ISEKAI-agent`'s `connect` handler (`main.rs`) only calls `peer_connect` and
  prints the JSON; there is no relay leg.

### Why the existing `Forward` mode is not enough

`Forward(addr)` `connect()`s the socket to a *fixed* peer, so it can only talk
to that one address and always sends replies there. The spec requires an
**unconnected** socket that (a) accepts datagrams from a dynamically-discovered
local source and (b) sends replies back to that recorded source with `sendto`.
That is a new mode.

## 3. Design

### 3.1 Overview

Add a concrete-target CONNECT-UDP forward-proxy client. Because its request
line, header set, context handling, and socket semantics all differ from the
wildcard/WebRTC machinery, implement it as a **focused new module**
`channel-masque/src/masque/connect_udp.rs` that reuses the existing H3 request
plumbing and datagram send/receive primitives, rather than threading a third
behavior through the compression-context loops.

```
   local app ──UDP──▶ [ agent local socket L ] ──HTTP/3 CONNECT-UDP──▶ proxy ──▶ peer
   local app ◀──UDP── [ agent local socket L ] ◀──HTTP/3 CONNECT-UDP── proxy ◀── peer
                         records last src A                context id 0
```

### 3.2 Public API (channel-masque)

```rust
pub struct ConnectUdpForward { /* opaque */ }

pub struct ConnectUdpConfig {
    /// Local UDP socket to bind (e.g. 127.0.0.1:0 for an ephemeral port).
    pub local_bind: SocketAddr,
    /// Request-target path from the masque_uri, e.g.
    /// "/.well-known/masque/udp/127.0.0.1/30000/".
    pub target_path: String,
    /// Extra request headers (Authorization: Bearer <auth0>, and
    /// `seera-signaling-session-id: <relay.session_id>`).
    pub headers: Vec<(String, String)>,
}

impl ConnectUdpForward {
    /// Open the CONNECT-UDP session over `channel`, bind the local socket, and
    /// run the bidirectional bridge until `shutdown` fires. Returns the bound
    /// local address so the caller can tell the application where to send.
    pub async fn start<S>(
        channel: S,          // the H3Channel (tower Service)
        config: ConnectUdpConfig,
        shutdown: CancellationToken,
        executor: SharedExec,
    ) -> anyhow::Result<(SocketAddr, ConnectUdpForward)>;
}
```

### 3.3 Request construction

Unlike `start_impl`, build the CONNECT request from the **concrete** target:

- Method `CONNECT`, `:protocol = connect-udp`, `capsule-protocol: ?1`.
- URI path = `config.target_path` (the `masque_uri` path). The **authority**
  comes from the H3 channel's target (the proxy the agent is already connected
  to), so the `masque_uri` host is used only for its path/port; see §4.4.
- **No** `connect-udp-bind` header (this is a classic CONNECT-UDP to a fixed
  target, not a bind session) and **no** `seera-session-create`.
- Body is the request stream (for HTTP Datagrams), as today.
- Require a 2xx response before bridging.

### 3.4 Recorded-source model

Maintain a single shared "last-seen local source":

```rust
let last_src: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
```

- **Uplink** (`recvfrom` → tunnel): loop `socket.recv_from()` → store the source
  in `last_src` → send the HTTP Datagram `varint(0) || payload` to the QUIC
  side. If a payload exceeds the datagram MTU, drop it and log (UDP semantics).
- **Downlink** (tunnel → `sendto`): loop reading HTTP Datagrams from the
  response stream; for context id `0`, take the current `last_src`. If it is
  `Some(addr)`, `socket.send_to(payload, addr)`; if `None` (no uplink datagram
  seen yet), drop and log. Datagrams with a non-zero context id are ignored
  (the concrete-target path never registers one).

**Single vs. multiple local sources.** The spec records *the* source and replies
to *the* recorded destination, i.e. a last-seen model that fits one local
application flow. This is the chosen behavior. A full per-source map (multiple
concurrent local clients multiplexed onto one tunnel) is possible but explicitly
out of scope; note it as a future extension. Document that if two local clients
use the socket concurrently, replies go to whichever sent most recently.

### 3.5 Datagram encoding

Reuse `crate::encode_var_int` / `decode_var_int`. Uplink frames are
`encode_var_int(0) || payload`; downlink parsing reads the leading varint and
treats `0` as the target payload. This matches the server's context-0 handling
(`bound-udp-server` phase-5 A-side: the proxy pre-registers context 0 → target).

### 3.6 Lifecycle & shutdown

- The bridge runs two `tokio` tasks (uplink, downlink) plus the H3 request
  future, all cancelled by the `CancellationToken`.
- Dropping `ConnectUdpForward` (or cancelling the token) closes the session and
  unbinds the socket.
- Surface fatal conditions (response stream ended, H3 error) by resolving the
  session; the caller (agent) then exits or reports.

## 4. Agent integration (`ISEKAI-agent`)

### 4.1 `connect` command changes

Add options to `Connect` (main.rs):

- `--auth0-token <JWT>` — the MASQUE data path authenticates with the **Auth0**
  token, not the Endpoint Token (mirrors `bind.rs`). Required to run the relay.
- `--relay-local-addr <ip:port>` — local UDP socket to bind (default
  `127.0.0.1:0`). Presence of this flag (or always, if `--auth0-token` given)
  switches `connect` from one-shot to running the relay leg.

Flow:
1. Call `peer_connect` (as today) and obtain `relay.masque_uri` and
   `relay.session_id`.
2. Build an `H3Channel` to the proxy (reuse `transport.rs`'s msquic client
   config; the bind session in `bind.rs` is the template).
3. `ConnectUdpForward::start` with:
   - `local_bind` = `--relay-local-addr`,
   - `target_path` = path component of `masque_uri`,
   - headers: `Authorization: Bearer <auth0>` and
     `seera-signaling-session-id: <relay.session_id>` (so the proxy binds this
     initiator leg to an ephemeral loopback source for the rendezvous — see the
     server-side phase-5 `read_public_address` change).
4. Print the bound local address (JSON) so the application knows where to send,
   then run until Ctrl-C / shutdown.

### 4.2 Relationship to `bind.rs`

`bind.rs::open_bind_session` (the **listener/target** leg) already opens a
MASQUE session with `Forward` mode and the `seera-signaling-session-id` header.
The new forward proxy is the **initiator** counterpart. Both should share the
msquic client-config helper and the header-injection pattern; refactor the
shared pieces into a small helper if convenient.

### 4.3 Auth and headers

- Data-path auth: `Authorization: Bearer <auth0_token>` (Auth0), whose `sub`
  must own/party the P2P connection (server enforces).
- `seera-signaling-session-id: <relay.session_id>` correlates the leg to the
  relay edge for the rendezvous binding.

### 4.4 Proxy authority vs. `masque_uri` host

The `masque_uri` authority (`proxy.isekai.link`) may differ from the
`--proxy-url` the agent dials (e.g. `https://127.0.0.1:8443`). The H3 connection
must target the **proxy the agent already talks to** (`--proxy-url`); only the
**path** (`/.well-known/masque/udp/{host}/{port}/`) is taken from `masque_uri`.
Parse `masque_uri` and use its `path_and_query`, discarding its authority.

## 5. Testing

- **Unit (channel-masque):**
  - varint(0) framing round-trip for uplink/downlink payloads.
  - Recorded-source logic: after an uplink `recv_from` from `A`, a downlink
    datagram is `send_to` `A`; downlink before any uplink is dropped; a later
    uplink from `B` redirects replies to `B`.
- **Loopback integration (channel-masque):** stand up a minimal in-process H3
  datagram echo (or a mock `Service`) and assert a datagram sent to the local
  socket returns to its source.
- **End-to-end (with `ISEKAI-link-server`):** two agents — one
  `bind` (listener leg) and one `connect --relay-local-addr` (initiator leg) —
  relay UDP through the proxy's loopback edge; a UDP echo behind the listener
  returns traffic to the initiator's local socket. This closes the phase-5
  "two-party data-plane relay e2e" gap on the server side.

## 6. Files

```
rust/channel-masque/src/masque/connect_udp.rs   (new) concrete-target CONNECT-UDP forward proxy
rust/channel-masque/src/masque/mod.rs           (mod) pub mod connect_udp;
rust/channel-masque/src/lib.rs                  (var) re-export ConnectUdpForward/Config; share request/datagram helpers
rust/ISEKAI-agent/src/main.rs                   (var) Connect gains --auth0-token / --relay-local-addr; run the relay leg
rust/ISEKAI-agent/src/bind.rs                   (var) factor out the shared msquic-config / header helper (optional)
docs/implementation_plan.md                     (this document)
```

## 7. Open questions / decisions

- **Single recorded source (adopted)** vs. per-source map — start with the
  spec's last-seen model; revisit if multiplexing multiple local clients is
  required.
- **Idle/timeout:** whether the relay leg self-terminates after inactivity, or
  only on shutdown. Default: run until cancelled.
- **New mode vs. new module:** this plan uses a focused new module. If deeper
  reuse of the existing threads is preferred, an alternative is a
  `MasqueClientMode::ConnectUdp` variant plus a parameterized request URI, but
  the context-0 / recorded-source semantics diverge enough that a separate path
  is cleaner and lower-risk.
