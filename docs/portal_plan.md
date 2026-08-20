# Implementation Plan: ISEKAI portal — TCP/UDP forwarding over ISEKAI link

## 1. Goal

Reach a TCP or UDP service that sits behind someone else's NAT, from a local
port, over the P2P path the camera apps already use.

```
  ┌─ portal-client ────────┐                      ┌─ portal-server ────────┐
  │ 127.0.0.1:5432         │  ISEKAI link (QUIC)  │  10.0.0.5:5432         │
  │   ← psql, curl, ssh    │ ═══════════════════▶ │    → the actual service │
  └────────────────────────┘   relay, then direct └────────────────────────┘
```

Neither side needs a reachable address, neither side opens a firewall port, and
after the connection migrates off the relay the proxy is out of the data path
entirely.

**This is the camera apps with the MJPEG swapped out.** Everything from Auth0
sign-in down to certificate pinning is already built, tested and running on
hardware; what is new is a few hundred lines of framing and one policy decision
(§4.3). The plan is mostly about *not* rebuilding what exists.

## 2. The name

**ISEKAI portal**, with crates `portal-core`, `portal-server`, `portal-client`.

It is a pun that happens to be accurate — a *port*al — and it fits the product's
world-crossing idea without being twee. It also stays out of the way of a name
already spoken for: `agent_access_spec_draft.md` uses **Gateway** for the
resource-side component of the agent access design, and this app is close enough
to that (§9) that reusing the word would make two different things share one
name.

Alternatives considered: **ISEKAI gate** (collides as above), **ISEKAI conduit**
(accurate, charmless), **ISEKAI bridge** (already means something else in
networking), **ISEKAI tunnel** (accurate, and every product in this space is
called this).

The rest of the document uses `portal-*`. Changing it is a rename.

## 3. What already exists

Almost all of it. This section is the argument for the shape of §4.

| | where | reused as-is? |
| --- | --- | --- |
| Auth0 device sign-in, token refresh | `isekai-p2p::auth0`, `config` | yes |
| Endpoint keys, Endpoint IDs, PoP | `isekai-p2p-core::endpoint`, `pop` | yes |
| Pairing, Grants, the camera list | `isekai-p2p-core::proxy`, `isekai-p2p::initiator` | yes |
| Peer Connect, relay legs, lease renewal | `isekai-p2p::{initiator,listener}` | yes |
| Direct-path candidates and migration | `isekai-p2p-core::observed`, `camera-core::video` | **extract** (§4.4) |
| Endpoint certificate by CSR | `camera-core::tls`, `isekai-link-utils::cert` | yes |
| Key attestation and pinning | `isekai-p2p-core::attestation`, `camera-core::video` | **extract** |
| The paired-Endpoint check | `camera-core::paired` | yes |
| Hostname checking | `isekai-p2p-core::hostname` | yes |
| Privacy consent | `camera-core::privacy` | **no** — see §8 |
| The mobile FFI shape | `isekai-client-ffi` | later (§7) |

What is genuinely new: a forwarding protocol (§4.1), a service catalogue
(§4.3), and two small binaries.

## 4. Design

### 4.1 The forwarding protocol

A new ALPN, `isekai-portal-v1`, on the same QUIC connection shape the video
uses. One connection per session; everything below rides inside it.

**TCP — one QUIC bidirectional stream per TCP connection.**

```
client accepts on 127.0.0.1:5432
  → opens a bidi stream
  → writes an OPEN frame: { service: "db" }
  → then raw bytes, both ways, until either side finishes
```

The mapping is the whole point and it is nearly free: a QUIC stream already has
ordered, reliable, flow-controlled bytes in both directions and an independent
FIN in each. `tokio::io::copy_bidirectional` is the body of it. A stream reset
maps to a TCP RST; a clean FIN maps to a FIN.

**UDP — QUIC datagrams, keyed by a session id.**

```
[ u32 session ][ payload ]
```

The client allocates a session id per (local source address, service); the
server keeps a UDP socket per session and forwards both ways, dropping the
session after an idle timeout (60 s, configurable).

Datagrams rather than unreliable streams because UDP's own semantics are
datagram semantics — losing one is allowed, reordering is allowed, and a
stream would add head-of-line blocking that the application does not expect.

**Two things to get right here, and they are the ones that will bite:**

- **Size.** The inner QUIC datagram rides inside the MASQUE CONNECT-UDP
  datagram, which rides inside the outer QUIC. A UDP payload that does not fit
  must be **dropped with a counter**, never fragmented — the application asked
  for a datagram service and silently splitting one is worse than losing it.
  `isekai-p2p-core::transport`'s MTU floor (#102) is what bounds this; the
  number belongs in one constant with the arithmetic written out beside it.
- **Backpressure.** Streams have flow control; datagrams have none. Each UDP
  session gets a bounded queue and drops the oldest on overflow, with a counter.
  Unbounded buffering here is how a memory leak looks in production.

### 4.2 Crates

```
portal-core      the protocol above, over a peer QUIC connection
portal-server    the side with the services (a `ListenerSession`)
portal-client    the side with the local ports (an `InitiatorSession`)
```

`portal-core` depends on `isekai-p2p` exactly as `camera-core` does. The two
core crates do not depend on each other.

### 4.3 The service catalogue — the one real decision

**The initiator must not be able to name a host and port.**

That is the obvious design — a SOCKS-shaped `OPEN { host, port }` — and it turns
`portal-server` into an open proxy into whatever network it sits on. Every
device on that LAN, every link-local metadata endpoint, every `127.0.0.1`
service the operator never meant to expose, reachable by anyone the Grant lets
in. A Grant says *these two Endpoints may talk*; it says nothing about what may
be reached, and it was never meant to.

So the server declares what exists, and the client asks for it **by name**:

```toml
# portal-server.toml
[service.db]
protocol = "tcp"
target   = "10.0.0.5:5432"

[service.dns]
protocol = "udp"
target   = "10.0.0.1:53"
```

The target never crosses the wire. An `OPEN` for a name that is not in the file
is refused, and the refusal is the same whether the name is unknown or the
protocol is wrong — there is nothing to be learned by probing.

This is the split `agent_access_spec_draft.md` §3.1 argues for, one layer down:
what is coarse (may these two Endpoints talk, over which protocol) lives in the
middle, and what is fine (which services, at which addresses) lives on the
machine that owns the resources and never leaves it.

**The client's local ports are its own business.** `portal-client` maps
`127.0.0.1:5432 → db`; nothing about that reaches the server.

### 4.4 What to extract rather than fork

`camera-core::video` is roughly 1,700 lines, and most of it is not about video:
dialling with a retry deadline across the peer's bind gap, path events,
migration, the peer-certificate callback (pin + hostname), keepalives, idle
timeouts, the registration lifecycle. `serve_frames`/`receive_frames` are the
MJPEG part and they are the small part.

Copying that into `portal-core` would fork every one of the fixes this year —
#102's MTU floor, #114's keepalives, #119's registration drain, #125's
non-retryable refusal, #139's name check — and the copy would not get the next
one.

So: **extract the connection layer first**, into `isekai-p2p` (it is peer-QUIC
plumbing, not camera plumbing) or a new `peer-quic` crate, with `camera-core`
moved onto it in the same change. Roughly:

```rust
pub struct PeerConnectionOptions { alpn, verify, pin, observed, path_events, migrate, rtt }
pub async fn dial_peer(..) -> Result<Connection>      // the retry/pin/name logic
pub fn bind_peer_listener(..) -> Result<(Registration, Listener, SocketAddr)>
```

If that extraction turns out to be more than a day, do the spike (§7 phase 0)
against a copy, then extract before phase 1 — but do not ship two copies.

**Three things phase 0 found, all of which belong in the extracted layer.** Each
cost an unexplained hang before it was understood, and each is a property of
peer QUIC rather than of video — which is exactly the argument for the layer:

1. **The `Configuration` must outlive the `Connection`.** msquic shuts a
   connection down when the configuration it was started with is dropped, and
   the symptom is not a message about configurations — it is `connection
   shutdown by local` a few milliseconds after a handshake that plainly
   succeeded. `camera-core` never meets this because its config is a local in
   the same function as the whole session; anything that *returns* a connection
   does. The extracted API has to hand both back together.
2. **The remote address is pinned, not resolved.** `set_remote_addr` before
   `start`, with the host string used only as the TLS name. `camera-core` does
   this and records why (a loopback-only name is what mobile resolvers are worst
   at); a copy that omits it waits out the idle timeout instead of connecting.
3. **Every await gets a deadline, the handshake first.** Phase 0 had deadlines on
   its reads and its drain and none on `start`, so when the handshake stalled
   none of them ever ran and the test hung with nothing to say. One unbounded
   await makes every other bound decorative.

**And one about the moving itself, from 1b.** The comments in these functions
are the reasoning, so they get extracted and substituted rather than retyped.
The one constant typed by hand in 1b went in as `from_secs(15)` where the
original says `from_secs(10)` — a path keepalive whose whole point is that it is
the only thing still crossing the relay leg once the video is direct, so halving
it would have cut viewers off a connect TTL into watching. Reading the original
back is what caught it. **1c hand-moves three more functions.**

And one for the tests rather than the layer, which took three goes to get right:
**a `Registration` dropped with any live handle blocks in `RegistrationClose`
forever.** Every one of these hangs a test binary with no message —

- a failing assertion unwinds, so teardown written after it never runs. It has
  to be in `Drop`, or it is a happy path wearing a teardown's name
- struct fields drop in declaration order, so a `Registration` declared before
  the connection goes first and blocks on it
- waiting for `wait_idle` while still holding the connection waits for something
  that cannot happen; the drain has to take ownership
- **a stream still in a local variable counts**, even one a test opened only to
  read a byte

The extracted layer should own this: a session handle whose `Drop` releases
everything, and one drain that takes it by value. Leaving it to each caller is
leaving four ways to hang.

**Phase 1a stated two of the four rules; 1c-ii owns all four.** The layer's
entry point is `isekai_p2p::peer::dial`, and what it returns is a `PeerSession`
holding the connection, the configuration it may not outlive, and the
registration both belong to — declared in that order, so dropping it releases
them in msquic's. `PeerSession::drain` takes that by value, which is the third
rule enforced rather than restated: releasing the connection is no longer
something a caller can forget to do before waiting.

`Dialed` was 1a's way of saying the first rule and is gone; a strict subset of
`PeerSession` with no users of its own was a second way to hold the pieces, and
one type that cannot be held wrong is the point.

What stays with the caller is the fourth: which of *its* tasks are holding
handles, and when to stop them. Only the caller knows. `portal-core`'s test
cancels its token in `Drop` and then drains — one call where it used to clone
the `Arc` out, drop the value, and wait on what was left.

### 4.5 Identity, and a protocol identifier

Peer Connect is gated on the Endpoint Token's `protocols` list, and the camera
apps use `isekai-validator-v1`. A new identifier — `isekai-portal-v1` — has to
be issued in tokens by the Identity API before any of this connects at all.

**This is the only external dependency in the plan**, and it is on the server
side. Worth raising early: everything else here can be built and tested against
`isekai-validator-v1` on a development proxy, but shipping needs the new one.

## 5. Security, and what comes free

| | |
| --- | --- |
| Who may connect | the Grant, from pairing (§8.9) — unchanged |
| That the peer is who the proxy says | key attestation + pinning (#122/#125) — unchanged |
| That it is the device the user meant | the paired-Endpoint check (#126) — unchanged |
| That the certificate is for the host dialled | #139 — unchanged |
| The proxy cannot read the traffic | the video key never leaves the device (#117/#121) — unchanged |
| **What may be reached behind the peer** | **new: §4.3** |

Only the last row is this app's own problem. That is the return on building on
the existing session rather than beside it.

One thing genuinely changes in kind: the camera apps carry one media stream in
one direction, and this carries arbitrary application traffic in both. A
compromised `portal-client` Endpoint reaches every service in the catalogue,
where a compromised viewer only ever saw pictures. The catalogue is therefore
not a convenience feature — it is the blast radius.

## 6. Testing

- **`portal-core`, unit** — the frame codec, the session table, the idle sweep,
  the oversize-datagram refusal, and the catalogue lookup including the "unknown
  name and wrong protocol refuse identically" property.
- **Loopback integration**, the shape of `camera-core/tests/video_loopback.rs`:
  a real QUIC connection between two halves in one process, a real TCP echo
  server behind the server half, bytes end to end. Registration shared and
  drained (the trap that hung those tests for months is documented there).
- **UDP**: an echo socket, a payload at the size limit and one over it — the
  second must be dropped and counted, not truncated.
- **Against a real proxy**, by hand, for the things no test reaches: the bind
  gap, migration to the direct path mid-transfer, and a long-lived TCP
  connection surviving it.

`iperf3` over the forward is the honest end-to-end throughput number, and worth
having before anyone asks.

## 7. Rollout

| phase | what | done when |
| --- | --- | --- |
| **0** | Spike: TCP only, one hard-coded service, no config, no UI. Proves the framing and the stream mapping | **done** — `portal-core`, loopback. Against a real proxy is phase 1, which is where the session comes from |
| **1a** | The rules: `Dialed` and `drain_registration` into `isekai_p2p::peer`; `camera-core` and the spike onto them | **done** — `Dialed` superseded by `PeerSession` in 1c-ii |
| **1b** | `video_client_config` → the layer, ALPN as a parameter | **done** — the settings and their reasoning moved verbatim; `camera-core` delegates |
| **1c-i** | `AttestedPeer`, `Unpinnable` and `install_certificate_check` → the layer | **done** — `camera-core` re-exports the names its viewers and FFI import |
| **1c-ii** | `dial_video` → the layer, with the rules from 1a enforced rather than stated: a session handle whose `Drop` releases everything, a drain that takes ownership, and the certificate check installed by the dial rather than by the caller. #141 is classified here | **done** — `peer::dial` returns a `PeerSession`; #141 classified off the transport status. Run on Windows hardware: video as before, and the switch to the direct path |
| **1c-iii** | delete `spike.rs`; portal on a real `InitiatorSession` | portal forwards over a proxy |
| **2** | The catalogue, the config file, refusals | phase 0 with a file instead of a constant |
| **3** | UDP: datagrams, session table, idle sweep, size and queue bounds | a DNS query answers over the forward |
| **4** | Direct-path migration and the RTT/path reporting the camera apps have | a transfer survives the switch |
| **5** | Packaging: a CLI that is pleasant (`portal-client --map 5432:db`), logging, `--help` that explains the catalogue | somebody else can use it from the README alone |

Mobile (FFI) is deliberately last and not scheduled: the desktop shape has to
settle first, and a phone is a strange place to terminate a database connection.

## 8. Out of scope

- **The privacy policy.** It is about video, and this app carries none. If
  `portal-*` ships to end users it needs its own consent text and its own §5 —
  what the proxy can see (that a connection happened, when, how much) is the
  same, but "the camera in your living room" is not the framing.
- **Multiple simultaneous peers** on one `portal-client`. The session model
  supports it; the CLI need not, at first.
- **Authentication of the *service*.** The forward carries whatever the service
  speaks; if that is plaintext, it is plaintext to the peer that reached it.
  Say so in the README rather than implying a tunnel makes an unauthenticated
  service safe.
- **NAT-traversal changes.** Nothing here needs any.

## 9. The relationship to the agent access draft

`agent_access_spec_draft.md` (server repo) designs a Resource Gateway: an agent
reaches a resource through a component that holds the policy and enforces it per
operation. **`portal-server` is the transport half of that**, and its catalogue
is a coarse, static ancestor of the same idea — names in the middle, addresses
and scope at the edge.

Two things follow, and both are cheap now and expensive later:

- keep the catalogue **data**, loaded at start, rather than compiled in — a
  policy channel later has something to write into
- give every forwarded connection a **correlation id** in its logs, in the shape
  §3.3 of that draft describes (`access_lease_id` / `decision_id`), even though
  nothing distributes one yet

Neither costs anything today. Both are the difference between the Gateway being
a new component and being this one, grown.

## 10. Open questions

1. **Where does the connection layer live** — `isekai-p2p`, or a new
   `peer-quic` crate? Extracting into `isekai-p2p` is less ceremony; a separate
   crate keeps `isekai-p2p` about the control plane. Lean towards `isekai-p2p`.
2. **Does the client ever choose the local port**, or does the catalogue name it
   too? Naming it server-side is tidier and wrong: the local port is the
   client's own namespace and can collide with anything already running there.
3. **One connection or several?** One QUIC connection carrying every service is
   simplest and shares congestion control. If a bulk transfer starving an
   interactive forward turns out to matter, QUIC's stream priorities are the
   answer before more connections are.
4. **`isekai-portal-v1` in the Identity API** — who, and when (§4.5).
