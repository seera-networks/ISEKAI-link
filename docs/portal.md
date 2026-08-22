# ISEKAI portal

Reach a TCP or UDP service that sits behind someone else's NAT, from a local
port on your machine.

```
  ┌─ your machine ─────────┐                      ┌─ theirs ───────────────┐
  │ 127.0.0.1:5432         │  ISEKAI link (QUIC)  │  10.0.0.5:5432         │
  │   ← psql, curl, dig    │ ═══════════════════▶ │    → the actual service │
  └────────────────────────┘   relay, then direct └────────────────────────┘
```

Neither side needs a reachable address and neither opens a firewall port. The
connection starts over a relay and moves to a direct path when the two ends can
punch one, after which the relay is out of the data path.

Two programs:

| | runs where | |
| --- | --- | --- |
| `portal-server` | with the services | declares what may be reached |
| `portal-client` | with the local ports | maps a port onto a name |

---

## Before you start

You need an **Auth0 access token** for the ISEKAI deployment, on both machines.
Everything else — Endpoint keys, certificates — is generated on first use.

Build and run from the workspace:

```sh
cd rust
cargo run --release -p portal-server -- --help
cargo run --release -p portal-client -- --help
```

The rest of this page writes `portal-server` and `portal-client` for those two,
and every command runs from `rust/` — which is also where the key files and
`portal-server.toml` end up by default.

**`cargo run` rather than the built binary, and that is not laziness.** msquic
is a shared library built into `target/…/build/seera-msquic-*/out/lib`, and
nothing puts it on the loader's path: `cargo run` adds it, and
`./target/release/portal-server` fails at start with

```
error while loading shared libraries: libmsquic.so.2
```

To run one directly, tell the loader where it is:

```sh
export LD_LIBRARY_PATH="$(dirname "$(find target/release/build -name libmsquic.so.2 | head -1)")"
./target/release/portal-server --help
```

An install layout that does not need this is #167.

The binaries default to the public deployment (`identity.isekai.tools`,
`tokyo.link.isekai.tools`); `--identity-url` and `--proxy-url` point them
somewhere else.

---

## 1. Say what may be reached

On the machine with the services:

```sh
portal-server --example-config > portal-server.toml
```

Edit it. This file is the **whole** of what a peer can reach:

```toml
[service.db]
protocol = "tcp"
target   = "10.0.0.5:5432"

[service.dns]
protocol = "udp"
target   = "10.0.0.1:53"
```

A peer asks for `db`. It cannot ask for a host and port — that is the one design
decision this program is built around, because a caller that could name an
address would turn the server into an open proxy onto whatever network it sits
on: every device on that LAN, every link-local metadata endpoint, every
`127.0.0.1` service you never meant to expose.

`target` is an **address, not a hostname**. Resolving one would put a DNS answer
in charge of where forwarded traffic goes.

The file is read before anything touches the network, so a typo costs you a
message naming the service rather than a half-started server.

## 2. Start the server and show a pairing code

```sh
portal-server --auth0-token "$TOKEN" --register --pair
```

```
endpoint id : ep:9z8y7x…
listener id : pl_1a2b3c…

pairing code: K7QM-3XPD
  or the URI: isekai://pair?code=K7QM-3XPD
  expires at: 2026-08-22T07:31:04Z

The peer runs: portal-client --pair K7QM-3XPD
```

Read the code to whoever should be let in. It lasts five minutes and can be
redeemed once; asking again replaces it, so an unused code is not something you
have to clean up.

`--register` is only needed the first time, when the key is new. Keep
`portal-server.pem`: a new key is a new Endpoint ID, and every grant made
against the old one stops applying.

## 3. Redeem it, once

On the client machine:

```sh
portal-client --auth0-token "$TOKEN" --register --pair K7QM-3XPD
```

```
paired with : ep:9z8y7x…
grant       : g_5f6a7b…

Connect with --map alone; the listener is found for you.
```

**That is the last time either side has to carry anything.** What pairing makes
is a *Grant*, and a Grant's key is `(server Endpoint, your Endpoint, protocol)`
with no listener in it — so it is reusable, it has no expiry unless one is set,
and it keeps working when the server restarts onto a new listener id. The client
asks the proxy which listener that Endpoint has now, every time it connects.

`--register` on the first run only: the key was generated here and the Identity
API has not seen it yet.

## 4. Forward a port

```sh
portal-client --auth0-token "$TOKEN" --map 5432:db --map udp:5353:dns
```

```
connection id: b7f0c1…
tcp 127.0.0.1:5432 -> db
udp 127.0.0.1:5353 -> dns
```

No listener id, no capability, and the same command works tomorrow and after the
server has been restarted. Paired with more than one server, add
`--peer ep:9z8y7x…`; the client says so, and lists them, if it needs telling.

And then, from anything on that machine:

```sh
psql -h 127.0.0.1 -p 5432
dig @127.0.0.1 -p 5353 example.com
```

**Which local port stands for which service is your business** — nothing about
`--map` is sent, and the server only ever sees the name. Pick a port that is
free; `--map 15432:db` is as good as `--map 5432:db`.

The protocol prefix is not optional for UDP and cannot be guessed: the server
looks a name up *under a protocol*, so asking for `dns` over TCP is refused with
the same answer as a name that does not exist.

Forwarded ports bind to loopback. `--bind 0.0.0.0` opens them to your network,
which is a second door onto the server's services — do it deliberately.

---

## What this does not do

**It does not authenticate the service.** The forward carries whatever the
service speaks. If that is a database with no password, then anyone you pair
with has a database with no password — a tunnel makes the *transport*
private, and says nothing about what is at the end of it. Put the same
authentication on a forwarded service that you would put on an exposed one.

**UDP payloads over about 1200 bytes are dropped**, counted, and never split. A
datagram service that silently splits is worse than one that silently loses,
because the application cannot tell the difference. The limit is the peer
connection's MTU and cannot be raised.

The case to know is DNS: EDNS0 commonly advertises a 1232-byte buffer, so a
large response can exceed this — and it is dropped with no truncation bit and no
ICMP, which leaves a stub resolver waiting out a timeout rather than retrying
over TCP. Ordinary queries are well under it. A resolver configured for a
smaller buffer is fine.

**One peer at a time per client.** The session model supports more; the
command line does not, yet. `--peer` chooses which of several paired servers to
connect to, not how many at once.

---

## Letting somebody in just once

Pairing is standing access. For a guest — someone who should reach a service
today and not next week — there is a capability instead:

```sh
portal-client --whoami                     # they send you this Endpoint ID
portal-server --auth0-token "$TOKEN" --allow ep:4d5e6f… --capability-ttl 300
portal-client --auth0-token "$TOKEN" \
              --listener pl_1a2b3c… --capability cap_7g8h9i… --map 5432:db
```

**It is one-shot and lasts 300 seconds at most**, so the peer has to be at the
keyboard. That is the point of it rather than a limitation: what you are handing
over is one connection, not a way back in.

## Taking access away

```sh
portal-server --auth0-token "$TOKEN" --grants
```

```
grant       : g_5f6a7b…  ep:4d5e6f…  (pairing, masa's laptop)
```

```sh
portal-server --auth0-token "$TOKEN" --revoke g_5f6a7b…
```

A grant stands until revoked, so this is the counterpart of pairing and not an
afterthought. Grants belong to the Endpoint rather than to a listener, so they
survive restarts — which means nothing expires them by accident either.

---

## When it does not work

Both programs log to **stderr** at `info`, so the ids they print on stdout stay
copy-pasteable. `RUST_LOG=debug` gets the rest, including the per-second
connection counters and which path they are about.

| what you see | what it means |
| --- | --- |
| ``the peer does not offer `db` `` | not in the catalogue, or offered under the other protocol. The two are deliberately the same answer on the wire — the server's log says which |
| ``the peer could not reach `db` `` | it is in the catalogue and the target did not answer. The service is down, or `target` is wrong |
| the local connect succeeds and then closes at once | the same refusal, seen by an application that does not print the reason |
| `no relay leg claims this connection` | a connection arrived that no leg accounts for. It works, over the relay only |
| forwarding works but stays slow | check for `forwarding moved onto the direct path`. Without it you are on the relay, which is a round trip through someone else's machine |
| a DNS query times out and small ones work | the response is over the size limit above |
| `capability-endpoint-mismatch` | the capability was issued for a different Endpoint. Usually a second key: `--key` defaults to `portal-client.pem` in the working directory, so running from another directory makes a new Endpoint. The client says `generating a new Endpoint key` when it does |
| nothing below `error` in the log | you are on a build before this was fixed — `RUST_LOG=info` |

**`capability-endpoint-mismatch` on the capability path**: it was issued for a
different Endpoint, or it has already been used. A capability is one-shot and
lasts 300 seconds at most. On the pairing path this cannot happen.

---

## The design

`docs/portal_plan.md` is the whole of it, including the parts that were
considered and rejected. The short version:

- **`portal-core`** — the forwarding protocol over a peer QUIC connection.
  One bidirectional stream per TCP connection; QUIC datagrams keyed by a session
  id for UDP.
- **`isekai-p2p`** — the session, the relay legs, the certificates, and getting
  a connection off the relay. The camera apps use the same code.
- The service catalogue (§4.3) is the one real policy decision, and the reason
  the initiator can never name an address.
