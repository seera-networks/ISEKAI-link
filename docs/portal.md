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

You need an **ISEKAI account**, and a browser once, on each machine. Everything
else — Endpoint keys, certificates, tokens — is generated or fetched on first
use.

### Download a release

Grab the archive for your platform from
[Releases](https://github.com/seera-networks/ISEKAI-link/releases), unpack it,
and run it from anywhere:

```sh
unzip portal-ubuntu-latest.zip
cd portal-ubuntu-latest
./portal-server --help
./portal-client --help
```

The archive carries the libraries these need — `libmsquic` above all, which
nothing installs — so it runs on a machine that has never built this. On Linux
and macOS the two names at the top level are launchers that point the loader at
the bundled `lib/`; on Windows the DLLs sit beside the executables.

### Or build it

```sh
cd rust
cargo run --release -p portal-server -- --help
cargo run --release -p portal-client -- --help
```

**`cargo run`, and not the binary it produces.** msquic is a shared library
built into `target/…/build/seera-msquic-*/out/lib` and nothing puts it on the
loader's path — `cargo run` adds it for the run, and
`./target/release/portal-server` fails at startup with

```
error while loading shared libraries: libmsquic.so.2
```

To get a binary you can move, build the same archive the release does:

```sh
cargo build --release -p portal-server -p portal-client
cd .. && scripts/bundle-apps.sh rust/target/release dist portal portal-server portal-client
```

The rest of this page writes `portal-server` and `portal-client` for whichever
of these you are using, and every command runs from wherever the key files and
`portal-server.toml` should live.

The binaries default to the public deployment (`identity.isekai.tools`,
`tokyo.link.isekai.tools`); `--identity-url` and `--proxy-url` point them
somewhere else.

---

## 0. Sign in, once per machine

```sh
portal-server --login          # on the machine with the services
portal-client --login          # on the machine with the local ports
```

```
To sign in, open:

    https://seera-networks.jp.auth0.com/activate?user_code=CVNR-SWDW

and confirm the code:  CVNR-SWDW

Waiting…
```

Open it, confirm the code, and that machine is signed in for good: the tokens
land beside the Endpoint key and **refresh themselves from then on**. No command
after this needs a token.

**Each binary has its own store**, because each is a separate Endpoint with its
own key — `portal-server-auth0.json` beside `portal-server.pem`,
`portal-client-auth0.json` beside `portal-client.pem`. So a machine running both
signs in twice, and a non-default `--key` has to be passed to `--login` as well,
since that is what the name is derived from.

**This is what lets a server be left running.** An Endpoint Token lasts minutes
and is reissued for the life of the session, and each reissue needs a current
Auth0 token — so a session started with a token that later expires stops being
able to renew, and ends. `--auth0-token` still works for scripts that already
have one, and it says so in the log; it cannot be refreshed.

The saved file is a credential in its own right — a refresh token mints access
tokens until it is revoked — so it is written owner-readable, like the key
beside it. `--auth0-tokens` puts it somewhere else.

If the sign-in is ever revoked, the next start says so and names the fix rather
than failing several minutes in:

```
Error: refresh the Auth0 access token
Caused by:
    the Auth0 session has ended, sign in again: Unknown or invalid refresh token.
```

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

## 2. Start the server

```sh
portal-server --register --config portal-server.toml
```

```
endpoint id : ep:9z8y7x…
listener id : pl_1a2b3c…
```

Leave it running. The listener id is printed for diagnostics: a client on a
grant looks the current one up for itself, and only the one-shot capability
path below needs it by hand.

`--register` is only needed the first time, when the key is new. Keep
`portal-server.pem`: a new key is a new Endpoint ID, and every grant made
against the old one stops applying.

## 3. Show a pairing code

```sh
portal-server --pair
```

```
pairing code: K7QM-3XPD
  or the URI: isekai://pair?code=K7QM-3XPD
  expires at: 2026-08-22T07:31:04Z

The peer runs: portal-client --pair K7QM-3XPD
```

Read the code to whoever should be let in. It lasts five minutes and can be
redeemed once; asking again replaces it, so an unused code is not something you
have to clean up.

**This does not start the server**, and does not need one running either. A
pairing code names a protocol and nothing else — what redeeming it makes is a
grant, and a grant's key has no listener in it — so it can be issued while a
server is already up, which is the usual case once something is installed.

So this is a second terminal, not a second server — which is what it had to be
before, and the reason for the change.

## 4. Redeem it, once

On the client machine:

```sh
portal-client --register --pair K7QM-3XPD
```

```
paired with : ep:9z8y7x…
grant       : gr_5f6a7b…

Connect with --map alone; the listener is found for you.
```

**That is the last time either side has to carry anything.** What pairing makes
is a *Grant*, and a Grant's key is `(server Endpoint, your Endpoint, protocol)`
with no listener in it — so it is reusable, it has no expiry unless one is set,
and it keeps working when the server restarts onto a new listener id. The client
asks the proxy which listener that Endpoint has now, every time it connects.

`--register` on the first run only: the key was generated here and the Identity
API has not seen it yet.

## 5. Forward a port

```sh
portal-client --map 5432:db --map udp:5353:dns
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

## Letting in something that has no screen

Pairing needs a person: one side shows eight characters, the other types them,
and there is **one live code per protocol** because that is what fits on a
screen. Three CI jobs cannot each have their own, and an agent sandbox has
nobody to read a code aloud.

A **ticket** is the same idea with those two constraints removed. It is a
256-bit secret handed over out of band, several can be outstanding at once, and
what redeeming one makes **expires on its own**.

```sh
portal-server --ticket --ticket-label ci-run-4821 --grant-ttl 3600
```

```
Hand over this one string:

  iskt1_eyJwIjoidG9reW8ubGluay5pc2VrYWkudG9vbHM6ODQ0MyIsInQiOiJ0a3QxX1FBODF…

ticket id   : tkt_AbC12345  (--revoke-ticket takes this)
expires at  : 2026-08-28T08:45:00Z
grant ttl   : 3600s

The peer runs: portal-client --redeem <that string>

It works once, it is not shown again, and it is a secret until
it is spent -- send it the way you would send a password.
```

The secret is printed **first, and before anything that could be missing from
the proxy's answer**: it is shown once and never again, so nothing optional gets
to come between you and it.

```sh
portal-client --redeem iskt1_eyJwIjoi… --map 5432:db
```

```
let in by   : ep:9z8y7x…
grant       : gr_AbC12345
expires at  : 2026-09-28T09:32:00Z
connection id: b7f0c1…
tcp 127.0.0.1:5432 -> db
```

**Redeeming and connecting are one command.** Add `--map` and the same run goes
on to forward, using the Endpoint it was just let in by — there is no reason to
start the client twice, and the second run would only have to be told the peer
the first one had this second been told. Leave `--map` off and it stops after
redeeming, which is what you want when the ticket arrives before the work does.

The same goes for `--pair`.

After that it is an ordinary grant — `--map` alone, the listener looked up each
time, restarts survived — until its expiry, at which point access ends without
anyone having to remember to take it away. **That is what a ticket is for**:
work that finishes.

### Two lifetimes, and they are different quantities

`--ticket-ttl` is how long the paper stays good; `--grant-ttl` is how long
whoever presents it may stay. A 15-minute ticket making a 1-hour grant is the
normal case, not a mistake. Both clamp to 60..=86,400 seconds, defaulting to 900
and 3,600.

**A ticket cannot make unlimited access.** That is the one thing pairing does
that this deliberately does not.

### The string carries the proxy, but does not choose it

`--redeem` takes the whole `iskt1_` string rather than the bare secret, because
a ticket by itself does not say **where** to spend it: presenting one to the
wrong proxy is refused as an unknown ticket, with nothing in the answer to
suggest the address was the problem.

What it does **not** do is send you there. Redeeming presents this Endpoint's
token, and the proof-of-possession covers the method, path and body but not the
host — so a string composed by somebody else would otherwise decide where your
credentials go. If the ticket names a proxy other than `--proxy-url`, portal
stops and tells you what to pass:

```
Error: this ticket is for osaka.link.isekai.tools:8443, but --proxy-url is
tokyo.link.isekai.tools:8443.
```

Pass that `--proxy-url` to the later commands too — **the grant lives at the
proxy you redeemed at**, and `--map` looks it up wherever `--proxy-url` points.

Put it in a link's **fragment** if you send one (`https://…/join#iskt1_…`): a
path or a query ends up in `Referer` headers and access logs. `--redeem` takes
that form too.

Treat it as a password until it is spent. Both `iskt1_` and `tkt1_` are fixed
prefixes so that secret scanners and `grep` can find one that got away. Handing
a ticket to `--pair` by mistake is refused before anything is sent, rather than
travelling to the proxy in a field meant for an eight-character code.

### Seeing where they went

```sh
portal-server --tickets
```

```
ticket      : tkt_AbC12345  redeemed by ep:4d5e6f… as gr_AbC12345 at 2026-08-28T08:32:00Z, ci-run-4821
ticket      : tkt_Dd77e210  unredeemed, expires 2026-08-28T09:15:00Z, nightly-backup
```

**This is the only record of where a ticket went.** Whoever redeems binds
themselves to it, and if the wrong party got there first this is where you see
it — and the intended one finds out because their redemption is refused.

```sh
portal-server --revoke-ticket tkt_Dd77e210
```

Tearing up an unused ticket stops it being redeemable. **It does not remove
anybody already let in by it** — that is a grant now, and `--revoke` is what
takes a grant away. Tearing up the paper does not evict the person who already
walked in.

## Letting somebody in just once

Pairing is standing access. For a guest — someone who should reach a service
today and not next week — there is a capability instead:

```sh
portal-client --whoami                     # they send you this Endpoint ID
portal-server --allow ep:4d5e6f… --capability-ttl 300
portal-client \
              --listener pl_1a2b3c… --capability cap_7g8h9i… --map 5432:db
```

**It is one-shot and lasts 300 seconds at most**, so the peer has to be at the
keyboard. That is the point of it rather than a limitation: what you are handing
over is one connection, not a way back in.

## Taking access away

```sh
portal-server --grants
```

```
grant       : gr_5f6a7b…  ep:4d5e6f…  (pairing, masa's laptop)
```

```sh
portal-server --revoke gr_5f6a7b…
```

Both answer and exit without serving anything. That is not just tidiness: a
second Peer Listener under this Endpoint is one more row for every client that
looks one up, so asking "who is in?" must not put one there.

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
| `the Auth0 session has ended, sign in again` | the saved sign-in was revoked or expired past refreshing. `--login` again |
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
