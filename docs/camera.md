# ISEKAI camera

Stream a camera from one machine to another, with no port opened, no firewall
rule, and no reachable address at either end.

Two desktop apps: **`camera-server`** publishes a camera, **`camera-client`**
watches it. There are mobile viewers too — [`ios/`](../ios/README.md) and
[`android/`](../android/) — and they pair exactly the way the desktop viewer
does.

The session starts on a relay and moves onto a direct peer-to-peer path when the
two networks allow one. Nothing has to be configured for that; it is what §5
below is about.

> The implementation is written down in
> [`camera-apps-spec.md`](camera-apps-spec.md). This page is how to use it.

---

## Get the apps

### Download a release

Grab the archive for your platform from
[Releases](https://github.com/seera-networks/ISEKAI-link/releases/latest),
unpack it, and run it from anywhere:

```sh
unzip camera-apps-ubuntu-latest.zip
cd camera-apps-ubuntu-latest
./camera-server        # on the machine with the camera
./camera-client        # on the machine that watches
```

The archive carries the libraries these need — OpenCV, which no current Ubuntu
packages at the version required, and `libmsquic`, which nothing installs — so
it runs on a machine that has never built this. On Linux and macOS the two names
at the top level are launchers that point the loader at the bundled `lib/`; on
Windows the DLLs sit beside the executables.

### Or build it

```sh
cd rust
cargo run --release -p camera-server
cargo run --release -p camera-client
```

**`cargo run`, and not the binary it produces** — `libmsquic` is built into
`target/…/build/seera-msquic-*/out/lib` and nothing puts it on the loader's
path. These two are also the only crates in the workspace that need OpenCV and
libclang; [`Build.md`](Build.md) is what makes that work on each platform.

Both apps read and write their files **relative to the directory you start them
in**, so run each one from wherever its keys should live.

---

## 0. The privacy policy, once

Both apps show the policy in full on first run and **nothing else can be
operated until it is accepted**. Using this requires an account and collects
personal data, which is what that is for.

Japanese and English are both included and can be switched between. The record
is kept per user, not per directory — so it is not something a different working
directory asks again. Accepting is recorded against a version: if the policy is
revised, the next start asks once more.

---

## 1. Sign in, once per machine

Both apps have an **`Auth0:`** row. Press **`Sign in`** and it shows a short
code and a link:

```
Auth0:  enter this code:  CVNR-SWDW   [open the page]
```

Open the page in any browser, confirm the code, and that machine is signed in
for good — the row changes to **`signed in — the token renews itself`**, and the
tokens land beside the Endpoint key.

**Each app has its own store**, because each is a separate Endpoint with its own
key: `camera-server-auth0.json` beside `camera-server-endpoint.pem`, and
`camera-client-auth0.json` beside `camera-client-endpoint.pem`. A machine
running both signs in twice.

**This is what lets a camera be left running.** The Endpoint Token behind every
proxy call lasts minutes and is reissued for the life of the session, and each
reissue needs a current Auth0 token. A signed-in app refreshes its own; the
`Auth0 token:` paste field — which only appears while signed out — cannot be
refreshed, so a session started with a pasted token ends when that token
expires. The field says as much.

**`Sign out`** removes the saved tokens.

---

## 2. Start the camera and show a pairing code

On the machine with the camera. The settings above the buttons default to the
public deployment:

| | |
| --- | --- |
| `Identity URL:` | `https://identity.isekai.tools:9443` |
| `Proxy URL:` | `https://tokyo.link.isekai.tools:8443` |
| `Key path:` | `camera-server-endpoint.pem` |
| `Protocol:` | `isekai-validator-v1` |

Tick **`Register endpoint on open`** the first time, when the key is new — that
is what introduces this device to the Identity API. Leave it off afterwards.

**Keep `camera-server-endpoint.pem`.** A new key is a new Endpoint ID, and every
device paired against the old one stops being able to connect.

Press **`🔌 Open`**. The app creates its Peer Listener and reports:

```
P2P: listener pl_8Ai-8hjwzfvH8xBf ready (endpoint ep:47db230e…)
Direct path offered:  not yet — bind a relay first
Endpoint ID:  ep:47db230e…
Listener ID:  pl_8Ai-8hjwzfvH8xBf
```

Then pick a camera and start capturing:

- **`Camera:`** is a dropdown of what this machine appears to have, and
  **`Scan`** rescans. The list is only built when you ask for it — finding out
  whether a device works means *opening* it, and doing that at startup would
  light the camera indicator with nobody watching.
- The list is a hint, not the limit. Whether a device can be used is decided by
  opening it, and the result is shown. An index can be typed in directly for
  something the list does not name.
- **`▶ Start`** begins capturing; **`■ Stop`** ends it. The device can be changed
  while streaming.

Capture is **640×480 at about 30 fps, JPEG**, and none of that is adjustable.

Finally, under **`Add a device`**, press **`Show a pairing code`**:

```
Add a device
Scan this, or type the code into the viewer:
    [QR]
    182E-FC9J
    expires in 289s
```

Read the code to whoever should be let in, or let them scan the QR. It counts
down on screen and can be redeemed once; asking again replaces it, so an unused
code is not something to clean up.

---

## 3. Pair the viewer, once

On the machine that watches, with the same settings — its own key path
(`camera-client-endpoint.pem`) and **`Register endpoint on connect`** ticked the
first time.

Under **`Cameras`**, type or paste the code into **`Pairing code:`** and press
**`Pair`**. A scanned `isekai://pair?code=…` URI works, and so do the eight
characters with or without the dash.

**That is the last time anything has to be carried across.** What pairing makes
is a *grant*, and a grant belongs to the camera's **Endpoint**, not to the
listener it happens to be running — so the camera appears in the list from then
on, **including after it has been restarted onto a new listener**. The viewer
asks the proxy which listener that Endpoint has now, every time it connects.

The list is fetched automatically as soon as there is a credential to ask with,
so it should not need **`Refresh`**.

---

## 4. Watch

Select the camera in the **`Cameras`** list and press **`Connect`**. Video
appears below, and the app reports the connection it made:

```
P2P: connected; give connection id to the server, then it streams: conn_Ovqv0RedtVEa
Connection ID:  conn_Ovqv0RedtVEa
```

**Up to 8 viewers** are served at once. Beyond that a viewer is reported as
waiting and is taken as soon as a slot frees up.

A viewer that goes away — closed, killed, crashed, or off the network — stops
being carried within a minute or so. Nothing has to be reported for that to
happen and there is nothing to clean up.

---

## 5. Moving onto a direct path

Once connected, the viewer shows both paths it is holding, with `▶` on the one
in use:

```
▶ Isekai Link path:  127.0.0.1:61808 -> 127.0.0.1:61806
   Direct path    :  192.168.0.12:61807 -> 192.168.0.12:61810
```

`Direct path` reads `not available` until one has been found and validated.
Once both are known, **`Migrate to P2P`** becomes pressable and moves the stream
onto the direct path; the button then offers the way back. The graph below is
the round-trip time, sampled every second, which is where the difference between
the two shows up.

**The relay is not thrown away.** Both paths stay active, and the relay leg is
kept warm by a per-path keepalive. That matters for more than falling back: the
keepalive is also how the camera knows a viewer is still there once the video
has stopped going through the relay.

Whether a direct path can be established at all is up to the two networks. When
none can be, everything above still works — over the relay.

---

## Managing who may connect

**`Allowed devices`** lists the grants this camera has issued. **`Remove`**
revokes one, and that device stops being able to connect; it does not need to be
told. **`Refresh`** re-reads the list.

**`Manual exchange (capability + connection id)`**, folded away at the bottom, is
the exchange pairing replaced: issue a one-shot capability to a named Endpoint,
and bind a connection id by hand. It is there for a proxy without grants and for
working around anything the automatic path gets wrong. Note that a connection
bound this way is **not** kept renewed, so it will expire on its own — see the
known limitations in [`camera-apps-spec.md`](camera-apps-spec.md).

---

## What each machine keeps

Written next to wherever the app was started, and `0600`.

| File | What it is |
| --- | --- |
| `camera-server-endpoint.pem` | The camera's Endpoint key. **A long-lived secret; do not copy it anywhere.** |
| `camera-server-endpoint-video-tls.pem` | The TLS key for the video connection. **Generated on the device and never sent.** |
| `camera-server-auth0.json` | The saved sign-in. A refresh token mints access tokens until it is revoked. |
| `camera-client-endpoint.pem` | The viewer's Endpoint key. |
| `camera-client-auth0.json` | The viewer's saved sign-in. |

`.gitignore` ignores `*.pem`, so none of these can be committed by accident.

**The video TLS key never leaves the device.** Only a certificate request goes
out — a public key and a name. The relay carries the video's ciphertext, so a
key the proxy generated would leave that stretch encrypted against everyone
except the party carrying it.

---

## What this does not do

- **Resolution is fixed at 640×480.** The device can be chosen; the format
  cannot.
- **The chosen camera is not remembered.** Every start goes back to index 0, so
  a machine using anything other than its built-in camera has to be told again.
- **A viewer that is running but not sending is dropped.** What is measured is
  traffic, not liveness.
- **An iOS viewer suspended in the background loses the video after 30 seconds**
  — the video connection's idle timeout, which is reached long before the
  connection's own lease. Coming back says the connection was lost and one press
  of `Connect` restores it. Returning to the foreground deliberately does *not*
  reconnect on its own: coming out of a pocket is not a reason to open a camera
  and start using the network.
- **The video certificate is only renewed by restarting.** It is valid for about
  90 days and is not replaced while running.
- **An actively malicious relay operator is not yet locked out.** The TLS key
  stays on the device, so the relay holds only ciphertext — but the proxy is
  also what derives the name and holds the ACME account, so it could obtain its
  own certificate for that name and sit in the middle. Closing that needs SPKI
  pinning backed by the peer's Endpoint key.

---

## Troubleshooting

**`Direct path offered: not yet — bind a relay first`** — expected before a
viewer has connected. The camera has nothing to advertise until a leg exists.

**`Migrate to P2P` is greyed out** — it needs both paths known. Either the direct
path has not validated yet, or these two networks cannot make one.

**The camera list says `none — pair with a camera below`** — no grant yet. Pair
with a code from the camera. If a camera was paired and has disappeared, its
listener lease may have expired: open it again on the camera machine.

**A device cannot be opened** — usually another application is holding it. The
reason is shown, and it keeps retrying twice a second, so re-plugging or quitting
the other app recovers without pressing anything.

**Sign-in stops working** — if it was revoked, signing in again is the fix; the
app says so rather than failing several minutes later.
