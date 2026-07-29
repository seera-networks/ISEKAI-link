# IsekaiCameraClient (iOS)

SwiftUI viewer for the ISEKAI camera stream — Phase 2 of
[`docs/ios_camera_client_plan.md`](../docs/ios_camera_client_plan.md). All of the
transport and P2P work happens in Rust (`rust/isekai-client-ffi`, wrapping
`camera-core`); this app is the UI, the JPEG decode, and the key storage.

## Build

Requires macOS with Xcode, plus:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
brew install xcodegen
```

Then, from this directory:

```sh
./build-rust.sh          # UniFFI bindings + IsekaiClientFFI.xcframework
xcodegen generate        # writes IsekaiCameraClient.xcodeproj
open IsekaiCameraClient.xcodeproj
```

Re-run `build-rust.sh` whenever the FFI crate's API changes, and `xcodegen
generate` whenever `project.yml` or the set of source files changes.

Only `project.yml` and `IsekaiCameraClient/App` are tracked. The `.xcodeproj`,
`Generated/`, `Frameworks/` and `Info.plist` are all build outputs.

## Something to connect to

`camera-server` needs OpenCV and a camera, which is a lot to arrange just to see
whether the viewer works. `camera-core`'s `synthetic_server` example is the
server half on its own, streaming generated JPEGs — no OpenCV, so it builds
wherever the workspace does, Windows included:

```sh
AUTH0_TOKEN=<jwt> cargo run -p camera-core --example synthetic_server
```

It defaults to the live Identity and Proxy, so the viewer and the server only
need internet — they do not have to share a LAN, which is the whole point of the
relay. Point `IDENTITY_URL`/`PROXY_URL` at a local stack instead if you have one
(and set `ISEKAI_INSECURE_SKIP_VERIFY=1` for its self-signed certificates).

It keeps its Endpoint key in `synthetic-server-endpoint.pem` and registers it
with the Identity API only when it has just generated one — a repeat
registration comes back 409. `REGISTER=1`/`0` overrides that.

It prints its `listener=` and `endpoint=` ids and then takes the two halves of
the exchange on stdin:

```text
issue <the app's Endpoint ID>      -> ok capability=…
bind <the app's Connection ID>     -> ok
```

## Automated check

`IsekaiCameraClientTests` drives the FFI directly — connect over the relay, wait
for a frame — in the simulator. That is Phase 0's "one frame received" and Phase
1's "connect → frame from a Swift test", with no device and no GUI.

Run `synthetic_server` with a control socket and the test picks everything up
from it, credentials included:

```sh
AUTH0_TOKEN=<jwt> cargo run -p camera-core --example synthetic_server -- \
  --control 127.0.0.1:57345
xcodebuild test -project ios/IsekaiCameraClient.xcodeproj -scheme IsekaiCameraClient \
  -destination 'platform=iOS Simulator,name=iPhone 15'
```

With nothing listening on that port the test skips, so a plain build needs no
setup.

CI runs it only when **both** of these secrets exist:

| Secret | What it is |
| --- | --- |
| `ISEKAI_TEST_AUTH0_TOKEN` | An Auth0 access token for the live Identity/Proxy. Expires, so it needs refreshing. |
| `ISEKAI_TEST_ENDPOINT_KEY_PEM` | The synthetic server's Endpoint key (PKCS#8 PEM), written to `rust/synthetic-server-endpoint.pem` before the run. |

The key is pinned rather than generated because the proxy issues a per-Endpoint
relay certificate through ACME and caches it by Endpoint ID: a new key each run
means a new Let's Encrypt certificate, against a limit of 50 per week for the
whole `isekai.tools` domain. Reuse a key whose certificate the proxy has already
cached — running the server once locally leaves one in
`synthetic-server-endpoint.pem` — and paste that file in whole, `BEGIN`/`END`
lines included.

Both are required, so a half-configured repository skips the test rather than
quietly spending that budget.

## Onto a device, without a Mac

The `ios-ipa` CI job packages an **unsigned** device build. Run it from the
Actions tab (`iOS client FFI` → Run workflow) on whichever branch you want, or
take the one from the last push to `main`, and download the
`IsekaiCameraClient-unsigned-ipa` artifact.

From Windows, [Sideloadly](https://sideloadly.io) or
[AltStore](https://altstore.io) re-signs that `.ipa` with an Apple ID and
installs it over USB. Apple's own iTunes and iCloud need to be installed — the
direct downloads from apple.com, not the Microsoft Store builds — for the device
drivers.

A free Apple ID is enough: this app needs no entitlement beyond the default
keychain. The profile it gets expires after **7 days**, so the app stops
launching until it is installed again; AltStore can refresh it over Wi-Fi if you
leave AltServer running. A paid Developer Program membership raises that to a
year and unlocks TestFlight, which would remove the cable entirely.

## Using it

The four values that identify a session are exchanged by hand for now (QR codes
are a Phase 5 item):

1. The app shows its **Endpoint ID** under "This device". Give it to the camera
   server and have it issue a **capability**.
2. Paste that capability and the server's **Listener ID** into "Camera server",
   and **Sign in with Auth0** under "Account".
3. **Connect**. The app then shows a **Connection ID** — give that back to the
   camera server so it can bind its relay leg, and video starts flowing.

Against a local stack (see `ISEKAI-link-server/docs/p2p_local_testing.md`) turn
on **Skip TLS verification** and point the URLs at the local Proxy and Identity.
The simulator reaches `127.0.0.1` on the host Mac directly; a device needs the
host's LAN address.

## Signing in

**Sign in with Auth0** runs the Authorization Code flow with PKCE through
`ASWebAuthenticationSession`, so credentials stay in Safari and the app only
ever sees the resulting tokens. They go to the keychain, and the access token is
renewed from the refresh token as it expires.

The browser session is ephemeral: each sign-in starts with a clean cookie jar.
That gives up single sign-on with Safari — credentials are entered every time —
in exchange for never inheriting a half-finished login transaction, which Auth0
reports as "we couldn't find your session" and which is otherwise only clearable
from iOS Settings. With a refresh token, signing in is rare.

The Auth0 side needs, once:

- a **Native** application (no client secret — that is what PKCE replaces),
  whose client id is in `Auth0Config.swift`
- `isekaiviewer://callback` in its **Allowed Callback URLs**
- **Allow Offline Access** on the `https://masque.seera-networks.com/` API, or
  no refresh token is issued and the session ends with the access token

`Auth0Config`'s `issuer` and `audience` have to match the Identity API's
`AUTH0_ISSUER` / `AUTH0_AUDIENCE` or the token it mints is rejected.

A hand-pasted token still works when not signed in — a way in while the callback
URL is being registered. Remove that field and `ViewerModel.currentToken`'s
fallback once the login is proven.

## Known gaps
- No reconnect and no `scenePhase` handling — iOS suspends UDP sockets in the
  background, so the session dies when the app leaves the foreground (Phase 4).
- The Endpoint key is a software key in the keychain. Secure Enclave needs the
  FFI to take a signer instead of a PEM (plan R7).
