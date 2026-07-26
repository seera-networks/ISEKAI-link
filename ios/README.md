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
setup. CI runs it whenever the `ISEKAI_TEST_AUTH0_TOKEN` secret is present.

## Using it

The four values that identify a session are exchanged by hand for now (QR codes
are a Phase 5 item):

1. The app shows its **Endpoint ID** under "This device". Give it to the camera
   server and have it issue a **capability**.
2. Paste that capability and the server's **Listener ID** into "Camera server",
   and an Auth0 access token into "Auth0 access token".
3. **Connect**. The app then shows a **Connection ID** — give that back to the
   camera server so it can bind its relay leg, and video starts flowing.

Against a local stack (see `ISEKAI-link-server/docs/p2p_local_testing.md`) turn
on **Skip TLS verification** and point the URLs at the local Proxy and Identity.
The simulator reaches `127.0.0.1` on the host Mac directly; a device needs the
host's LAN address.

## Known gaps

- The Auth0 token is pasted rather than obtained through a login
  (`ASWebAuthenticationSession` is Phase 3).
- No reconnect and no `scenePhase` handling — iOS suspends UDP sockets in the
  background, so the session dies when the app leaves the foreground (Phase 4).
- The Endpoint key is a software key in the keychain. Secure Enclave needs the
  FFI to take a signer instead of a PEM (plan R7).
