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
