import IsekaiCameraClient
import XCTest

/// Proves the Rust core, msquic and UniFFI actually carry a frame *on iOS* —
/// the completion criterion for Phase 0 ("one frame received" on the simulator)
/// and Phase 1 ("connect → frame from a Swift test") of the plan. No device and
/// no GUI involved.
///
/// The peer is `camera-core`'s `synthetic_server --control 127.0.0.1:57345`
/// running on the host; the simulator reaches the host's loopback directly. Everything
/// the test needs — endpoints, credentials, listener id — comes back from
/// `hello`, so there is nothing to configure but the port. Without a server
/// listening the test skips, which keeps the suite green for anyone who just
/// wants to build the app.
final class ViewerConnectTests: XCTestCase {
    private static let controlPort: UInt16 = 57345

    func testReceivesAFrameOverTheRelay() throws {
        let control: ControlClient
        do {
            control = try ControlClient(port: Self.controlPort)
        } catch {
            throw XCTSkip("no synthetic_server on 127.0.0.1:\(Self.controlPort) — \(error)")
        }
        addTeardownBlock { control.close() }

        let hello = try control.request("hello")
        let peer = try control.fields(of: hello)

        // A fresh key per run: the capability the peer issues is bound to this
        // Endpoint ID, and reusing one across runs would hide a mismatch.
        let pem = try generateEndpointKeyPem()
        let endpointID = try endpointIdOf(pem: pem)
        let capability = try control.field("capability", of: control.request("issue \(endpointID)"))

        let config = ClientConfig(
            identityUrl: try XCTUnwrap(peer["identity"], "hello: \(hello)"),
            proxyUrl: try XCTUnwrap(peer["proxy"], "hello: \(hello)"),
            protocol: try XCTUnwrap(peer["protocol"], "hello: \(hello)"),
            capability: capability,
            listenerId: try XCTUnwrap(peer["listener"], "hello: \(hello)"),
            expectedEndpoint: "",
            register: true,
            // Follow whatever the peer is talking to: a local stack needs this,
            // the live deployment must not have it.
            insecureSkipVerify: peer["insecure"] == "1",
            // Both peers run on the CI host, so a direct path is between
            // loopback-adjacent addresses and proves nothing the relay does
            // not. Keep the test on the relay it is there to exercise.
            enableMigration: false,
            logFilter: ""
        )

        let sink = RecordingSink()
        let session = try IsekaiCameraClient.connect(
            config: config,
            endpointKeyPem: pem,
            auth0Token: try XCTUnwrap(peer["token"], "hello: \(hello)"),
            // The token the harness supplies is fixed and the run is far shorter
            // than its lifetime, so there is nothing to renew from.
            auth0Provider: nil,
            sink: sink
        )
        addTeardownBlock { session.disconnect() }

        // The peer can only bind once it knows the connection id — the same
        // hand-off the operator performs by pasting it into the desktop server.
        _ = try control.fields(of: control.request("bind \(session.connectionId())"))

        // Generous: #47's video handshake is allowed a long idle timeout so it
        // can span the gap between dialling and the peer binding.
        let outcome = XCTWaiter.wait(for: [sink.firstFrame], timeout: 90)
        XCTAssertEqual(
            outcome, .completed,
            "no frame arrived. last state: \(sink.lastState)"
        )
        XCTAssertEqual(
            sink.firstFrameMagic, [0xFF, 0xD8],
            "expected a JPEG frame from synthetic_server"
        )
    }
}

/// Records the first frame and the latest state. UniFFI calls these on the
/// tokio runtime's worker threads, so everything here is lock-guarded.
private final class RecordingSink: FrameSink {
    let firstFrame = XCTestExpectation(description: "first frame from the relay")

    private let lock = NSLock()
    private var magic: [UInt8] = []
    private var state = "none"
    private var seenFrame = false
    private var paths: PathStatus?

    var lastPaths: PathStatus? {
        lock.lock()
        defer { lock.unlock() }
        return paths
    }

    var firstFrameMagic: [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        return magic
    }

    var lastState: String {
        lock.lock()
        defer { lock.unlock() }
        return state
    }

    func onFrame(jpeg: Data, seq: UInt64) {
        lock.lock()
        guard !seenFrame else {
            lock.unlock()
            return
        }
        seenFrame = true
        magic = Array(jpeg.prefix(2))
        lock.unlock()
        firstFrame.fulfill()
    }

    func onState(state: ConnectionState, detail: String) {
        lock.lock()
        self.state = detail.isEmpty ? "\(state)" : "\(state) (\(detail))"
        lock.unlock()
    }

    /// Both peers are the same host here, so whether a direct path shows up is
    /// not something this test asserts on — it only has to accept the callback.
    func onPath(status: PathStatus) {
        lock.lock()
        paths = status
        lock.unlock()
    }

    func onRtt(rttMs: Double) {}

    func onLog(line: String) {}
}
