import Combine
import Foundation
import UIKit

/// Drives one viewer session: settings in, frames and status out.
@MainActor
final class ViewerModel: ObservableObject {
    enum Phase: Equatable {
        case idle
        case connecting
        case connected
        case streaming
        case closed
        case failed
    }

    @Published var settings = ViewerSettings.load()
    /// Pasted by hand in Phase 2; Phase 3 of the plan replaces this with an
    /// `ASWebAuthenticationSession` login. Only consulted when no Auth0 session
    /// is signed in.
    @Published var auth0Token = ""

    /// The signed-in Auth0 session, when there is one.
    let auth: AuthStore

    @Published private(set) var phase: Phase = .idle
    @Published private(set) var statusDetail = ""
    @Published private(set) var connectionID = ""
    @Published private(set) var endpointID = ""
    @Published private(set) var frame: UIImage?
    @Published private(set) var frameCount = 0
    /// Which route the video is taking, and whether it could take another.
    @Published private(set) var paths: PathStatus?
    /// Latest round-trip time in milliseconds, sampled about once a second.
    @Published private(set) var rttMs: Double?
    /// Recent log lines from the core, newest last. Bounded — this is a
    /// diagnostic view, not a record.
    @Published private(set) var logLines: [String] = []
    @Published private(set) var errorMessage: String?

    /// The cameras this Endpoint may connect to, or nil before the proxy has
    /// been asked. "none" and "not asked yet" have to look different: someone
    /// who paired yesterday should not be shown a bare "none" and conclude the
    /// camera is gone.
    @Published private(set) var cameras: [Camera]?
    /// What the last listing or pairing said, shown under the picker.
    @Published private(set) var cameraStatus: String?
    @Published private(set) var isBusyWithCameras = false

    private var session: ViewerSession?
    private var sink: ViewerSink?
    private var lastSeq: UInt64 = 0

    private var authObserver: AnyCancellable?

    /// The store is built in the body rather than as a default argument: Swift
    /// evaluates default arguments outside the main actor, and `AuthStore` is
    /// isolated to it. Passing one in stays available for tests.
    init(auth: AuthStore? = nil) {
        let auth = auth ?? AuthStore()
        self.auth = auth
        // SwiftUI observes the object a view was handed, not the ones it owns,
        // so forward the store's changes or signing in leaves the UI stale.
        authObserver = auth.objectWillChange.sink { [weak self] _ in
            self?.objectWillChange.send()
        }
    }

    var isConnected: Bool { session != nil }

    /// A camera and a credential are enough. The capability is not required —
    /// leaving it empty is what connects on the standing grant that pairing
    /// creates, and filling it in is the older hand-carried route.
    var canConnect: Bool {
        session == nil
            && !settings.listenerID.isBlank
            && (auth.isSignedIn || !auth0Token.isBlank)
    }

    var canUseControlPlane: Bool {
        !isBusyWithCameras && (auth.isSignedIn || !auth0Token.isBlank)
    }

    // MARK: - Cameras

    /// Ask the proxy which cameras this Endpoint may connect to.
    func refreshCameras() {
        runControlPlane { config, pem, token in
            let found = try listCameras(config: config, endpointKeyPem: pem, auth0Token: token)
            return { model in
                model.cameras = found
                model.cameraStatus = found.isEmpty ? "No cameras yet — pair with one below." : nil
                // A camera that has gone is not one to still be pointing at —
                // and the clearing has to be saved, or the next launch restores
                // a selection that is not on the list.
                if !found.contains(where: { $0.listenerId == model.settings.listenerID }) {
                    model.settings.listenerID = ""
                    model.settings.save()
                }
            }
        }
    }

    /// Redeem a code the camera displayed. Accepts what was typed and what a QR
    /// scan produced; the core takes the code out of either.
    func pair(with code: String) {
        let code = code.trimmed
        guard !code.isEmpty else { return }
        runControlPlane { config, pem, token in
            // Pairing answers with the list as well, so there is no second
            // round trip to read back what it just changed.
            let paired = try pairWithCode(
                config: config,
                endpointKeyPem: pem,
                auth0Token: token,
                code: code,
                label: UIDevice.current.name
            )
            return { model in
                model.cameras = paired.cameras
                guard let camera = paired.camera else {
                    // Paired with a camera that is not running. The code is
                    // spent and the grant stands; it appears here when it is
                    // next up. Saying "failed" would invite trying the code
                    // again, and a code works once.
                    model.cameraStatus = "Paired with \(paired.ownerEndpoint), which is not "
                        + "running right now. It will appear here when it is."
                    return
                }
                model.cameraStatus = "Paired with \(camera.label)."
                // Select it, and clear any capability: a grant is what
                // authorizes this now, and a stale capability would be carried
                // instead of it.
                model.settings.listenerID = camera.listenerId
                model.settings.capability = ""
                model.settings.save()
            }
        }
    }

    func select(camera: Camera) {
        settings.listenerID = camera.listenerId
        settings.capability = ""
        settings.save()
    }

    /// One shape for both control-plane calls: gather the settings on the main
    /// actor, do the blocking work off it, apply the result back on it.
    ///
    /// The core blocks for an Identity round trip and a QUIC connection to the
    /// proxy, so none of it can run on the main thread.
    private func runControlPlane(
        _ work: @escaping (ClientConfig, String, String) throws -> (ViewerModel) -> Void
    ) {
        guard !isBusyWithCameras else { return }
        let pem: String
        do {
            pem = try EndpointKeyStore.loadOrCreate()
        } catch {
            cameraStatus = "Endpoint key: \(error.localizedDescription)"
            return
        }
        let config = clientConfig()
        isBusyWithCameras = true
        cameraStatus = nil
        // Each of these calls builds a tokio runtime and a msquic registration
        // and drops them, without the drain this workspace does at exit. The
        // numbers on either side are how anyone without a Mac can see whether
        // that comes back down — press Refresh twenty times and read the log.
        let before = ProcessStats.sample()
        Task {
            do {
                let token = try await self.currentToken()
                let apply = try await Task.detached(priority: .userInitiated) {
                    try work(config, pem, token)
                }.value
                apply(self)
            } catch {
                self.cameraStatus = error.localizedDescription
            }
            self.isBusyWithCameras = false
            self.append(log: "control plane: before \(before.summary), "
                + "after \(ProcessStats.sample().summary)")
            // Reclaiming is not instant, and "did it come back down" is the
            // whole question — a reading taken the moment the call returns
            // cannot answer it. Three seconds turned out to be too short on a
            // device: the count was still at its peak then and had dropped by
            // the time the next call started.
            Task {
                try? await Task.sleep(for: .seconds(10))
                self.append(log: "control plane: settled \(ProcessStats.sample().summary)")
            }
        }
    }

    var statusText: String {
        switch phase {
        case .idle: return "Idle"
        case .connecting: return "Connecting…"
        case .connected: return "Connected — waiting for video"
        case .streaming: return "Streaming"
        case .closed: return "Closed"
        case .failed: return "Failed"
        }
    }

    /// Load the Endpoint identity and the saved token. Safe to call repeatedly.
    func prepare() {
        do {
            endpointID = try endpointIdOf(pem: EndpointKeyStore.loadOrCreate())
        } catch {
            errorMessage = "Endpoint key: \(error.localizedDescription)"
        }
        // The hand-pasted fallback, if one was ever used. `try?` flattens the
        // throwing call's optional result, so this binds only when a token was
        // actually stored.
        if let stored = try? KeychainStore.string(for: KeychainStore.auth0TokenAccount) {
            auth0Token = stored
        }
    }

    func connect() {
        guard session == nil else { return }

        errorMessage = nil
        frame = nil
        frameCount = 0
        lastSeq = 0
        connectionID = ""
        statusDetail = ""
        phase = .connecting

        settings.save()

        let pem: String
        do {
            pem = try EndpointKeyStore.loadOrCreate()
        } catch {
            fail("Endpoint key: \(error.localizedDescription)")
            return
        }

        let config = clientConfig()
        let sink = ViewerSink(model: self)
        self.sink = sink

        // Getting a token can mean a round trip to Auth0 to renew it, so the
        // rest of connect waits on that first.
        Task {
            do {
                let token = try await self.currentToken()
                // Only a signed-in session can renew. A hand-pasted token has
                // nothing behind it, so the core keeps using it and the session
                // ends with it, as it always did.
                let provider = self.auth.isSignedIn
                    ? Auth0TokenBridge(
                        auth: self.auth,
                        initial: token,
                        expiresAt: self.auth.expiresAt
                    )
                    : nil
                self.startConnecting(
                    config: config,
                    endpointKeyPem: pem,
                    token: token,
                    provider: provider,
                    sink: sink
                )
            } catch {
                self.fail(error.localizedDescription)
            }
        }
    }

    /// The settings as the core wants them, shared by connecting and by the
    /// control-plane calls so the two cannot describe the same session
    /// differently.
    private func clientConfig() -> ClientConfig {
        ClientConfig(
            identityUrl: settings.identityURL.trimmed,
            proxyUrl: settings.proxyURL.trimmed,
            protocol: settings.protocolName.trimmed,
            capability: settings.capability.trimmed,
            listenerId: settings.listenerID.trimmed,
            register: settings.register,
            insecureSkipVerify: settings.insecureSkipVerify,
            enableMigration: settings.enableMigration,
            logFilter: settings.logFilter.trimmed
        )
    }

    /// The signed-in session's access token, renewed if it has gone stale.
    /// Falls back to a hand-pasted one so the app still works before the Auth0
    /// application's callback URL is registered.
    private func currentToken() async throws -> String {
        if auth.isSignedIn {
            return try await auth.accessToken()
        }
        let manual = auth0Token.trimmed
        guard !manual.isEmpty else { throw AuthError.notSignedIn }
        try? KeychainStore.set(manual, for: KeychainStore.auth0TokenAccount)
        return manual
    }

    private func startConnecting(
        config: ClientConfig,
        endpointKeyPem pem: String,
        token: String,
        provider: Auth0TokenProvider?,
        sink: ViewerSink
    ) {
        // The core blocks for the control-plane exchange and the relay-leg
        // setup before it returns, so this cannot run on the main thread.
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = Result {
                try startSession(
                    config: config,
                    endpointKeyPem: pem,
                    auth0Token: token,
                    auth0Provider: provider,
                    sink: sink
                )
            }
            // Bound to a constant after the blocking call: the model is not
            // retained while connecting, and the hop back to the main actor
            // captures a `let` rather than the enclosing closure's `self`.
            guard let model = self else { return }
            Task { @MainActor in
                switch result {
                case .success(let session):
                    model.attach(session)
                case .failure(let error):
                    model.fail(error.localizedDescription)
                }
            }
        }
    }

    func disconnect() {
        session?.disconnect()
        releaseSession()
        phase = .closed
    }

    /// Let go of a session that has already ended.
    ///
    /// Ending it and letting go of it are two things, and only the first was
    /// being done when a connection stopped on its own. `connect()` refuses
    /// while a session is held, and `isConnected` — which is just "a session is
    /// held" — disables the whole settings form and shows a Disconnect button.
    /// So a connection that died left the app offering to end something already
    /// over, and the way back was to press that and *then* Connect: two actions
    /// for something nobody chose.
    ///
    /// Nothing is reported to the proxy here, unlike `disconnect()`. The state
    /// that brought us here is terminal, so there is nothing left to say — and
    /// dropping the session is what stops it renewing that connection's lease,
    /// which is the part that matters.
    ///
    /// The phase and any error are left alone: what happened is still worth
    /// showing.
    private func releaseSession() {
        session = nil
        sink = nil
        paths = nil
        rttMs = nil
    }

    /// Forget the Endpoint key and mint a new identity. Any capability the
    /// camera server issued for the old Endpoint ID stops matching.
    func resetEndpointKey() {
        guard session == nil else { return }
        do {
            try EndpointKeyStore.reset()
            endpointID = try endpointIdOf(pem: EndpointKeyStore.loadOrCreate())
            errorMessage = nil
        } catch {
            errorMessage = "Endpoint key: \(error.localizedDescription)"
        }
    }

    // MARK: - Called by ViewerSink

    func apply(state: ConnectionState, detail: String) {
        switch state {
        case .connecting:
            phase = .connecting
            statusDetail = detail
        case .connected:
            phase = .connected
            statusDetail = ""
            // The core passes the connection id here — the value the camera
            // server needs in order to bind its own relay leg.
            if !detail.isEmpty { connectionID = detail }
        case .streaming:
            phase = .streaming
            statusDetail = ""
        // Both terminal, and both have to let go of the session. The camera
        // stopping, the network going, or this app being suspended past the
        // video connection's 30s idle timeout all arrive here.
        case .closed:
            phase = .closed
            statusDetail = ""
            releaseSession()
        case .failed:
            phase = .failed
            statusDetail = detail
            errorMessage = detail
            releaseSession()
        }
    }

    func apply(paths status: PathStatus) {
        paths = status
    }

    func apply(rtt ms: Double) {
        rttMs = ms
    }

    func append(log line: String) {
        logLines.append(line)
        if logLines.count > 500 {
            logLines.removeFirst(logLines.count - 500)
        }
    }

    /// The log as one blob, for sharing out of the app.
    var logText: String { logLines.joined(separator: "\n") }

    /// Switch between the Isekai Link relay and a direct path.
    ///
    /// The switch is asynchronous — `paths` updates when the connection reports
    /// it, not here — and if the new path turns out to carry nothing the core
    /// returns to the relay by itself after a few seconds.
    func migrate() {
        guard let session else { return }
        if !session.migrate() {
            errorMessage = "No direct path is available yet."
        }
    }

    func present(_ image: UIImage?, seq: UInt64) {
        guard let image else { return }
        // Frames decode concurrently and hop back independently; drop one that
        // lost the race to a newer frame.
        guard seq >= lastSeq else { return }
        lastSeq = seq
        frame = image
        frameCount += 1
        if phase == .connected { phase = .streaming }
    }

    // MARK: -

    private func attach(_ session: ViewerSession) {
        self.session = session
        connectionID = session.connectionId()
        // `onState(.connected)` may have landed already; do not walk it back.
        if phase == .connecting { phase = .connected }
    }

    private func fail(_ message: String) {
        errorMessage = message
        phase = .failed
        session = nil
        sink = nil
        paths = nil
        rttMs = nil
    }
}

/// Calls the FFI's free `connect`.
///
/// It lives out here because `ViewerModel.connect()` shadows the global of the
/// same base name for every call made from inside the type.
private func startSession(
    config: ClientConfig,
    endpointKeyPem: String,
    auth0Token: String,
    auth0Provider: Auth0TokenProvider?,
    sink: FrameSink
) throws -> ViewerSession {
    try connect(
        config: config,
        endpointKeyPem: endpointKeyPem,
        auth0Token: auth0Token,
        auth0Provider: auth0Provider,
        sink: sink
    )
}

extension String {
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
    var isBlank: Bool { trimmed.isEmpty }
}
