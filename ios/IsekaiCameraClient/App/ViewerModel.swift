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
    /// `ASWebAuthenticationSession` login.
    @Published var auth0Token = ""

    @Published private(set) var phase: Phase = .idle
    @Published private(set) var statusDetail = ""
    @Published private(set) var connectionID = ""
    @Published private(set) var endpointID = ""
    @Published private(set) var frame: UIImage?
    @Published private(set) var frameCount = 0
    @Published private(set) var errorMessage: String?

    private var session: ViewerSession?
    private var sink: ViewerSink?
    private var lastSeq: UInt64 = 0

    var isConnected: Bool { session != nil }

    var canConnect: Bool {
        session == nil
            && !settings.capability.isBlank
            && !settings.listenerID.isBlank
            && !auth0Token.isBlank
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
        // `try?` flattens the throwing call's optional result, so this binds
        // only when a token was actually stored.
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
        try? KeychainStore.set(auth0Token, for: KeychainStore.auth0TokenAccount)

        let pem: String
        do {
            pem = try EndpointKeyStore.loadOrCreate()
        } catch {
            fail("Endpoint key: \(error.localizedDescription)")
            return
        }

        let config = ClientConfig(
            identityUrl: settings.identityURL.trimmed,
            proxyUrl: settings.proxyURL.trimmed,
            protocol: settings.protocolName.trimmed,
            capability: settings.capability.trimmed,
            listenerId: settings.listenerID.trimmed,
            register: settings.register,
            insecureSkipVerify: settings.insecureSkipVerify
        )
        let token = auth0Token.trimmed
        let sink = ViewerSink(model: self)
        self.sink = sink

        // The core blocks for the control-plane exchange and the relay-leg
        // setup before it returns, so this cannot run on the main thread.
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = Result {
                try startSession(
                    config: config,
                    endpointKeyPem: pem,
                    auth0Token: token,
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
        session = nil
        sink = nil
        phase = .closed
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
        case .closed:
            phase = .closed
            statusDetail = ""
        case .failed:
            phase = .failed
            statusDetail = detail
            errorMessage = detail
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
    sink: FrameSink
) throws -> ViewerSession {
    try connect(config: config, endpointKeyPem: endpointKeyPem, auth0Token: auth0Token, sink: sink)
}

extension String {
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
    var isBlank: Bool { trimmed.isEmpty }
}
