import SwiftUI

/// The whole Phase 2 skeleton: the four values that have to be exchanged with
/// the camera server by hand, a Connect button, and the stream.
struct ContentView: View {
    @StateObject private var model = ViewerModel()
    @State private var signInError: String?

    var body: some View {
        NavigationStack {
            Form {
                streamSection
                connectionSection
                identitySection
                serverSection
                authSection
                manualTokenSection
                developmentSection
            }
            .navigationTitle("ISEKAI Viewer")
        }
        .task { model.prepare() }
    }

    private var streamSection: some View {
        Section("Stream") {
            ZStack {
                Color.black
                if let frame = model.frame {
                    Image(uiImage: frame)
                        .resizable()
                        .scaledToFit()
                } else {
                    Text("No video")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .aspectRatio(4.0 / 3.0, contentMode: .fit)
            .frame(maxWidth: .infinity)
            .listRowInsets(EdgeInsets())

            LabeledContent("Frames", value: "\(model.frameCount)")
            if let rtt = model.rttMs {
                LabeledContent("RTT", value: String(format: "%.0f ms", rtt))
            }
            if let paths = model.paths {
                PathRow(
                    label: "Isekai Link",
                    path: paths.relay,
                    active: paths.onRelay
                )
                PathRow(
                    label: "Direct",
                    path: paths.direct,
                    active: !paths.onRelay
                )
                Button(paths.onRelay ? "Switch to direct path" : "Switch to Isekai Link") {
                    model.migrate()
                }
                .disabled(!paths.canMigrate)
            }
        }
    }

    // A title string and a footer cannot be combined in one Section
    // initialiser, so the sections with footers spell their header out.
    private var connectionSection: some View {
        Section {
            LabeledContent("Status", value: model.statusText)
            if !model.statusDetail.isEmpty {
                Text(model.statusDetail)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            if !model.connectionID.isEmpty {
                CopyableValue(label: "Connection ID", value: model.connectionID)
            }
            if let error = model.errorMessage {
                Text(error)
                    .font(.footnote)
                    .foregroundStyle(.red)
            }

            if model.isConnected {
                Button("Disconnect", role: .destructive) { model.disconnect() }
            } else {
                Button("Connect") { model.connect() }
                    .disabled(!model.canConnect)
            }
        } header: {
            Text("Connection")
        } footer: {
            Text("Hand the Connection ID to the camera server so it can bind its relay leg.")
        }
    }

    private var identitySection: some View {
        Section {
            CopyableValue(label: "Endpoint ID", value: model.endpointID)
            Button("Reset Endpoint key", role: .destructive) { model.resetEndpointKey() }
                .disabled(model.isConnected)
        } header: {
            Text("This device")
        } footer: {
            Text("Give the Endpoint ID to the camera server; it issues a capability for it.")
        }
    }

    private var serverSection: some View {
        Section("Camera server") {
            LabeledField("Capability", text: $model.settings.capability)
            LabeledField("Listener ID", text: $model.settings.listenerID)
            LabeledField("Protocol", text: $model.settings.protocolName)
            LabeledField("Identity URL", text: $model.settings.identityURL, keyboard: .URL)
            LabeledField("Proxy URL", text: $model.settings.proxyURL, keyboard: .URL)
            Toggle("Register Endpoint", isOn: $model.settings.register)
        }
    }

    @ViewBuilder
    private var authSection: some View {
        Section {
            if model.auth.isSignedIn {
                LabeledContent("Signed in", value: expiryText)
                Button("Sign out", role: .destructive) { model.auth.signOut() }
                    .disabled(model.isConnected)
            } else {
                Button("Sign in with Auth0") { signIn() }
                    .disabled(model.auth.isWorking)
            }
            if let error = signInError {
                Text(error)
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        } header: {
            Text("Account")
        } footer: {
            Text(model.auth.isSignedIn
                ? "The token is renewed automatically while the session lasts."
                : "Opens Auth0 in Safari. The app never sees your password.")
        }
    }

    /// A hand-pasted token, kept as a deliberate way in for when Auth0 is
    /// unreachable. Ignored once signed in.
    @ViewBuilder
    private var manualTokenSection: some View {
        if !model.auth.isSignedIn {
            Section {
                LabeledField("Token", text: $model.auth0Token, lineLimit: 1 ... 4)
            } header: {
                Text("Auth0 access token (fallback)")
            } footer: {
                Text("Only used when not signed in.")
            }
        }
    }

    private var expiryText: String {
        guard let expiresAt = model.auth.expiresAt else { return "—" }
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        return "expires \(formatter.localizedString(for: expiresAt, relativeTo: Date()))"
    }

    private func signIn() {
        signInError = nil
        Task {
            do {
                try await model.auth.signIn()
            } catch let failure as Auth0Client.Failure where failure == .cancelled {
                // The user backed out; not worth reporting.
            } catch {
                signInError = error.localizedDescription
            }
        }
    }

    private var developmentSection: some View {
        Section {
            Toggle("Skip TLS verification", isOn: $model.settings.insecureSkipVerify)
        } header: {
            Text("Development")
        } footer: {
            Text("Accepts self-signed proxy and Identity certificates. Never enable this against a real deployment.")
        }
    }
}

/// A monospaced, selectable value with a copy button — for the ids that have to
/// move between this app and the camera server by hand.
private struct CopyableValue: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text(label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(value.isEmpty ? "—" : value)
                    .font(.system(.footnote, design: .monospaced))
                    .textSelection(.enabled)
            }
            Spacer(minLength: 8)
            Button {
                UIPasteboard.general.string = value
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .disabled(value.isEmpty)
        }
    }
}

/// A labelled text field that does not fight the pasted values it receives.
private struct LabeledField: View {
    let label: String
    @Binding var text: String
    var keyboard: UIKeyboardType = .default
    var lineLimit: ClosedRange<Int> = 1 ... 1

    init(_ label: String, text: Binding<String>, keyboard: UIKeyboardType = .default, lineLimit: ClosedRange<Int> = 1 ... 1) {
        self.label = label
        self._text = text
        self.keyboard = keyboard
        self.lineLimit = lineLimit
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            TextField(label, text: $text, axis: .vertical)
                .lineLimit(lineLimit)
                .font(.system(.footnote, design: .monospaced))
                .keyboardType(keyboard)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
        }
    }
}

/// One route the video can take, marked when it is the one in use.
private struct PathRow: View {
    let label: String
    let path: PathInfo?
    let active: Bool

    var body: some View {
        LabeledContent(active ? "▶ \(label)" : label) {
            if let path {
                Text("\(path.local) → \(path.remote)")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            } else {
                Text("not available")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}
