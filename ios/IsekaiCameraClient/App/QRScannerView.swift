import AVFoundation
import SwiftUI

/// The camera, looking for the QR a camera server displays.
///
/// Reports only this project's own pairing URI. Everything else in front of the
/// lens — a poster, a wifi code, someone's link — is ignored and scanning
/// continues, because handing an arbitrary string to the proxy would spend a
/// request to be told it is not a pairing code. What counts is decided by the
/// core (`pairingCodeInScan`), so the app does not carry its own idea of the
/// format.
struct QRScannerView: View {
    /// The pairing code, once one has been read. Called once; the sheet is
    /// expected to dismiss.
    let onCode: (String) -> Void
    let onCancel: () -> Void

    @State private var authorization: AVAuthorizationStatus = AVCaptureDevice
        .authorizationStatus(for: .video)

    var body: some View {
        NavigationStack {
            Group {
                switch authorization {
                case .authorized:
                    CameraPreview(onCode: onCode)
                        .ignoresSafeArea(edges: .bottom)
                        .overlay(alignment: .bottom) {
                            Text("Point this at the code the camera is showing.")
                                .font(.footnote)
                                .padding()
                                .background(.ultraThinMaterial, in: Capsule())
                                .padding(.bottom, 24)
                        }
                case .notDetermined:
                    ProgressView().task {
                        _ = await AVCaptureDevice.requestAccess(for: .video)
                        authorization = AVCaptureDevice.authorizationStatus(for: .video)
                    }
                default:
                    // Denied or restricted. Not a dead end: the code can be
                    // typed, and saying so beats a black rectangle.
                    //
                    // Spelled out rather than `ContentUnavailableView`, which
                    // wants iOS 17 and this app runs on 16.
                    VStack(spacing: 12) {
                        Image(systemName: "camera.fill")
                            .font(.largeTitle)
                            .foregroundStyle(.secondary)
                        Text("No camera access").font(.headline)
                        Text("Allow camera access in Settings to scan, or type the "
                             + "code in instead.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .padding()
                }
            }
            .navigationTitle("Scan a pairing code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: onCancel)
                }
            }
        }
    }
}

/// The capture session, as a view.
private struct CameraPreview: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerViewController {
        let controller = ScannerViewController()
        controller.onCode = onCode
        return controller
    }

    func updateUIViewController(_ controller: ScannerViewController, context: Context) {
        controller.onCode = onCode
    }
}

/// Owns the `AVCaptureSession` and its preview layer.
///
/// A view controller rather than a `UIView`: the session has to start and stop
/// with the view's appearance, or it holds the camera open behind whatever the
/// user moved on to.
final class ScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onCode: ((String) -> Void)?

    private let session = AVCaptureSession()
    private var preview: AVCaptureVideoPreviewLayer?
    /// A scan fires once. Metadata arrives every frame the code is in view, and
    /// without this the sheet would try to pair a dozen times off one code —
    /// and a code works once.
    private var handled = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        configure()
    }

    private func configure() {
        // No camera at all — the simulator. The view stays black and the
        // typed-in path is unaffected.
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input)
        else { return }
        session.addInput(input)

        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return }
        session.addOutput(output)
        // Set after adding the output: the available types are not known until
        // it belongs to a session.
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]

        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.bounds
        view.layer.addSublayer(preview)
        self.preview = preview
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        preview?.frame = view.bounds
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        handled = false
        guard !session.isRunning else { return }
        // `startRunning` blocks until the camera is configured, which is long
        // enough to be visible as a stutter if it happens on the main thread.
        DispatchQueue.global(qos: .userInitiated).async { [session] in
            session.startRunning()
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        guard session.isRunning else { return }
        DispatchQueue.global(qos: .userInitiated).async { [session] in
            session.stopRunning()
        }
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput objects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard !handled else { return }
        // Whatever else is in view is not an error and not a reason to stop:
        // keep scanning until one of ours comes along.
        for object in objects {
            guard let readable = object as? AVMetadataMachineReadableCodeObject,
                  let value = readable.stringValue,
                  let code = pairingCodeInScan(scanned: value)
            else { continue }
            handled = true
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            onCode?(code)
            return
        }
    }
}
