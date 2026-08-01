import Foundation

/// Receives the Rust core's callbacks and forwards them to `ViewerModel`.
///
/// UniFFI invokes `onFrame`/`onState` on the tokio runtime's worker threads, so
/// nothing here may touch the model — or any other main-actor state — directly.
final class ViewerSink: FrameSink {
    private weak var model: ViewerModel?
    private let decodeQueue = DispatchQueue(label: "tools.isekai.viewer.decode", qos: .userInitiated)

    private let lock = NSLock()
    private var pending: (jpeg: Data, seq: UInt64)?
    private var draining = false

    init(model: ViewerModel) {
        self.model = model
    }

    func onFrame(jpeg: Data, seq: UInt64) {
        // Keep only the newest frame. Decoding can fall behind the stream, and a
        // live viewer wants the current picture rather than a queue of stale
        // ones; this also bounds how much memory a slow device accumulates.
        lock.lock()
        pending = (jpeg, seq)
        let shouldStartDraining = !draining
        draining = true
        lock.unlock()

        guard shouldStartDraining else { return }
        decodeQueue.async { [weak self] in self?.drain() }
    }

    func onState(state: ConnectionState, detail: String) {
        Task { @MainActor [weak model] in
            model?.apply(state: state, detail: detail)
        }
    }

    func onPath(status: PathStatus) {
        Task { @MainActor [weak model] in
            model?.apply(paths: status)
        }
    }

    func onRtt(rttMs: Double) {
        Task { @MainActor [weak model] in
            model?.apply(rtt: rttMs)
        }
    }

    func onLog(line: String) {
        Task { @MainActor [weak model] in
            model?.append(log: line)
        }
    }

    private func drain() {
        while true {
            lock.lock()
            guard let frame = pending else {
                draining = false
                lock.unlock()
                return
            }
            pending = nil
            lock.unlock()

            let image = JPEGDecoder.decode(frame.jpeg)
            Task { @MainActor [weak model] in
                model?.present(image, seq: frame.seq)
            }
        }
    }
}
