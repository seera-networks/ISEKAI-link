import Darwin
import Foundation

/// Line-based client for `camera-core`'s `synthetic_server --control`.
///
/// Blocking POSIX sockets on purpose: the peer is on loopback, the exchange is
/// four short lines, and a test reads more clearly without an async stack in the
/// middle of it.
struct ControlClient {
    enum Failure: Error, CustomStringConvertible {
        case unreachable(String)
        case closed
        case rejected(String)
        case missingField(String, in: String)

        var description: String {
            switch self {
            case .unreachable(let detail): return "control socket unreachable: \(detail)"
            case .closed: return "control socket closed mid-reply"
            case .rejected(let reply): return "control server rejected the request: \(reply)"
            case .missingField(let name, let reply): return "no '\(name)' in reply: \(reply)"
            }
        }
    }

    private let fd: Int32

    init(host: String = "127.0.0.1", port: UInt16, timeout: TimeInterval = 30) throws {
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        guard inet_pton(AF_INET, host, &address.sin_addr) == 1 else {
            throw Failure.unreachable("not an IPv4 address: \(host)")
        }

        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw Failure.unreachable("socket(): errno \(errno)")
        }

        var limit = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &limit, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &limit, socklen_t(MemoryLayout<timeval>.size))

        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                Darwin.connect(descriptor, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connected == 0 else {
            Darwin.close(descriptor)
            throw Failure.unreachable("connect(\(host):\(port)): errno \(errno)")
        }
        fd = descriptor
    }

    func close() {
        Darwin.close(fd)
    }

    /// Send one command and return its single-line reply.
    func request(_ command: String) throws -> String {
        try writeAll(command + "\n")
        return try readReply()
    }

    /// Parse an `ok key=value …` reply. Throws on `err …`.
    func fields(of reply: String) throws -> [String: String] {
        guard reply == "ok" || reply.hasPrefix("ok ") else {
            throw Failure.rejected(reply)
        }
        var fields: [String: String] = [:]
        for token in reply.dropFirst(2).split(separator: " ") {
            guard let separator = token.firstIndex(of: "=") else { continue }
            fields[String(token[..<separator])] = String(token[token.index(after: separator)...])
        }
        return fields
    }

    /// `fields(of:)` plus a lookup, so a missing key names itself in the failure.
    func field(_ name: String, of reply: String) throws -> String {
        guard let value = try fields(of: reply)[name] else {
            throw Failure.missingField(name, in: reply)
        }
        return value
    }

    private func writeAll(_ text: String) throws {
        var bytes = Array(text.utf8)
        var offset = 0
        while offset < bytes.count {
            let written = bytes[offset...].withUnsafeBufferPointer { buffer in
                Darwin.write(fd, buffer.baseAddress, buffer.count)
            }
            guard written > 0 else { throw Failure.unreachable("write(): errno \(errno)") }
            offset += written
        }
    }

    private func readReply() throws -> String {
        var line = [UInt8]()
        var byte: UInt8 = 0
        while true {
            let count = Darwin.read(fd, &byte, 1)
            if count == 0 { throw Failure.closed }
            guard count > 0 else { throw Failure.unreachable("read(): errno \(errno)") }
            if byte == UInt8(ascii: "\n") { break }
            line.append(byte)
        }
        return String(decoding: line, as: UTF8.self)
    }
}
