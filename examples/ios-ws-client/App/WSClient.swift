import Foundation
import FreeholdWSClient   // Rust C FFI via module.modulemap

/// Swift wrapper around the Rust QUIC/H3 WebSocket client.
///
/// The Rust side handles all QUIC/HTTP3 networking (via quinn + h3).
/// This class polls for incoming messages on a timer and publishes
/// them as `@Published` properties for SwiftUI.
@MainActor
public final class WSClient: ObservableObject {

    @Published public private(set) var state: ConnectionState = .disconnected
    @Published public private(set) var messages: [String] = []
    @Published public private(set) var lastError: String?

    public enum ConnectionState: Int {
        case disconnected = 0
        case connecting   = 1
        case connected    = 2
        case error        = 3
    }

    private var pollTimer: Timer?

    public init() {
        ws_client_init()
    }

    // MARK: - Actions

    public func connect(host: String, port: UInt16) {
        messages.removeAll()
        lastError = nil
        state = .connecting

        host.withCString { hostPtr in
            let result = ws_client_connect(hostPtr, port)
            if result != 0 {
                state = .error
                lastError = "Failed to start connection"
            }
        }

        startPolling()
    }

    public func disconnect() {
        stopPolling()
        ws_client_disconnect()
        state = .disconnected
    }

    public func send(_ text: String) {
        text.withCString { ptr in
            let _ = ws_client_send(ptr)
        }
        log("-> \(text)")
    }

    // MARK: - Polling

    private func startPolling() {
        pollTimer = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.poll()
            }
        }
    }

    private func stopPolling() {
        pollTimer?.invalidate()
        pollTimer = nil
    }

    private func poll() {
        // Update state from Rust
        let rawState = ws_client_state()
        if let s = ConnectionState(rawValue: Int(rawState.rawValue)) {
            if s != state {
                state = s
            }
        }

        // Check for error
        if state == .error {
            let errPtr = ws_client_last_error()
            if let errPtr = errPtr {
                lastError = String(cString: errPtr)
                ws_client_free_string(errPtr)
            }
        }

        // Drain messages
        while let msgPtr = ws_client_poll_message() {
            if let textPtr = msgPtr.pointee.text {
                let text = String(cString: textPtr)
                log("<- \(text)")
            }
            ws_client_free_message(msgPtr)
        }
    }

    private func log(_ msg: String) {
        messages.append(msg)
        // Keep last 500
        if messages.count > 500 {
            messages = Array(messages.suffix(500))
        }
    }
}
