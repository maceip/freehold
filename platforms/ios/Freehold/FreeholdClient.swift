// FreeholdClient.swift
// Swift wrapper for Freehold FFI
//
// Provides a clean Swift API over the C FFI bindings.

import Foundation
import Combine

// MARK: - Relay State

/// Connection state for a relay
public enum RelayState: Int, Sendable {
    case disconnected = 0
    case pending = 1
    case connected = 2

    var displayName: String {
        switch self {
        case .disconnected: return "Disconnected"
        case .pending: return "Connecting..."
        case .connected: return "Connected"
        }
    }

    var icon: String {
        switch self {
        case .disconnected: return "circle"
        case .pending: return "circle.dashed"
        case .connected: return "circle.fill"
        }
    }
}

// MARK: - Status Updates

/// Status update from the Freehold engine
public enum FreeholdStatus: Sendable {
    case relayState(address: String, state: RelayState)
    case neighborDiscovered(ip: String)
    case error(message: String)
}

// MARK: - Configuration

/// Configuration for the Freehold client
public struct FreeholdConfiguration: Sendable {
    public let relayHost: String
    public let relayPort: UInt16
    public let claimPort: UInt16
    public let h3BindPort: UInt16
    public let backendHost: String
    public let backendPort: UInt16
    public let domain: String
    public let autoDiscover: Bool

    public init(
        relayHost: String,
        relayPort: UInt16,
        claimPort: UInt16,
        h3BindPort: UInt16 = 4433,
        backendHost: String = "127.0.0.1",
        backendPort: UInt16 = 8080,
        domain: String = "localhost",
        autoDiscover: Bool = true
    ) {
        self.relayHost = relayHost
        self.relayPort = relayPort
        self.claimPort = claimPort
        self.h3BindPort = h3BindPort
        self.backendHost = backendHost
        self.backendPort = backendPort
        self.domain = domain
        self.autoDiscover = autoDiscover
    }
}

// MARK: - Freehold Client

/// Main Freehold client interface
@MainActor
public final class FreeholdClient: ObservableObject {
    // MARK: Published State

    @Published public private(set) var isRunning: Bool = false
    @Published public private(set) var currentState: RelayState = .disconnected
    @Published public private(set) var relayAddress: String = ""
    @Published public private(set) var discoveredNeighbors: [String] = []
    @Published public private(set) var lastError: String?

    // MARK: Private

    private var statusPollTimer: Timer?
    private var configuration: FreeholdConfiguration?

    // MARK: Singleton

    public static let shared = FreeholdClient()

    private init() {
        // Initialize FFI layer
        let result = freehold_init()
        if result != 0 {
            print("Warning: Failed to initialize Freehold FFI")
        }
    }

    deinit {
        stop()
    }

    // MARK: Public Methods

    /// Start the Freehold service with the given configuration
    public func start(with configuration: FreeholdConfiguration) throws {
        guard !isRunning else { return }

        self.configuration = configuration

        // Create C config struct
        let result = configuration.relayHost.withCString { relayHostPtr in
            configuration.backendHost.withCString { backendHostPtr in
                configuration.domain.withCString { domainPtr in
                    var config = FreeholdConfig(
                        relay_host: relayHostPtr,
                        relay_port: configuration.relayPort,
                        claim_port: configuration.claimPort,
                        h3_bind_port: configuration.h3BindPort,
                        backend_host: backendHostPtr,
                        backend_port: configuration.backendPort,
                        domain: domainPtr,
                        auto_discover: configuration.autoDiscover
                    )
                    return freehold_start(&config)
                }
            }
        }

        if result != 0 {
            throw FreeholdError.startFailed
        }

        isRunning = true
        currentState = .pending
        relayAddress = "\(configuration.relayHost):\(configuration.relayPort)"

        // Start polling for status updates
        startStatusPolling()
    }

    /// Stop the Freehold service
    public func stop() {
        guard isRunning else { return }

        stopStatusPolling()

        let result = freehold_stop()
        if result != 0 {
            print("Warning: Failed to stop Freehold cleanly")
        }

        isRunning = false
        currentState = .disconnected
    }

    /// Get the library version
    public var version: String {
        guard let versionPtr = freehold_version() else {
            return "unknown"
        }
        return String(cString: versionPtr)
    }

    // MARK: Private Methods

    private func startStatusPolling() {
        statusPollTimer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.pollStatus()
            }
        }
    }

    private func stopStatusPolling() {
        statusPollTimer?.invalidate()
        statusPollTimer = nil
    }

    private func pollStatus() {
        while let updatePtr = freehold_poll_status() {
            defer { freehold_free_status_update(updatePtr) }

            let update = updatePtr.pointee

            switch Int(update.update_type.rawValue) {
            case Int(FREEHOLD_STATUS_TYPE_RELAY_STATE.rawValue):
                if let addrPtr = update.relay_addr {
                    relayAddress = String(cString: addrPtr)
                }
                if let state = RelayState(rawValue: Int(update.relay_state.rawValue)) {
                    currentState = state
                }

            case Int(FREEHOLD_STATUS_TYPE_NEIGHBOR_DISCOVERED.rawValue):
                if let ipPtr = update.neighbor_ip {
                    let ip = String(cString: ipPtr)
                    if !discoveredNeighbors.contains(ip) {
                        discoveredNeighbors.append(ip)
                    }
                }

            case Int(FREEHOLD_STATUS_TYPE_ERROR.rawValue):
                if let msgPtr = update.error_message {
                    lastError = String(cString: msgPtr)
                }

            default:
                break
            }
        }
    }
}

// MARK: - Errors

public enum FreeholdError: Error, LocalizedError {
    case startFailed
    case notRunning
    case invalidConfiguration

    public var errorDescription: String? {
        switch self {
        case .startFailed:
            return "Failed to start Freehold service"
        case .notRunning:
            return "Freehold service is not running"
        case .invalidConfiguration:
            return "Invalid configuration"
        }
    }
}
