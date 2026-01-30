// VPNManager.swift
// Manages the VPN Network Extension
//
// This class handles:
// - Loading/saving VPN configurations
// - Starting/stopping the VPN tunnel
// - Monitoring VPN status

import Foundation
import NetworkExtension
import Combine

/// Manages the Freehold VPN Network Extension
@MainActor
public final class VPNManager: ObservableObject {

    // MARK: - Published State

    @Published public private(set) var isEnabled: Bool = false
    @Published public private(set) var status: NEVPNStatus = .disconnected
    @Published public private(set) var isConfigured: Bool = false

    // MARK: - Private

    private var manager: NETunnelProviderManager?
    private var statusObserver: Any?

    // MARK: - Singleton

    public static let shared = VPNManager()

    private init() {
        loadConfiguration()
    }

    deinit {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    // MARK: - Public Methods

    /// Load existing VPN configuration
    public func loadConfiguration() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            Task { @MainActor in
                if let error = error {
                    print("Failed to load VPN config: \(error)")
                    return
                }

                // Find our tunnel provider
                self?.manager = managers?.first { manager in
                    guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol else {
                        return false
                    }
                    return proto.providerBundleIdentifier == "network.freehold.ios.tunnel"
                }

                self?.isConfigured = self?.manager != nil
                self?.updateStatus()
                self?.observeStatusChanges()
            }
        }
    }

    /// Configure or update the VPN
    public func configure(
        relayHost: String,
        relayPort: Int,
        claimPort: Int
    ) async throws {
        let manager = self.manager ?? NETunnelProviderManager()

        // Configure protocol
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "network.freehold.ios.tunnel"
        proto.serverAddress = relayHost
        proto.providerConfiguration = [
            "relayHost": relayHost,
            "relayPort": relayPort,
            "claimPort": claimPort
        ]

        manager.protocolConfiguration = proto
        manager.localizedDescription = "Freehold"
        manager.isEnabled = true

        // Save configuration
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }

        self.manager = manager
        self.isConfigured = true
        self.updateStatus()
        self.observeStatusChanges()
    }

    /// Remove VPN configuration
    public func removeConfiguration() async throws {
        guard let manager = manager else { return }

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.removeFromPreferences { error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }

        self.manager = nil
        self.isConfigured = false
        self.status = .disconnected
    }

    /// Start the VPN tunnel
    public func connect() throws {
        guard let manager = manager else {
            throw VPNError.notConfigured
        }

        do {
            try manager.connection.startVPNTunnel()
        } catch {
            throw VPNError.startFailed(error)
        }
    }

    /// Stop the VPN tunnel
    public func disconnect() {
        manager?.connection.stopVPNTunnel()
    }

    /// Toggle VPN connection
    public func toggle() throws {
        if status == .connected || status == .connecting {
            disconnect()
        } else {
            try connect()
        }
    }

    // MARK: - Private Methods

    private func updateStatus() {
        status = manager?.connection.status ?? .disconnected
        isEnabled = manager?.isEnabled ?? false
    }

    private func observeStatusChanges() {
        guard let manager = manager else { return }

        // Remove existing observer
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }

        // Observe status changes
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: manager.connection,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.updateStatus()
            }
        }
    }
}

// MARK: - Status Extensions

extension NEVPNStatus {
    var displayName: String {
        switch self {
        case .disconnected: return "Disconnected"
        case .connecting: return "Connecting..."
        case .connected: return "Connected"
        case .disconnecting: return "Disconnecting..."
        case .invalid: return "Invalid"
        case .reasserting: return "Reconnecting..."
        @unknown default: return "Unknown"
        }
    }

    var icon: String {
        switch self {
        case .disconnected: return "circle"
        case .connecting: return "circle.dashed"
        case .connected: return "checkmark.circle.fill"
        case .disconnecting: return "circle.dashed"
        case .invalid: return "xmark.circle"
        case .reasserting: return "arrow.clockwise.circle"
        @unknown default: return "questionmark.circle"
        }
    }

    var color: String {
        switch self {
        case .connected: return "green"
        case .connecting, .reasserting: return "orange"
        case .disconnected, .disconnecting: return "gray"
        case .invalid: return "red"
        @unknown default: return "gray"
        }
    }
}

// MARK: - Errors

enum VPNError: Error, LocalizedError {
    case notConfigured
    case startFailed(Error)
    case configurationFailed(Error)

    var errorDescription: String? {
        switch self {
        case .notConfigured:
            return "VPN is not configured"
        case .startFailed(let error):
            return "Failed to start VPN: \(error.localizedDescription)"
        case .configurationFailed(let error):
            return "Failed to configure VPN: \(error.localizedDescription)"
        }
    }
}
