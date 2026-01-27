// PacketTunnelProvider.swift
// Freehold Network Extension - VPN Packet Tunnel Provider
//
// This implements a NEPacketTunnelProvider that integrates with the Freehold
// network to provide VPN-like functionality on iOS.
//
// Architecture:
// - Device sends packets to tunnel interface
// - We intercept packets and route freehold traffic through QUIC
// - Other traffic passes through normally

import NetworkExtension
import os.log

/// Freehold Packet Tunnel Provider
///
/// Provides VPN-like functionality by intercepting network traffic and
/// routing it through the Freehold relay network.
class PacketTunnelProvider: NEPacketTunnelProvider {

    // MARK: - Properties

    private let log = OSLog(subsystem: "network.freehold.tunnel", category: "PacketTunnel")
    private var isRunning = false

    /// Configuration from the VPN profile
    private var freeholdConfig: FreeholdTunnelConfiguration?

    // MARK: - Lifecycle

    override init() {
        super.init()
        os_log("PacketTunnelProvider initialized", log: log, type: .info)
    }

    // MARK: - NEPacketTunnelProvider

    /// Start the tunnel
    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        os_log("Starting tunnel", log: log, type: .info)

        // Parse configuration
        guard let config = parseConfiguration() else {
            os_log("Failed to parse configuration", log: log, type: .error)
            completionHandler(FreeholdTunnelError.invalidConfiguration)
            return
        }

        freeholdConfig = config

        // Initialize FFI
        let initResult = freehold_init()
        if initResult != 0 {
            os_log("Failed to initialize FFI", log: log, type: .error)
            completionHandler(FreeholdTunnelError.ffiInitFailed)
            return
        }

        // Setup VPN callbacks
        setupVPNCallbacks()

        // Configure tunnel network settings
        configureTunnelSettings { [weak self] error in
            if let error = error {
                os_log("Failed to configure tunnel: %{public}@", log: self?.log ?? .default, type: .error, error.localizedDescription)
                completionHandler(error)
                return
            }

            // Start Freehold service
            self?.startFreeholdService { error in
                if let error = error {
                    os_log("Failed to start Freehold: %{public}@", log: self?.log ?? .default, type: .error, error.localizedDescription)
                    completionHandler(error)
                    return
                }

                self?.isRunning = true
                self?.startPacketProcessing()
                os_log("Tunnel started successfully", log: self?.log ?? .default, type: .info)
                completionHandler(nil)
            }
        }
    }

    /// Stop the tunnel
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log("Stopping tunnel, reason: %{public}d", log: log, type: .info, reason.rawValue)

        isRunning = false

        // Stop Freehold
        freehold_vpn_stop()
        freehold_stop()

        os_log("Tunnel stopped", log: log, type: .info)
        completionHandler()
    }

    /// Handle sleep/wake events
    override func sleep(completionHandler: @escaping () -> Void) {
        os_log("Tunnel sleeping", log: log, type: .info)
        completionHandler()
    }

    override func wake() {
        os_log("Tunnel waking", log: log, type: .info)
    }

    // MARK: - Configuration

    private func parseConfiguration() -> FreeholdTunnelConfiguration? {
        // Get configuration from protocol configuration
        guard let protocolConfig = protocolConfiguration as? NETunnelProviderProtocol,
              let providerConfig = protocolConfig.providerConfiguration else {
            return nil
        }

        return FreeholdTunnelConfiguration(
            relayHost: providerConfig["relayHost"] as? String ?? "relay.freehold.network",
            relayPort: UInt16(providerConfig["relayPort"] as? Int ?? 443),
            claimPort: UInt16(providerConfig["claimPort"] as? Int ?? 8443)
        )
    }

    private func configureTunnelSettings(completionHandler: @escaping (Error?) -> Void) {
        // Configure the tunnel network interface
        let tunnelSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.0.0.1")

        // IPv4 configuration
        let ipv4Settings = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.0"])

        // Route only specific traffic through the tunnel
        // In a full implementation, you'd route freehold service traffic here
        ipv4Settings.includedRoutes = [NEIPv4Route.default()]
        ipv4Settings.excludedRoutes = [
            // Exclude local network
            NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.0.0.0"),
            NEIPv4Route(destinationAddress: "172.16.0.0", subnetMask: "255.240.0.0"),
            NEIPv4Route(destinationAddress: "192.168.0.0", subnetMask: "255.255.0.0"),
        ]

        tunnelSettings.ipv4Settings = ipv4Settings

        // DNS settings
        let dnsSettings = NEDNSSettings(servers: ["8.8.8.8", "8.8.4.4"])
        tunnelSettings.dnsSettings = dnsSettings

        // MTU
        tunnelSettings.mtu = 1400

        setTunnelNetworkSettings(tunnelSettings, completionHandler: completionHandler)
    }

    // MARK: - Freehold Integration

    private func setupVPNCallbacks() {
        // Setup callback for packets that need to be written to the tunnel
        let callback: PacketCallback = { data, len, context in
            guard let data = data, len > 0 else { return }

            // Get self reference from context
            guard let provider = Unmanaged<PacketTunnelProvider>.fromOpaque(context!).takeUnretainedValue() as PacketTunnelProvider? else {
                return
            }

            // Write packet to tunnel
            let packetData = Data(bytes: data, count: len)
            provider.packetFlow.writePackets([packetData], withProtocols: [NSNumber(value: AF_INET)])
        }

        // Pass self as context
        let contextPtr = Unmanaged.passUnretained(self).toOpaque()
        freehold_vpn_init(callback, contextPtr)
    }

    private func startFreeholdService(completionHandler: @escaping (Error?) -> Void) {
        guard let config = freeholdConfig else {
            completionHandler(FreeholdTunnelError.invalidConfiguration)
            return
        }

        // Start the Freehold service
        let result = config.relayHost.withCString { relayHostPtr in
            "127.0.0.1".withCString { backendHostPtr in
                "localhost".withCString { domainPtr in
                    var ffiConfig = FreeholdConfig(
                        relay_host: relayHostPtr,
                        relay_port: config.relayPort,
                        claim_port: config.claimPort,
                        h3_bind_port: 4433,
                        backend_host: backendHostPtr,
                        backend_port: 8080,
                        domain: domainPtr,
                        auto_discover: true
                    )
                    return freehold_start(&ffiConfig)
                }
            }
        }

        if result != 0 {
            completionHandler(FreeholdTunnelError.startFailed)
        } else {
            completionHandler(nil)
        }
    }

    // MARK: - Packet Processing

    private func startPacketProcessing() {
        // Read packets from the tunnel interface
        readPackets()
    }

    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self, self.isRunning else { return }

            for (index, packet) in packets.enumerated() {
                // Process each packet
                packet.withUnsafeBytes { buffer in
                    if let baseAddress = buffer.baseAddress {
                        freehold_vpn_process_packet(
                            baseAddress.assumingMemoryBound(to: UInt8.self),
                            buffer.count
                        )
                    }
                }
            }

            // Continue reading
            self.readPackets()
        }
    }
}

// MARK: - Configuration

struct FreeholdTunnelConfiguration {
    let relayHost: String
    let relayPort: UInt16
    let claimPort: UInt16
}

// MARK: - Errors

enum FreeholdTunnelError: Error, LocalizedError {
    case invalidConfiguration
    case ffiInitFailed
    case startFailed
    case tunnelSetupFailed

    var errorDescription: String? {
        switch self {
        case .invalidConfiguration:
            return "Invalid tunnel configuration"
        case .ffiInitFailed:
            return "Failed to initialize Freehold FFI"
        case .startFailed:
            return "Failed to start Freehold service"
        case .tunnelSetupFailed:
            return "Failed to setup tunnel interface"
        }
    }
}
