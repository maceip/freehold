// VPNView.swift
// VPN Configuration and Control UI

import SwiftUI
import NetworkExtension

struct VPNView: View {
    @StateObject private var vpnManager = VPNManager.shared

    @State private var relayHost = "relay.freehold.network"
    @State private var relayPort = "443"
    @State private var claimPort = "8443"
    @State private var showingError = false
    @State private var errorMessage = ""

    var body: some View {
        Form {
            // Status Section
            Section {
                HStack {
                    Label(vpnManager.status.displayName, systemImage: vpnManager.status.icon)
                        .foregroundStyle(statusColor)

                    Spacer()

                    if vpnManager.isConfigured {
                        Button(vpnManager.status == .connected ? "Disconnect" : "Connect") {
                            toggleVPN()
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(vpnManager.status == .connected ? .red : .blue)
                        .disabled(vpnManager.status == .connecting || vpnManager.status == .disconnecting)
                    }
                }
            } header: {
                Text("VPN Status")
            }

            // Configuration Section
            Section {
                TextField("Relay Host", text: $relayHost)
                    .textContentType(.URL)
                    .autocapitalization(.none)
                    .disabled(vpnManager.status == .connected)

                TextField("Relay Port", text: $relayPort)
                    .keyboardType(.numberPad)
                    .disabled(vpnManager.status == .connected)

                TextField("Claim Port", text: $claimPort)
                    .keyboardType(.numberPad)
                    .disabled(vpnManager.status == .connected)
            } header: {
                Text("Configuration")
            } footer: {
                Text("The VPN will route traffic to Freehold services through the relay network.")
            }

            // Actions Section
            Section {
                Button("Save Configuration") {
                    saveConfiguration()
                }
                .disabled(vpnManager.status == .connected)

                if vpnManager.isConfigured {
                    Button("Remove Configuration", role: .destructive) {
                        removeConfiguration()
                    }
                    .disabled(vpnManager.status == .connected)
                }
            }

            // Info Section
            Section {
                VStack(alignment: .leading, spacing: 8) {
                    InfoRow(title: "Status", value: vpnManager.status.displayName)
                    InfoRow(title: "Configured", value: vpnManager.isConfigured ? "Yes" : "No")
                    InfoRow(title: "Enabled", value: vpnManager.isEnabled ? "Yes" : "No")
                }
            } header: {
                Text("Information")
            }
        }
        .navigationTitle("VPN Settings")
        .alert("Error", isPresented: $showingError) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(errorMessage)
        }
    }

    private var statusColor: Color {
        switch vpnManager.status {
        case .connected: return .green
        case .connecting, .reasserting: return .orange
        case .disconnected, .disconnecting: return .secondary
        case .invalid: return .red
        @unknown default: return .secondary
        }
    }

    private func toggleVPN() {
        do {
            try vpnManager.toggle()
        } catch {
            errorMessage = error.localizedDescription
            showingError = true
        }
    }

    private func saveConfiguration() {
        Task {
            do {
                try await vpnManager.configure(
                    relayHost: relayHost,
                    relayPort: Int(relayPort) ?? 443,
                    claimPort: Int(claimPort) ?? 8443
                )
            } catch {
                errorMessage = error.localizedDescription
                showingError = true
            }
        }
    }

    private func removeConfiguration() {
        Task {
            do {
                try await vpnManager.removeConfiguration()
            } catch {
                errorMessage = error.localizedDescription
                showingError = true
            }
        }
    }
}

// MARK: - Info Row

struct InfoRow: View {
    let title: String
    let value: String

    var body: some View {
        HStack {
            Text(title)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
        }
    }
}

// MARK: - Preview

#Preview {
    NavigationStack {
        VPNView()
    }
}
