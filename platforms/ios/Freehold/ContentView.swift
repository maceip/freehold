// ContentView.swift
// Main UI for Freehold iOS App

import SwiftUI

struct ContentView: View {
    @EnvironmentObject var client: FreeholdClient
    @State private var showingSettings = false
    @State private var showingError = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                // Status Card
                StatusCard(
                    state: client.currentState,
                    relayAddress: client.relayAddress,
                    isRunning: client.isRunning
                )

                // Control Buttons
                ControlButtons(
                    isRunning: client.isRunning,
                    onStart: { showingSettings = true },
                    onStop: { client.stop() }
                )

                // Neighbors List
                if !client.discoveredNeighbors.isEmpty {
                    NeighborsList(neighbors: client.discoveredNeighbors)
                }

                Spacer()

                // Version
                Text("Freehold v\(client.version)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding()
            .navigationTitle("Freehold")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showingSettings = true
                    } label: {
                        Image(systemName: "gear")
                    }
                }
            }
            .sheet(isPresented: $showingSettings) {
                SettingsView { config in
                    do {
                        try client.start(with: config)
                        showingSettings = false
                    } catch {
                        showingError = true
                    }
                }
            }
            .alert("Error", isPresented: $showingError) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(client.lastError ?? "An unknown error occurred")
            }
            .onChange(of: client.lastError) { _, newValue in
                if newValue != nil {
                    showingError = true
                }
            }
        }
    }
}

// MARK: - Status Card

struct StatusCard: View {
    let state: RelayState
    let relayAddress: String
    let isRunning: Bool

    var body: some View {
        VStack(spacing: 16) {
            // Large Status Icon
            ZStack {
                Circle()
                    .fill(statusColor.opacity(0.2))
                    .frame(width: 120, height: 120)

                Image(systemName: state.icon)
                    .font(.system(size: 50))
                    .foregroundStyle(statusColor)
            }

            // Status Text
            VStack(spacing: 4) {
                Text(state.displayName)
                    .font(.title2)
                    .fontWeight(.semibold)

                if isRunning && !relayAddress.isEmpty {
                    Text(relayAddress)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding(32)
        .frame(maxWidth: .infinity)
        .background(.ultraThinMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 20))
    }

    private var statusColor: Color {
        switch state {
        case .connected: return .green
        case .pending: return .orange
        case .disconnected: return .gray
        }
    }
}

// MARK: - Control Buttons

struct ControlButtons: View {
    let isRunning: Bool
    let onStart: () -> Void
    let onStop: () -> Void

    var body: some View {
        HStack(spacing: 16) {
            if isRunning {
                Button(action: onStop) {
                    Label("Stop", systemImage: "stop.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(.red)
            } else {
                Button(action: onStart) {
                    Label("Start", systemImage: "play.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(.blue)
            }
        }
        .controlSize(.large)
    }
}

// MARK: - Neighbors List

struct NeighborsList: View {
    let neighbors: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Discovered Neighbors")
                .font(.headline)

            ForEach(neighbors, id: \.self) { neighbor in
                HStack {
                    Image(systemName: "network")
                        .foregroundStyle(.secondary)
                    Text(neighbor)
                        .font(.system(.body, design: .monospaced))
                    Spacer()
                }
                .padding(.vertical, 4)
            }
        }
        .padding()
        .frame(maxWidth: .infinity)
        .background(.ultraThinMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}

// MARK: - Settings View

struct SettingsView: View {
    @Environment(\.dismiss) private var dismiss

    @State private var relayHost = "relay.freehold.network"
    @State private var relayPort = "443"
    @State private var claimPort = "8443"
    @State private var backendHost = "127.0.0.1"
    @State private var backendPort = "8080"
    @State private var domain = "localhost"
    @State private var autoDiscover = true

    let onConnect: (FreeholdConfiguration) -> Void

    var body: some View {
        NavigationStack {
            Form {
                Section("Relay Server") {
                    TextField("Host", text: $relayHost)
                        .textContentType(.URL)
                        .autocapitalization(.none)

                    TextField("Port", text: $relayPort)
                        .keyboardType(.numberPad)

                    TextField("Claim Port", text: $claimPort)
                        .keyboardType(.numberPad)
                }

                Section("Local Backend") {
                    TextField("Host", text: $backendHost)
                        .autocapitalization(.none)

                    TextField("Port", text: $backendPort)
                        .keyboardType(.numberPad)
                }

                Section("Options") {
                    TextField("Domain", text: $domain)
                        .autocapitalization(.none)

                    Toggle("Auto-discover neighbors", isOn: $autoDiscover)
                }

                Section {
                    Button("Connect") {
                        let config = FreeholdConfiguration(
                            relayHost: relayHost,
                            relayPort: UInt16(relayPort) ?? 443,
                            claimPort: UInt16(claimPort) ?? 8443,
                            backendHost: backendHost,
                            backendPort: UInt16(backendPort) ?? 8080,
                            domain: domain,
                            autoDiscover: autoDiscover
                        )
                        onConnect(config)
                    }
                    .frame(maxWidth: .infinity)
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
            }
        }
    }
}

// MARK: - Preview

#Preview {
    ContentView()
        .environmentObject(FreeholdClient.shared)
}
