import SwiftUI

/// Connection path for dual-path DNS.
///
/// The primary domain uses SVCB records that let clients race both
/// the relay and direct paths — whichever responds first wins.
/// The explicit `.relay` and `.home` subdomains give manual control.
enum ConnectionPath: String, CaseIterable {
    /// Primary FQDN — SVCB racing (relay + direct). Best for most clients.
    case primary = "Auto (SVCB)"
    /// Explicit relay path — always routes through the relay.
    case relay = "Relay"
    /// Explicit direct/home path — lowest latency if NAT allows it.
    case home = "Direct"

    var description: String {
        switch self {
        case .primary: return "Races relay + direct"
        case .relay:   return "Always via relay"
        case .home:    return "Direct to server"
        }
    }

    func buildHost(subdomain: String) -> String {
        switch self {
        case .primary: return "\(subdomain).freehold.lit.app"
        case .relay:   return "\(subdomain).relay.freehold.lit.app"
        case .home:    return "\(subdomain).home.freehold.lit.app"
        }
    }
}

struct ContentView: View {
    @StateObject private var client = WSClient()
    @State private var subdomain = ""
    @State private var port = "8443"
    @State private var path: ConnectionPath = .primary
    @State private var sendText = "hello"
    @State private var devMode = false

    private var isConnected: Bool { client.state == .connected }
    private var isConnecting: Bool { client.state == .connecting }
    private var resolvedHost: String { path.buildHost(subdomain: subdomain) }

    var body: some View {
        NavigationStack {
            VStack(spacing: 12) {
                // ---- Connection fields ----
                HStack(spacing: 8) {
                    TextField("Subdomain hash (e.g. a7xk2m)", text: $subdomain)
                        .textFieldStyle(.roundedBorder)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)

                    TextField("Port", text: $port)
                        .textFieldStyle(.roundedBorder)
                        .keyboardType(.numberPad)
                        .frame(width: 72)
                }

                // ---- Path selector (dual-path DNS) ----
                Picker("Path", selection: $path) {
                    ForEach(ConnectionPath.allCases, id: \.self) { p in
                        Text(p.rawValue).tag(p)
                    }
                }
                .pickerStyle(.segmented)

                if !subdomain.isEmpty {
                    Text(resolvedHost)
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }

                // ---- Connect / Disconnect ----
                HStack {
                    Button(isConnected ? "Disconnect" : "Connect") {
                        if isConnected {
                            client.disconnect()
                        } else {
                            client.connect(
                                host: resolvedHost,
                                port: UInt16(port) ?? 8443,
                                skipVerify: devMode
                            )
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(subdomain.isEmpty || isConnecting)

                    Toggle("Dev", isOn: $devMode)
                        .fixedSize()
                        .font(.caption)

                    Spacer()

                    statusBadge
                }

                // ---- Error ----
                if let err = client.lastError {
                    Text(err)
                        .font(.caption)
                        .foregroundColor(.red)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }

                // ---- Send ----
                HStack {
                    TextField("Message", text: $sendText)
                        .textFieldStyle(.roundedBorder)
                    Button("Send") {
                        client.send(sendText)
                    }
                    .disabled(!isConnected)
                }

                // ---- Message log ----
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 2) {
                            ForEach(Array(client.messages.enumerated()), id: \.offset) { idx, msg in
                                Text(msg)
                                    .font(.system(.caption, design: .monospaced))
                                    .id(idx)
                            }
                        }
                        .padding(8)
                    }
                    .background(Color(.secondarySystemBackground))
                    .cornerRadius(8)
                    .onChange(of: client.messages.count) { _ in
                        if let last = client.messages.indices.last {
                            proxy.scrollTo(last, anchor: .bottom)
                        }
                    }
                }
            }
            .padding()
            .navigationTitle("Freehold WS")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    @ViewBuilder
    private var statusBadge: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(statusColor)
                .frame(width: 8, height: 8)
            Text(statusText)
                .font(.caption)
                .foregroundColor(.secondary)
        }
    }

    private var statusColor: Color {
        switch client.state {
        case .connected:    return .green
        case .connecting:   return .orange
        case .error:        return .red
        case .disconnected: return .gray
        }
    }

    private var statusText: String {
        switch client.state {
        case .connected:    return "Connected"
        case .connecting:   return "Connecting..."
        case .error:        return "Error"
        case .disconnected: return "Disconnected"
        }
    }
}

#Preview {
    ContentView()
}
