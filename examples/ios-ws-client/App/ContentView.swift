import SwiftUI

struct ContentView: View {
    @StateObject private var client = WSClient()
    @State private var host = ""
    @State private var port = "8443"
    @State private var sendText = "hello"
    @State private var devMode = false

    private var isConnected: Bool { client.state == .connected }
    private var isConnecting: Bool { client.state == .connecting }

    var body: some View {
        NavigationStack {
            VStack(spacing: 12) {
                // ---- Connection fields ----
                HStack(spacing: 8) {
                    TextField("Subdomain.freehold.lit.app", text: $host)
                        .textFieldStyle(.roundedBorder)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                        .textContentType(.URL)

                    TextField("Port", text: $port)
                        .textFieldStyle(.roundedBorder)
                        .keyboardType(.numberPad)
                        .frame(width: 72)
                }

                // ---- Connect / Disconnect ----
                HStack {
                    Button(isConnected ? "Disconnect" : "Connect") {
                        if isConnected {
                            client.disconnect()
                        } else {
                            client.connect(
                                host: host,
                                port: UInt16(port) ?? 8443,
                                skipVerify: devMode
                            )
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(host.isEmpty || isConnecting)

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
