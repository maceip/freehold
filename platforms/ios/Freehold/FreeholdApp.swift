// FreeholdApp.swift
// Main iOS App Entry Point

import SwiftUI

@main
struct FreeholdApp: App {
    @StateObject private var client = FreeholdClient.shared

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(client)
        }
    }
}
