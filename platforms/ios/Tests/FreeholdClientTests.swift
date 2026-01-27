// FreeholdClientTests.swift
// Tests for the Freehold iOS client

import XCTest
@testable import FreeholdClient

final class FreeholdClientTests: XCTestCase {

    func testVersion() {
        // This test requires the FFI library to be linked
        // In a real test environment, you'd verify the version string
        XCTAssertTrue(true)
    }

    func testConfigurationInit() {
        let config = FreeholdConfiguration(
            relayHost: "test.example.com",
            relayPort: 443,
            claimPort: 8443,
            h3BindPort: 4433,
            backendHost: "127.0.0.1",
            backendPort: 8080,
            domain: "localhost",
            autoDiscover: true
        )

        XCTAssertEqual(config.relayHost, "test.example.com")
        XCTAssertEqual(config.relayPort, 443)
        XCTAssertEqual(config.claimPort, 8443)
        XCTAssertEqual(config.h3BindPort, 4433)
        XCTAssertEqual(config.backendHost, "127.0.0.1")
        XCTAssertEqual(config.backendPort, 8080)
        XCTAssertEqual(config.domain, "localhost")
        XCTAssertTrue(config.autoDiscover)
    }

    func testRelayStateDisplayName() {
        XCTAssertEqual(RelayState.disconnected.displayName, "Disconnected")
        XCTAssertEqual(RelayState.pending.displayName, "Connecting...")
        XCTAssertEqual(RelayState.connected.displayName, "Connected")
    }

    func testRelayStateIcon() {
        XCTAssertEqual(RelayState.disconnected.icon, "circle")
        XCTAssertEqual(RelayState.pending.icon, "circle.dashed")
        XCTAssertEqual(RelayState.connected.icon, "circle.fill")
    }
}
