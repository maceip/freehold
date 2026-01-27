// Freehold Android Client - Root Build Configuration
// Target: API 36 (Android 16)

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.compose) apply false
}

// Rust/Cargo NDK configuration
buildscript {
    repositories {
        google()
        mavenCentral()
    }
}

tasks.register("buildRustLib") {
    group = "rust"
    description = "Build the Rust native library for Android"

    doLast {
        val targets = listOf(
            "aarch64-linux-android",
            "armv7-linux-androideabi",
            "x86_64-linux-android",
            "i686-linux-android"
        )

        val bridgePath = file("../../crates/freehold-android-bridge")

        targets.forEach { target ->
            exec {
                workingDir = bridgePath
                commandLine("cargo", "ndk", "-t", target, "build", "--release")
            }
        }
    }
}

tasks.register("generateKotlinBindings") {
    group = "rust"
    description = "Generate Kotlin bindings from UniFFI"
    dependsOn("buildRustLib")

    doLast {
        val bridgePath = file("../../crates/freehold-android-bridge")
        val outputPath = file("app/src/main/kotlin/com/freehold/client/bindings")

        outputPath.mkdirs()

        exec {
            workingDir = bridgePath
            commandLine(
                "cargo", "run", "--bin", "uniffi-bindgen",
                "generate", "src/freehold_android.udl",
                "--language", "kotlin",
                "--out-dir", outputPath.absolutePath
            )
        }
    }
}
