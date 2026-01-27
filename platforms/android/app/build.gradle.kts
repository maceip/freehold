plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.freehold.client"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.freehold.client"
        minSdk = 29  // Android 10+ for better VPN APIs
        targetSdk = 36  // Android 16
        versionCode = 1
        versionName = "0.1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isMinifyEnabled = false
            isDebuggable = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
        jniLibs {
            useLegacyPackaging = true
        }
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }
}

dependencies {
    // AndroidX Core
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.service)
    implementation(libs.androidx.activity.compose)

    // Compose
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    debugImplementation(libs.androidx.ui.tooling)

    // Coroutines
    implementation(libs.kotlinx.coroutines.android)

    // JNA for UniFFI bindings
    implementation(libs.jna) {
        artifact {
            type = "aar"
        }
    }
}

// Task to copy native libraries from Rust build
tasks.register<Copy>("copyNativeLibs") {
    group = "rust"
    description = "Copy compiled Rust libraries to jniLibs"

    val rustTarget = file("../../../target")

    from(rustTarget.resolve("aarch64-linux-android/release/libfreehold_android.so")) {
        into("arm64-v8a")
    }
    from(rustTarget.resolve("armv7-linux-androideabi/release/libfreehold_android.so")) {
        into("armeabi-v7a")
    }
    from(rustTarget.resolve("x86_64-linux-android/release/libfreehold_android.so")) {
        into("x86_64")
    }
    from(rustTarget.resolve("i686-linux-android/release/libfreehold_android.so")) {
        into("x86")
    }

    into(file("src/main/jniLibs"))
}

tasks.named("preBuild") {
    dependsOn("copyNativeLibs")
}
