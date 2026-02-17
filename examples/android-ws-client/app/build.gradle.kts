plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "app.lit.freehold.wsclient"
    compileSdk = 35

    defaultConfig {
        applicationId = "app.lit.freehold.wsclient"
        minSdk = 28  // Cronet requires API 28+
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // Compose
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")

    // Cronet — Google's HTTP/3 (QUIC) engine for Android
    implementation("org.chromium.net:cronet-api:130.6723.31")
    implementation("org.chromium.net:cronet-embedded:130.6723.31")

    // OkHttp with Cronet transport (bridges OkHttp API to Cronet engine)
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.google.net.cronet:cronet-okhttp:0.1.0")

    debugImplementation("androidx.compose.ui:ui-tooling")
}
