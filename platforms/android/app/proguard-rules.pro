# Freehold Android Client ProGuard Rules

# Keep UniFFI generated bindings
-keep class uniffi.freehold_android.** { *; }
-keepclassmembers class uniffi.freehold_android.** { *; }

# Keep JNA classes (required for UniFFI)
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { *; }

# Keep native method names
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep the callback interfaces
-keep interface com.freehold.client.StatusCallback { *; }
-keep interface com.freehold.client.FreeholdApp { *; }

# Keep data classes used with native code
-keep class com.freehold.client.TunnelConfig { *; }
-keep class com.freehold.client.ConnectionState { *; }

# Keep VPN service
-keep class com.freehold.client.FreeholdVpnService { *; }

# Kotlin coroutines
-keepclassmembernames class kotlinx.** {
    volatile <fields>;
}
