package com.freehold.client

import android.app.Application
import android.util.Log

/**
 * Freehold Application class
 *
 * Initializes the Rust runtime and manages application-wide state.
 */
class FreeholdApplication : Application() {

    companion object {
        private const val TAG = "FreeholdApp"

        @Volatile
        var instance: FreeholdApp? = null
            private set
    }

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "Freehold Application starting")

        // Initialize the Rust/UniFFI runtime
        try {
            FreeholdNative.initRuntime()
            Log.i(TAG, "Native runtime initialized")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize native runtime", e)
        }
    }

    override fun onTerminate() {
        Log.i(TAG, "Freehold Application terminating")

        try {
            FreeholdNative.shutdownRuntime()
        } catch (e: Exception) {
            Log.e(TAG, "Error shutting down native runtime", e)
        }

        super.onTerminate()
    }

    fun registerAppCallback(app: FreeholdApp) {
        instance = app
    }

    fun unregisterAppCallback() {
        instance = null
    }
}

/**
 * Interface for app-level callbacks from the VPN service
 */
interface FreeholdApp {
    fun onVpnConnected()
    fun onVpnDisconnected()
    fun onStateChanged(state: ConnectionState, message: String)
    fun onPortAssigned(port: Int)
    fun onError(error: String)
    fun onBytesTransferred(rx: Long, tx: Long)
}
