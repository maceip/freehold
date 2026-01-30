package com.freehold.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

/**
 * FreeholdVpnService - The "Fake VPN" that creates a UDP QUIC tunnel
 *
 * This isn't a traditional VPN - it creates a TUN interface to intercept traffic,
 * then tunnels selected traffic through QUIC to the Freehold relay network.
 *
 * Architecture:
 * ```
 * App Traffic
 *     |
 *     v
 * TUN Interface (this service)
 *     |
 *     +-- Local traffic: pass through
 *     |
 *     +-- Relay traffic: QUIC tunnel --> Freehold Relay
 *                                           |
 *                                           v
 *                                     H3 Proxy (local)
 *                                           |
 *                                           v
 *                                     Backend HTTP
 * ```
 */
class FreeholdVpnService : VpnService() {

    companion object {
        private const val TAG = "FreeholdVpn"
        private const val NOTIFICATION_CHANNEL_ID = "freehold_vpn"
        private const val NOTIFICATION_ID = 1

        // VPN configuration
        private const val VPN_MTU = 1500
        private const val VPN_ADDRESS = "10.255.255.1"
        private const val VPN_ROUTE = "0.0.0.0"
        private const val VPN_DNS = "8.8.8.8"

        // Actions
        const val ACTION_START = "com.freehold.client.START_VPN"
        const val ACTION_STOP = "com.freehold.client.STOP_VPN"

        // Extras
        const val EXTRA_RELAY_ADDRESS = "relay_address"
        const val EXTRA_RELAY_PORT = "relay_port"
        const val EXTRA_LOCAL_PORT = "local_port"
        const val EXTRA_BACKEND_ADDRESS = "backend_address"
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var tunnelThread: Thread? = null
    private val isRunning = AtomicBoolean(false)

    // Coroutine scope for async operations
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Native tunnel (via UniFFI bindings)
    private var nativeTunnel: FreeholdTunnelBridge? = null

    // QUIC tunnel socket
    private var quicSocket: DatagramSocket? = null

    // Configuration
    private var relayAddress: String = ""
    private var relayPort: Int = 0
    private var localPort: Int = 0
    private var backendAddress: String = ""

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "VPN Service created")
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_START -> {
                relayAddress = intent.getStringExtra(EXTRA_RELAY_ADDRESS) ?: "127.0.0.1"
                relayPort = intent.getIntExtra(EXTRA_RELAY_PORT, 443)
                localPort = intent.getIntExtra(EXTRA_LOCAL_PORT, 8443)
                backendAddress = intent.getStringExtra(EXTRA_BACKEND_ADDRESS) ?: "127.0.0.1:8080"

                startVpn()
                START_STICKY
            }
            ACTION_STOP -> {
                stopVpn()
                START_NOT_STICKY
            }
            else -> START_NOT_STICKY
        }
    }

    override fun onDestroy() {
        stopVpn()
        serviceScope.cancel()
        super.onDestroy()
        Log.d(TAG, "VPN Service destroyed")
    }

    private fun startVpn() {
        if (isRunning.getAndSet(true)) {
            Log.w(TAG, "VPN already running")
            return
        }

        Log.i(TAG, "Starting Freehold VPN tunnel")
        Log.i(TAG, "Relay: $relayAddress:$relayPort, Local: $localPort, Backend: $backendAddress")

        try {
            // Start foreground service
            startForeground(NOTIFICATION_ID, createNotification("Connecting..."))

            // Establish VPN interface
            vpnInterface = establishVpnInterface()
            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                stopSelf()
                return
            }

            val fd = vpnInterface!!.fd
            Log.i(TAG, "VPN interface established, fd=$fd")

            // Initialize native tunnel
            initializeNativeTunnel(fd)

            // Start the packet processing thread
            startTunnelThread(vpnInterface!!)

            // Update notification
            updateNotification("Connected to port $relayPort")

            // Notify app of connection
            FreeholdApp.instance?.onVpnConnected()

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start VPN", e)
            isRunning.set(false)
            stopSelf()
        }
    }

    private fun stopVpn() {
        if (!isRunning.getAndSet(false)) {
            return
        }

        Log.i(TAG, "Stopping Freehold VPN tunnel")

        // Stop native tunnel
        nativeTunnel?.stop()
        nativeTunnel = null

        // Stop tunnel thread
        tunnelThread?.interrupt()
        tunnelThread = null

        // Close QUIC socket
        quicSocket?.close()
        quicSocket = null

        // Close VPN interface
        vpnInterface?.close()
        vpnInterface = null

        // Notify app
        FreeholdApp.instance?.onVpnDisconnected()

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun establishVpnInterface(): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("Freehold")
            .setMtu(VPN_MTU)
            .addAddress(VPN_ADDRESS, 32)
            .addRoute(VPN_ROUTE, 0)
            .addDnsServer(VPN_DNS)
            .setBlocking(true)

        // Allow bypass for our own QUIC socket
        builder.allowFamily(android.system.OsConstants.AF_INET)
        builder.allowFamily(android.system.OsConstants.AF_INET6)

        // Exclude local addresses and the relay from VPN routing
        // This ensures our QUIC tunnel traffic doesn't get caught in a loop
        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: Exception) {
            Log.w(TAG, "Could not exclude own package from VPN")
        }

        return builder.establish()
    }

    private fun initializeNativeTunnel(vpnFd: Int) {
        try {
            // Initialize the Rust runtime
            FreeholdNative.initRuntime()

            // Create tunnel configuration
            val config = TunnelConfig(
                relayAddress = relayAddress,
                relayPort = relayPort.toUShort(),
                localPort = localPort.toUShort(),
                backendAddress = backendAddress,
                autoDiscover = true
            )

            // Create status callback
            val callback = object : StatusCallback {
                override fun onStateChanged(state: ConnectionState, message: String) {
                    Log.d(TAG, "State: $state - $message")
                    when (state) {
                        ConnectionState.CONNECTED -> updateNotification("Connected")
                        ConnectionState.CONNECTING -> updateNotification("Connecting...")
                        ConnectionState.DISCONNECTED -> updateNotification("Disconnected")
                        ConnectionState.ERROR -> updateNotification("Error: $message")
                    }
                    FreeholdApp.instance?.onStateChanged(state, message)
                }

                override fun onPortAssigned(port: UShort) {
                    Log.i(TAG, "Port assigned: $port")
                    FreeholdApp.instance?.onPortAssigned(port.toInt())
                }

                override fun onNeighborDiscovered(ip: String) {
                    Log.d(TAG, "Neighbor discovered: $ip")
                }

                override fun onError(error: String) {
                    Log.e(TAG, "Tunnel error: $error")
                    FreeholdApp.instance?.onError(error)
                }

                override fun onBytesTransferred(rx: ULong, tx: ULong) {
                    FreeholdApp.instance?.onBytesTransferred(rx.toLong(), tx.toLong())
                }
            }

            // Create and start the native tunnel
            nativeTunnel = FreeholdTunnelBridge(config, callback)
            nativeTunnel?.start(vpnFd)

            Log.i(TAG, "Native tunnel initialized")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize native tunnel", e)
            throw e
        }
    }

    private fun startTunnelThread(vpnInterface: ParcelFileDescriptor) {
        tunnelThread = Thread {
            Log.d(TAG, "Tunnel thread started")

            val inputStream = FileInputStream(vpnInterface.fileDescriptor)
            val outputStream = FileOutputStream(vpnInterface.fileDescriptor)
            val packet = ByteBuffer.allocate(VPN_MTU)

            try {
                // Create QUIC socket and protect it from VPN
                quicSocket = DatagramSocket()
                protect(quicSocket!!)
                quicSocket?.connect(InetSocketAddress(relayAddress, 9999))

                while (isRunning.get() && !Thread.interrupted()) {
                    // Read packet from TUN
                    val length = inputStream.read(packet.array())
                    if (length > 0) {
                        packet.limit(length)

                        // Process through native tunnel
                        val outPacket = nativeTunnel?.processOutbound(
                            packet.array().copyOf(length)
                        )

                        if (outPacket != null && outPacket.isNotEmpty()) {
                            // Send to QUIC tunnel
                            val datagram = DatagramPacket(
                                outPacket,
                                outPacket.size
                            )
                            quicSocket?.send(datagram)
                        }

                        packet.clear()
                    }

                    // Check for incoming QUIC packets
                    if (quicSocket?.isClosed == false) {
                        val recvBuffer = ByteArray(VPN_MTU)
                        val recvPacket = DatagramPacket(recvBuffer, recvBuffer.size)

                        try {
                            quicSocket?.soTimeout = 10 // 10ms timeout
                            quicSocket?.receive(recvPacket)

                            if (recvPacket.length > 0) {
                                // Process through native tunnel
                                val inPacket = nativeTunnel?.processInbound(
                                    recvBuffer.copyOf(recvPacket.length)
                                )

                                if (inPacket != null && inPacket.isNotEmpty()) {
                                    // Write to TUN
                                    outputStream.write(inPacket)
                                }
                            }
                        } catch (e: java.net.SocketTimeoutException) {
                            // Expected, continue loop
                        }
                    }
                }

            } catch (e: InterruptedException) {
                Log.d(TAG, "Tunnel thread interrupted")
            } catch (e: Exception) {
                Log.e(TAG, "Tunnel thread error", e)
            } finally {
                Log.d(TAG, "Tunnel thread stopped")
            }
        }.apply {
            name = "FreeholdTunnel"
            start()
        }
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            "Freehold VPN",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Freehold VPN tunnel status"
            setShowBadge(false)
        }

        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(channel)
    }

    private fun createNotification(status: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("Freehold")
            .setContentText(status)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(status: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, createNotification(status))
    }
}

/**
 * Bridge class for native tunnel operations.
 * This wraps the UniFFI-generated bindings.
 */
class FreeholdTunnelBridge(
    private val config: TunnelConfig,
    private val callback: StatusCallback
) {
    private var tunnel: uniffi.freehold_android.FreeholdTunnel? = null

    fun start(vpnFd: Int) {
        tunnel = uniffi.freehold_android.FreeholdTunnel(
            uniffi.freehold_android.TunnelConfig(
                relayAddress = config.relayAddress,
                relayPort = config.relayPort,
                localPort = config.localPort,
                backendAddress = config.backendAddress,
                autoDiscover = config.autoDiscover
            ),
            object : uniffi.freehold_android.StatusCallback {
                override fun onStateChanged(state: uniffi.freehold_android.ConnectionState, message: String) {
                    callback.onStateChanged(state.toLocal(), message)
                }
                override fun onPortAssigned(port: UShort) = callback.onPortAssigned(port)
                override fun onNeighborDiscovered(ip: String) = callback.onNeighborDiscovered(ip)
                override fun onError(error: String) = callback.onError(error)
                override fun onBytesTransferred(rx: ULong, tx: ULong) = callback.onBytesTransferred(rx, tx)
            }
        )
        tunnel?.start(vpnFd)
    }

    fun stop() {
        tunnel?.stop()
        tunnel = null
    }

    fun processOutbound(packet: ByteArray): ByteArray? {
        return try {
            tunnel?.processOutbound(packet)
        } catch (e: Exception) {
            null
        }
    }

    fun processInbound(packet: ByteArray): ByteArray? {
        return try {
            tunnel?.processInbound(packet)
        } catch (e: Exception) {
            null
        }
    }
}

// Extension to convert UniFFI ConnectionState to local enum
private fun uniffi.freehold_android.ConnectionState.toLocal(): ConnectionState {
    return when (this) {
        uniffi.freehold_android.ConnectionState.CONNECTED -> ConnectionState.CONNECTED
        uniffi.freehold_android.ConnectionState.CONNECTING -> ConnectionState.CONNECTING
        uniffi.freehold_android.ConnectionState.DISCONNECTED -> ConnectionState.DISCONNECTED
        uniffi.freehold_android.ConnectionState.ERROR -> ConnectionState.ERROR
    }
}

// Local data classes
data class TunnelConfig(
    val relayAddress: String,
    val relayPort: UShort,
    val localPort: UShort,
    val backendAddress: String,
    val autoDiscover: Boolean
)

enum class ConnectionState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    ERROR
}

interface StatusCallback {
    fun onStateChanged(state: ConnectionState, message: String)
    fun onPortAssigned(port: UShort)
    fun onNeighborDiscovered(ip: String)
    fun onError(error: String)
    fun onBytesTransferred(rx: ULong, tx: ULong)
}

// Native function bridge
object FreeholdNative {
    init {
        System.loadLibrary("freehold_android")
    }

    fun initRuntime() {
        uniffi.freehold_android.initRuntime()
    }

    fun shutdownRuntime() {
        uniffi.freehold_android.shutdownRuntime()
    }
}
