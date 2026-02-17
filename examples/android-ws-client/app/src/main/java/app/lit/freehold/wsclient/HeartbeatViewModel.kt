package app.lit.freehold.wsclient

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.chromium.net.CronetEngine
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Connection path for dual-path DNS.
 *
 * The primary domain uses SVCB records that let the browser/client race
 * both the relay and direct paths — whichever responds first wins.
 * The explicit .relay and .home subdomains give SDK clients manual control.
 */
enum class ConnectionPath(val label: String, val description: String) {
    /** Primary FQDN — SVCB racing (relay + direct). Best for most clients. */
    PRIMARY("Auto (SVCB)", "Races relay + direct, picks fastest"),
    /** Explicit relay path — always routes through the relay. */
    RELAY("Relay", "Always via relay (works behind any NAT)"),
    /** Explicit direct/home path — lowest latency if NAT allows it. */
    HOME("Direct", "Direct to server (permissive NAT only)"),
}

data class UiState(
    val subdomain: String = "",
    val port: String = "8443",
    val path: ConnectionPath = ConnectionPath.PRIMARY,
    val connected: Boolean = false,
    val connecting: Boolean = false,
    val error: String? = null,
    val messages: List<String> = emptyList(),
) {
    /** Build the WebSocket URL from subdomain, port, and connection path. */
    val url: String
        get() {
            if (subdomain.isBlank()) return ""
            val host = when (path) {
                ConnectionPath.PRIMARY -> "$subdomain.freehold.lit.app"
                ConnectionPath.RELAY   -> "$subdomain.relay.freehold.lit.app"
                ConnectionPath.HOME    -> "$subdomain.home.freehold.lit.app"
            }
            return "https://$host:$port/ws"
        }
}

class HeartbeatViewModel(app: Application) : AndroidViewModel(app) {

    private val _uiState = MutableStateFlow(UiState())
    val uiState: StateFlow<UiState> = _uiState

    private var ws: WebSocket? = null
    private var wsJob: Job? = null

    // Cronet engine — provides HTTP/3 (QUIC) transport
    private val cronetEngine: CronetEngine by lazy {
        CronetEngine.Builder(app)
            .enableQuic(true)
            .enableHttp2(true)
            .build()
    }

    // OkHttp client backed by Cronet for H3 WebSocket
    private val client: OkHttpClient by lazy {
        // Trust self-signed certs (dev only!)
        val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>?, type: String?) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>?, type: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        })
        val sslContext = SSLContext.getInstance("TLS").apply {
            init(null, trustAll, SecureRandom())
        }

        OkHttpClient.Builder()
            .sslSocketFactory(sslContext.socketFactory, trustAll[0] as X509TrustManager)
            .hostnameVerifier { _, _ -> true }
            .readTimeout(0, TimeUnit.MILLISECONDS)     // no read timeout for WS
            .pingInterval(30, TimeUnit.SECONDS)
            .build()
    }

    fun setSubdomain(subdomain: String) {
        _uiState.update { it.copy(subdomain = subdomain) }
    }

    fun setPort(port: String) {
        _uiState.update { it.copy(port = port) }
    }

    fun setPath(path: ConnectionPath) {
        _uiState.update { it.copy(path = path) }
    }

    fun connect() {
        disconnect()
        _uiState.update { it.copy(connecting = true, error = null, messages = emptyList()) }

        wsJob = viewModelScope.launch(Dispatchers.IO) {
            try {
                // Convert https:// -> wss:// for WebSocket
                val currentState = _uiState.value
                val wsUrl = currentState.url
                    .replaceFirst("https://", "wss://")
                    .replaceFirst("http://", "ws://")

                log("Path: ${currentState.path.label} (${currentState.path.description})")
                log("Connecting to $wsUrl ...")

                val request = Request.Builder()
                    .url(wsUrl)
                    .build()

                ws = client.newWebSocket(request, object : WebSocketListener() {
                    override fun onOpen(webSocket: WebSocket, response: Response) {
                        log("Connected (protocol: ${response.protocol})")
                        _uiState.update { it.copy(connected = true, connecting = false) }
                    }

                    override fun onMessage(webSocket: WebSocket, text: String) {
                        log("← $text")
                    }

                    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                        log("Error: ${t.message}")
                        _uiState.update { it.copy(connected = false, connecting = false, error = t.message) }
                    }

                    override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                        log("Closing: $code $reason")
                        webSocket.close(1000, null)
                        _uiState.update { it.copy(connected = false, connecting = false) }
                    }

                    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                        log("Closed: $code $reason")
                        _uiState.update { it.copy(connected = false, connecting = false) }
                    }
                })
            } catch (e: Exception) {
                log("Connection failed: ${e.message}")
                _uiState.update { it.copy(connecting = false, error = e.message) }
            }
        }
    }

    fun disconnect() {
        ws?.close(1000, "user disconnect")
        ws = null
        wsJob?.cancel()
        wsJob = null
        _uiState.update { it.copy(connected = false, connecting = false) }
    }

    fun send(text: String) {
        ws?.let {
            log("→ $text")
            it.send(text)
        }
    }

    private fun log(msg: String) {
        _uiState.update { state ->
            val messages = state.messages + msg
            // Keep last 200 messages
            state.copy(messages = if (messages.size > 200) messages.takeLast(200) else messages)
        }
    }

    override fun onCleared() {
        disconnect()
        super.onCleared()
    }
}
