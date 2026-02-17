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

data class UiState(
    val url: String = "https://142.248.222.1:55126/ws",
    val connected: Boolean = false,
    val connecting: Boolean = false,
    val error: String? = null,
    val messages: List<String> = emptyList(),
)

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

    fun setUrl(url: String) {
        _uiState.update { it.copy(url = url) }
    }

    fun connect() {
        disconnect()
        _uiState.update { it.copy(connecting = true, error = null, messages = emptyList()) }

        wsJob = viewModelScope.launch(Dispatchers.IO) {
            try {
                // Convert https:// -> wss:// for WebSocket
                val wsUrl = _uiState.value.url
                    .replaceFirst("https://", "wss://")
                    .replaceFirst("http://", "ws://")

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
