package com.freehold.client

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.freehold.client.ui.theme.FreeholdClientTheme
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * MainActivity - Freehold Android Client UI
 *
 * Provides a clean interface for:
 * - Configuring relay connection
 * - Starting/stopping the VPN tunnel
 * - Viewing connection status and statistics
 */
class MainActivity : ComponentActivity(), FreeholdApp {

    companion object {
        private const val TAG = "FreeholdMain"
        private const val VPN_REQUEST_CODE = 100
    }

    // UI State
    private val _uiState = MutableStateFlow(FreeholdUiState())
    val uiState: StateFlow<FreeholdUiState> = _uiState.asStateFlow()

    // VPN permission launcher
    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService()
        } else {
            Log.w(TAG, "VPN permission denied")
            _uiState.value = _uiState.value.copy(
                error = "VPN permission required"
            )
        }
    }

    // Notification permission launcher (API 33+)
    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (!granted) {
            Log.w(TAG, "Notification permission denied")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        // Register for app callbacks
        (application as FreeholdApplication).registerAppCallback(this)

        // Request notification permission if needed
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        setContent {
            FreeholdClientTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    FreeholdScreen(
                        uiState = uiState.collectAsState().value,
                        onConnect = { config -> requestVpnPermission(config) },
                        onDisconnect = { stopVpnService() },
                        onClearError = { _uiState.value = _uiState.value.copy(error = null) }
                    )
                }
            }
        }
    }

    override fun onDestroy() {
        (application as FreeholdApplication).unregisterAppCallback()
        super.onDestroy()
    }

    private fun requestVpnPermission(config: ConnectionConfig) {
        _uiState.value = _uiState.value.copy(
            config = config,
            connectionState = ConnectionState.CONNECTING
        )

        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            // Already have permission
            startVpnService()
        }
    }

    private fun startVpnService() {
        val config = _uiState.value.config ?: return

        val intent = Intent(this, FreeholdVpnService::class.java).apply {
            action = FreeholdVpnService.ACTION_START
            putExtra(FreeholdVpnService.EXTRA_RELAY_ADDRESS, config.relayAddress)
            putExtra(FreeholdVpnService.EXTRA_RELAY_PORT, config.relayPort)
            putExtra(FreeholdVpnService.EXTRA_LOCAL_PORT, config.localPort)
            putExtra(FreeholdVpnService.EXTRA_BACKEND_ADDRESS, config.backendAddress)
        }

        startForegroundService(intent)
    }

    private fun stopVpnService() {
        val intent = Intent(this, FreeholdVpnService::class.java).apply {
            action = FreeholdVpnService.ACTION_STOP
        }
        startService(intent)
    }

    // FreeholdApp interface implementations
    override fun onVpnConnected() {
        lifecycleScope.launch {
            _uiState.value = _uiState.value.copy(
                connectionState = ConnectionState.CONNECTED
            )
        }
    }

    override fun onVpnDisconnected() {
        lifecycleScope.launch {
            _uiState.value = _uiState.value.copy(
                connectionState = ConnectionState.DISCONNECTED,
                assignedPort = null
            )
        }
    }

    override fun onStateChanged(state: ConnectionState, message: String) {
        lifecycleScope.launch {
            _uiState.value = _uiState.value.copy(
                connectionState = state,
                statusMessage = message
            )
        }
    }

    override fun onPortAssigned(port: Int) {
        lifecycleScope.launch {
            _uiState.value = _uiState.value.copy(
                assignedPort = port
            )
        }
    }

    override fun onError(error: String) {
        lifecycleScope.launch {
            _uiState.value = _uiState.value.copy(
                error = error,
                connectionState = ConnectionState.ERROR
            )
        }
    }

    override fun onBytesTransferred(rx: Long, tx: Long) {
        lifecycleScope.launch {
            _uiState.value = _uiState.value.copy(
                rxBytes = rx,
                txBytes = tx
            )
        }
    }
}

// UI State
data class FreeholdUiState(
    val connectionState: ConnectionState = ConnectionState.DISCONNECTED,
    val statusMessage: String = "Not connected",
    val assignedPort: Int? = null,
    val rxBytes: Long = 0,
    val txBytes: Long = 0,
    val error: String? = null,
    val config: ConnectionConfig? = null
)

data class ConnectionConfig(
    val relayAddress: String,
    val relayPort: Int,
    val localPort: Int,
    val backendAddress: String
)

@Composable
fun FreeholdScreen(
    uiState: FreeholdUiState,
    onConnect: (ConnectionConfig) -> Unit,
    onDisconnect: () -> Unit,
    onClearError: () -> Unit
) {
    var relayAddress by remember { mutableStateOf("relay.freehold.network") }
    var relayPort by remember { mutableStateOf("443") }
    var localPort by remember { mutableStateOf("8443") }
    var backendAddress by remember { mutableStateOf("127.0.0.1:8080") }

    val isConnected = uiState.connectionState == ConnectionState.CONNECTED
    val isConnecting = uiState.connectionState == ConnectionState.CONNECTING

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(modifier = Modifier.height(48.dp))

        // Logo / Status indicator
        StatusIndicator(state = uiState.connectionState)

        Spacer(modifier = Modifier.height(24.dp))

        // Title
        Text(
            text = "FREEHOLD",
            fontSize = 32.sp,
            fontWeight = FontWeight.Bold,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.primary
        )

        Text(
            text = "Anycast Relay Network",
            fontSize = 14.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(32.dp))

        // Status card
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant
            )
        ) {
            Column(
                modifier = Modifier.padding(16.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "Status",
                        fontWeight = FontWeight.Medium
                    )
                    Text(
                        text = when (uiState.connectionState) {
                            ConnectionState.CONNECTED -> "Connected"
                            ConnectionState.CONNECTING -> "Connecting..."
                            ConnectionState.DISCONNECTED -> "Disconnected"
                            ConnectionState.ERROR -> "Error"
                        },
                        color = when (uiState.connectionState) {
                            ConnectionState.CONNECTED -> Color(0xFF4CAF50)
                            ConnectionState.CONNECTING -> Color(0xFFFFC107)
                            ConnectionState.DISCONNECTED -> MaterialTheme.colorScheme.onSurfaceVariant
                            ConnectionState.ERROR -> Color(0xFFF44336)
                        }
                    )
                }

                if (uiState.assignedPort != null) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(text = "Port")
                        Text(
                            text = uiState.assignedPort.toString(),
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }

                if (isConnected) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(text = "RX / TX")
                        Text(
                            text = "${formatBytes(uiState.rxBytes)} / ${formatBytes(uiState.txBytes)}",
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        // Configuration fields (only when disconnected)
        if (!isConnected && !isConnecting) {
            OutlinedTextField(
                value = relayAddress,
                onValueChange = { relayAddress = it },
                label = { Text("Relay Address") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            Spacer(modifier = Modifier.height(12.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                OutlinedTextField(
                    value = relayPort,
                    onValueChange = { relayPort = it.filter { c -> c.isDigit() } },
                    label = { Text("Relay Port") },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                )

                OutlinedTextField(
                    value = localPort,
                    onValueChange = { localPort = it.filter { c -> c.isDigit() } },
                    label = { Text("Local Port") },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            OutlinedTextField(
                value = backendAddress,
                onValueChange = { backendAddress = it },
                label = { Text("Backend Address") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
        }

        Spacer(modifier = Modifier.weight(1f))

        // Error display
        uiState.error?.let { error ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.errorContainer
                ),
                onClick = onClearError
            ) {
                Text(
                    text = error,
                    modifier = Modifier.padding(16.dp),
                    color = MaterialTheme.colorScheme.onErrorContainer
                )
            }
            Spacer(modifier = Modifier.height(16.dp))
        }

        // Connect/Disconnect button
        Button(
            onClick = {
                if (isConnected || isConnecting) {
                    onDisconnect()
                } else {
                    onConnect(
                        ConnectionConfig(
                            relayAddress = relayAddress,
                            relayPort = relayPort.toIntOrNull() ?: 443,
                            localPort = localPort.toIntOrNull() ?: 8443,
                            backendAddress = backendAddress
                        )
                    )
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = if (isConnected || isConnecting) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.primary
                }
            )
        ) {
            Text(
                text = when {
                    isConnecting -> "Cancel"
                    isConnected -> "Disconnect"
                    else -> "Connect"
                },
                fontSize = 18.sp,
                fontWeight = FontWeight.Medium
            )
        }

        Spacer(modifier = Modifier.height(24.dp))
    }
}

@Composable
fun StatusIndicator(state: ConnectionState) {
    val targetColor = when (state) {
        ConnectionState.CONNECTED -> Color(0xFF4CAF50)
        ConnectionState.CONNECTING -> Color(0xFFFFC107)
        ConnectionState.DISCONNECTED -> Color(0xFF9E9E9E)
        ConnectionState.ERROR -> Color(0xFFF44336)
    }

    val color by animateColorAsState(
        targetValue = targetColor,
        animationSpec = tween(300)
    )

    // Pulsing animation for connecting state
    val infiniteTransition = rememberInfiniteTransition()
    val scale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = if (state == ConnectionState.CONNECTING) 1.2f else 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(500),
            repeatMode = RepeatMode.Reverse
        )
    )

    Box(
        modifier = Modifier
            .size((80 * scale).dp)
            .clip(CircleShape)
            .background(color.copy(alpha = 0.2f)),
        contentAlignment = Alignment.Center
    ) {
        Box(
            modifier = Modifier
                .size((60 * scale).dp)
                .clip(CircleShape)
                .background(color.copy(alpha = 0.4f)),
            contentAlignment = Alignment.Center
        ) {
            Box(
                modifier = Modifier
                    .size((40 * scale).dp)
                    .clip(CircleShape)
                    .background(color)
            ) {
                // Hexagon symbol
                Text(
                    text = when (state) {
                        ConnectionState.CONNECTED -> "\u2B22" // Filled hexagon
                        ConnectionState.CONNECTING -> "\u25CE" // Bullseye
                        ConnectionState.DISCONNECTED -> "\u2B21" // Empty hexagon
                        ConnectionState.ERROR -> "\u2716" // X mark
                    },
                    modifier = Modifier.align(Alignment.Center),
                    color = Color.White,
                    fontSize = 20.sp
                )
            }
        }
    }
}

private fun formatBytes(bytes: Long): String {
    return when {
        bytes < 1024 -> "${bytes}B"
        bytes < 1024 * 1024 -> "${bytes / 1024}KB"
        bytes < 1024 * 1024 * 1024 -> "${bytes / (1024 * 1024)}MB"
        else -> "${bytes / (1024 * 1024 * 1024)}GB"
    }
}
