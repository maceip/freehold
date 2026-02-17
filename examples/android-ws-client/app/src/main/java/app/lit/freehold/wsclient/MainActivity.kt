package app.lit.freehold.wsclient

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                HeartbeatScreen()
            }
        }
    }
}

@Composable
fun HeartbeatScreen(vm: HeartbeatViewModel = viewModel()) {
    val state by vm.uiState.collectAsState()
    val listState = rememberLazyListState()

    // Auto-scroll to bottom
    LaunchedEffect(state.messages.size) {
        if (state.messages.isNotEmpty()) {
            listState.animateScrollToItem(state.messages.lastIndex)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Text(
            "Freehold WebSocket Client",
            style = MaterialTheme.typography.headlineSmall,
        )

        Spacer(Modifier.height(8.dp))

        // Subdomain + port input
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            OutlinedTextField(
                value = state.subdomain,
                onValueChange = vm::setSubdomain,
                label = { Text("Subdomain hash") },
                placeholder = { Text("a7xk2m") },
                modifier = Modifier.weight(1f),
                singleLine = true,
            )
            OutlinedTextField(
                value = state.port,
                onValueChange = vm::setPort,
                label = { Text("Port") },
                placeholder = { Text("8443") },
                modifier = Modifier.width(96.dp),
                singleLine = true,
            )
        }

        Spacer(Modifier.height(4.dp))

        // Connection path selector (dual-path DNS)
        Row(
            horizontalArrangement = Arrangement.spacedBy(4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("Path:", fontSize = 14.sp)
            ConnectionPath.entries.forEach { path ->
                FilterChip(
                    selected = state.path == path,
                    onClick = { vm.setPath(path) },
                    label = { Text(path.label, fontSize = 12.sp) },
                )
            }
        }

        // Show resolved URL
        if (state.url.isNotBlank()) {
            Text(
                state.url,
                fontSize = 11.sp,
                color = MaterialTheme.colorScheme.outline,
                modifier = Modifier.padding(horizontal = 4.dp),
            )
        }

        Spacer(Modifier.height(8.dp))

        // Connect / Disconnect button
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Button(
                onClick = {
                    if (state.connected) vm.disconnect() else vm.connect()
                },
                enabled = state.subdomain.isNotBlank() || state.connected,
            ) {
                Text(if (state.connected) "Disconnect" else "Connect")
            }

            // Status indicator
            Text(
                text = when {
                    state.connected -> "● Connected"
                    state.connecting -> "◌ Connecting..."
                    else -> "○ Disconnected"
                },
                fontSize = 14.sp,
                color = when {
                    state.connected -> MaterialTheme.colorScheme.primary
                    state.connecting -> MaterialTheme.colorScheme.tertiary
                    else -> MaterialTheme.colorScheme.outline
                },
            )
        }

        // Error display
        state.error?.let { err ->
            Spacer(Modifier.height(4.dp))
            Text(err, color = MaterialTheme.colorScheme.error, fontSize = 12.sp)
        }

        Spacer(Modifier.height(8.dp))

        // Send a message
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            var sendText by remember { mutableStateOf("hello") }
            OutlinedTextField(
                value = sendText,
                onValueChange = { sendText = it },
                modifier = Modifier.weight(1f),
                singleLine = true,
                label = { Text("Send") },
            )
            Button(
                onClick = { vm.send(sendText) },
                enabled = state.connected,
            ) {
                Text("Send")
            }
        }

        Spacer(Modifier.height(8.dp))

        // Message log
        Surface(
            modifier = Modifier.fillMaxSize(),
            tonalElevation = 1.dp,
            shape = MaterialTheme.shapes.small,
        ) {
            LazyColumn(
                state = listState,
                contentPadding = PaddingValues(8.dp),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                items(state.messages) { msg ->
                    Text(msg, fontSize = 12.sp, fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace)
                }
            }
        }
    }
}
