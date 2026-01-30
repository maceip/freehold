/**
 * Freehold IWA - Direct Sockets & QUIC Client
 *
 * This module provides QUIC connectivity via quinn-wasm and
 * demonstrates Direct Sockets API usage for TCP/UDP communication.
 */

// Import quinn-wasm module (will be loaded after WASM initialization)
let quinnWasm = null;
let isConnected = false;

// DOM Elements
const statusIndicator = document.getElementById('status-indicator');
const statusText = document.getElementById('status-text');
const apiStatus = document.getElementById('api-status');
const serverAddress = document.getElementById('server-address');
const btnConnect = document.getElementById('btn-connect');
const btnDisconnect = document.getElementById('btn-disconnect');
const btnSend = document.getElementById('btn-send');
const messageInput = document.getElementById('message-input');
const messageControls = document.getElementById('message-controls');
const logContainer = document.getElementById('log-container');

/**
 * Logging utility with timestamps and severity levels
 */
function log(message, level = 'info') {
  const time = new Date().toLocaleTimeString('en-US', { hour12: false });
  const entry = document.createElement('div');
  entry.className = 'log-entry';
  entry.innerHTML = `
    <span class="log-time">[${time}]</span>
    <span class="log-message ${level}">${escapeHtml(message)}</span>
  `;
  logContainer.appendChild(entry);
  logContainer.scrollTop = logContainer.scrollHeight;
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/**
 * Update connection status UI
 */
function updateStatus(connected, text) {
  isConnected = connected;
  statusIndicator.className = `status-indicator ${connected ? 'connected' : ''}`;
  statusText.textContent = text;

  btnConnect.disabled = connected;
  btnDisconnect.disabled = !connected;
  messageControls.style.display = connected ? 'flex' : 'none';
}

/**
 * Check Direct Sockets API availability
 */
function checkDirectSocketsAPI() {
  const apis = [
    { name: 'TCPSocket', available: typeof TCPSocket !== 'undefined' },
    { name: 'UDPSocket', available: typeof UDPSocket !== 'undefined' },
    { name: 'TCPServerSocket', available: typeof TCPServerSocket !== 'undefined' },
  ];

  apiStatus.innerHTML = apis.map(api => `
    <div class="api-badge">
      <span class="dot ${api.available ? 'available' : 'unavailable'}"></span>
      <span>${api.name}</span>
    </div>
  `).join('');

  const allAvailable = apis.every(api => api.available);

  if (!allAvailable) {
    log('Direct Sockets API not fully available. Ensure you are running in an Isolated Web App with proper permissions.', 'warn');
  } else {
    log('Direct Sockets API available', 'success');
  }

  return allAvailable;
}

/**
 * Initialize quinn-wasm module
 */
async function initQuinnWasm() {
  try {
    log('Loading quinn-wasm module...');

    // Dynamic import of quinn-wasm
    const module = await import('./quinn_wasm_direct_sockets.js');
    await module.default(); // Initialize WASM
    module.start(); // Set up panic hooks and tracing

    quinnWasm = module;
    log('quinn-wasm initialized successfully', 'success');
    return true;
  } catch (err) {
    log(`Failed to initialize quinn-wasm: ${err.message}`, 'error');
    console.error('quinn-wasm init error:', err);
    return false;
  }
}

/**
 * Connect to QUIC server using quinn-wasm
 */
async function connectToServer() {
  const address = serverAddress.value.trim();

  if (!address) {
    log('Please enter a server address', 'error');
    return;
  }

  if (!quinnWasm) {
    log('quinn-wasm not initialized', 'error');
    return;
  }

  try {
    log(`Connecting to ${address}...`);
    updateStatus(false, 'Connecting...');

    // Use quinn-wasm to establish QUIC connection
    const response = await quinnWasm.connect_quic_direct_sockets(address, 'Hello from Freehold IWA');

    log(`Connected! Server response: ${response}`, 'success');
    updateStatus(true, `Connected to ${address}`);
  } catch (err) {
    log(`Connection failed: ${err.message}`, 'error');
    updateStatus(false, 'Connection failed');
    statusIndicator.classList.add('error');
  }
}

/**
 * Disconnect from QUIC server
 */
async function disconnectFromServer() {
  try {
    log('Disconnecting...');

    if (quinnWasm && quinnWasm.disconnect) {
      await quinnWasm.disconnect();
    }

    log('Disconnected', 'info');
    updateStatus(false, 'Disconnected');
  } catch (err) {
    log(`Disconnect error: ${err.message}`, 'error');
    updateStatus(false, 'Disconnected');
  }
}

/**
 * Send message over QUIC connection
 */
async function sendMessage() {
  const message = messageInput.value.trim();

  if (!message) {
    return;
  }

  if (!quinnWasm || !isConnected) {
    log('Not connected', 'error');
    return;
  }

  try {
    log(`Sending: ${message}`);

    const address = serverAddress.value.trim();
    const response = await quinnWasm.connect_quic_direct_sockets(address, message);

    log(`Response: ${response}`, 'success');
    messageInput.value = '';
  } catch (err) {
    log(`Send failed: ${err.message}`, 'error');
  }
}

/**
 * TCP Server Socket demonstration
 * Creates a local TCP server using Direct Sockets API
 */
async function startTCPServer(port = 44818) {
  if (typeof TCPServerSocket === 'undefined') {
    log('TCPServerSocket not available', 'error');
    return null;
  }

  try {
    log(`Starting TCP server on port ${port}...`);

    const socket = new TCPServerSocket('0.0.0.0', {
      localPort: port,
    });

    const { readable: server, localAddress, localPort } = await socket.opened;
    log(`TCP server listening on ${localAddress}:${localPort}`, 'success');

    // Handle incoming connections
    server.pipeTo(new WritableStream({
      async write(connection) {
        const { readable: client, writable, remoteAddress, remotePort } = await connection.opened;
        log(`New connection from ${remoteAddress}:${remotePort}`);

        // Echo server: read data and echo it back
        const reader = client.getReader();
        const writer = writable.getWriter();

        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            const text = new TextDecoder().decode(value);
            log(`Received: ${text}`);

            // Echo back
            await writer.write(new TextEncoder().encode(`Echo: ${text}`));
          }
        } catch (err) {
          log(`Connection error: ${err.message}`, 'error');
        } finally {
          reader.releaseLock();
          writer.releaseLock();
        }
      }
    }));

    return socket;
  } catch (err) {
    log(`Failed to start TCP server: ${err.message}`, 'error');
    return null;
  }
}

/**
 * UDP Socket demonstration
 */
async function createUDPSocket(localPort = 44819) {
  if (typeof UDPSocket === 'undefined') {
    log('UDPSocket not available', 'error');
    return null;
  }

  try {
    log(`Creating UDP socket on port ${localPort}...`);

    const socket = new UDPSocket({
      localAddress: '0.0.0.0',
      localPort: localPort,
    });

    const { readable, writable, localAddress, localPort: boundPort } = await socket.opened;
    log(`UDP socket bound to ${localAddress}:${boundPort}`, 'success');

    // Handle incoming datagrams
    readable.pipeTo(new WritableStream({
      write(datagram) {
        const { data, remoteAddress, remotePort } = datagram;
        const text = new TextDecoder().decode(data);
        log(`UDP from ${remoteAddress}:${remotePort}: ${text}`);
      }
    }));

    return { socket, writable };
  } catch (err) {
    log(`Failed to create UDP socket: ${err.message}`, 'error');
    return null;
  }
}

// Event listeners
btnConnect.addEventListener('click', connectToServer);
btnDisconnect.addEventListener('click', disconnectFromServer);
btnSend.addEventListener('click', sendMessage);

messageInput.addEventListener('keypress', (e) => {
  if (e.key === 'Enter') {
    sendMessage();
  }
});

serverAddress.addEventListener('keypress', (e) => {
  if (e.key === 'Enter' && !isConnected) {
    connectToServer();
  }
});

// Initialize on load
document.addEventListener('DOMContentLoaded', async () => {
  log('Freehold IWA initializing...');

  // Check Direct Sockets API
  checkDirectSocketsAPI();

  // Initialize quinn-wasm
  await initQuinnWasm();

  log('Ready', 'success');
});

// Export functions for external use
export {
  connectToServer,
  disconnectFromServer,
  sendMessage,
  startTCPServer,
  createUDPSocket,
  log
};
