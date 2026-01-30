/**
 * Freehold QUIC Client - quinn-wasm Integration
 *
 * This module provides a bridge between the UI and the quinn-wasm
 * WebAssembly module for QUIC protocol support via Direct Sockets API.
 */

// State
let wasmModule = null;
let isConnected = false;
let connectionStats = {
  bytesSent: 0,
  bytesReceived: 0,
  rtt: null,
  activeStreams: 0,
};

// DOM Elements
const logArea = document.getElementById('log-area');
const connectionStatus = document.getElementById('connection-status');
const statusLabel = document.getElementById('status-label');
const serverAddr = document.getElementById('server-addr');
const alpnProtocol = document.getElementById('alpn-protocol');
const messageData = document.getElementById('message-data');

// Buttons
const btnConnect = document.getElementById('btn-connect');
const btnDisconnect = document.getElementById('btn-disconnect');
const btnPing = document.getElementById('btn-ping');
const btnSend = document.getElementById('btn-send');
const btnSendDatagram = document.getElementById('btn-send-datagram');
const btnClearLog = document.getElementById('btn-clear-log');
const btnExportLog = document.getElementById('btn-export-log');

// Stats elements
const statRtt = document.getElementById('stat-rtt');
const statBytesSent = document.getElementById('stat-bytes-sent');
const statBytesRecv = document.getElementById('stat-bytes-recv');
const statStreams = document.getElementById('stat-streams');

/**
 * Log a message to the activity log
 */
function log(message, level = 'info') {
  const time = new Date().toISOString().split('T')[1].split('.')[0];
  const entry = document.createElement('div');
  entry.className = 'log-line';
  entry.innerHTML = `
    <span class="log-time">${time}</span>
    <span class="log-level ${level}">${level}</span>
    <span class="log-content">${escapeHtml(message)}</span>
  `;
  logArea.appendChild(entry);
  logArea.scrollTop = logArea.scrollHeight;
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/**
 * Update connection status UI
 */
function setConnectionStatus(status) {
  connectionStatus.className = `status-badge ${status}`;
  statusLabel.textContent = status === 'connected' ? 'Connected' :
    status === 'pending' ? 'Connecting...' :
    status === 'error' ? 'Error' : 'Disconnected';

  isConnected = status === 'connected';

  // Update button states
  btnConnect.disabled = isConnected || status === 'pending';
  btnDisconnect.disabled = !isConnected;
  btnPing.disabled = !isConnected;
  btnSend.disabled = !isConnected;
  btnSendDatagram.disabled = !isConnected;
}

/**
 * Update stats display
 */
function updateStats() {
  statRtt.textContent = connectionStats.rtt !== null ? connectionStats.rtt.toFixed(1) : '--';
  statBytesSent.textContent = formatBytes(connectionStats.bytesSent);
  statBytesRecv.textContent = formatBytes(connectionStats.bytesReceived);
  statStreams.textContent = connectionStats.activeStreams;
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes;
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + 'K';
  return (bytes / (1024 * 1024)).toFixed(1) + 'M';
}

/**
 * Check if Direct Sockets API is available
 */
function checkDirectSocketsAPI() {
  const tcpAvailable = typeof TCPSocket !== 'undefined';
  const udpAvailable = typeof UDPSocket !== 'undefined';

  if (!tcpAvailable || !udpAvailable) {
    log('Direct Sockets API not available. This app requires an Isolated Web App environment.', 'error');
    return false;
  }

  log('Direct Sockets API detected (TCPSocket, UDPSocket available)', 'success');
  return true;
}

/**
 * Initialize quinn-wasm module
 */
async function initWasm() {
  try {
    log('Loading quinn-wasm WebAssembly module...');

    // Import the WASM module
    const module = await import('./quinn_wasm_direct_sockets.js');

    // Initialize WASM
    await module.default();

    // Start tracing and panic hooks
    if (module.start) {
      module.start();
    }

    wasmModule = module;
    log('quinn-wasm initialized successfully', 'success');
    return true;
  } catch (err) {
    log(`Failed to load quinn-wasm: ${err.message}`, 'error');
    console.error('WASM init error:', err);
    return false;
  }
}

/**
 * Connect to QUIC server
 */
async function connect() {
  const address = serverAddr.value.trim();
  const alpn = alpnProtocol.value;

  if (!address) {
    log('Please enter a server address', 'error');
    return;
  }

  if (!wasmModule) {
    log('WASM module not initialized', 'error');
    return;
  }

  setConnectionStatus('pending');
  log(`Connecting to ${address} with ALPN: ${alpn}...`);

  const startTime = performance.now();

  try {
    // Attempt QUIC connection via quinn-wasm
    const response = await wasmModule.connect_quic_direct_sockets(
      address,
      `CONNECT ${alpn}`
    );

    const rtt = performance.now() - startTime;
    connectionStats.rtt = rtt;
    connectionStats.activeStreams = 1;

    setConnectionStatus('connected');
    log(`Connected to ${address}`, 'success');
    log(`Initial RTT: ${rtt.toFixed(2)}ms`, 'debug');

    if (response) {
      connectionStats.bytesReceived += response.length;
      log(`Server response: ${response}`, 'info');
    }

    updateStats();
  } catch (err) {
    setConnectionStatus('error');
    log(`Connection failed: ${err.message}`, 'error');
    console.error('Connection error:', err);
  }
}

/**
 * Disconnect from server
 */
async function disconnect() {
  log('Disconnecting...');

  try {
    if (wasmModule && wasmModule.disconnect) {
      await wasmModule.disconnect();
    }

    connectionStats.activeStreams = 0;
    setConnectionStatus('disconnected');
    log('Disconnected', 'info');
    updateStats();
  } catch (err) {
    log(`Disconnect error: ${err.message}`, 'error');
    setConnectionStatus('disconnected');
  }
}

/**
 * Send ping to measure RTT
 */
async function sendPing() {
  if (!isConnected || !wasmModule) return;

  const address = serverAddr.value.trim();
  const startTime = performance.now();

  try {
    await wasmModule.connect_quic_direct_sockets(address, 'PING');
    const rtt = performance.now() - startTime;

    connectionStats.rtt = rtt;
    connectionStats.bytesSent += 4;
    connectionStats.bytesReceived += 4;

    log(`Ping RTT: ${rtt.toFixed(2)}ms`, 'debug');
    updateStats();
  } catch (err) {
    log(`Ping failed: ${err.message}`, 'error');
  }
}

/**
 * Send message over QUIC stream
 */
async function sendMessage() {
  const data = messageData.value.trim();

  if (!data) {
    log('Please enter a message to send', 'error');
    return;
  }

  if (!isConnected || !wasmModule) {
    log('Not connected', 'error');
    return;
  }

  const address = serverAddr.value.trim();

  try {
    log(`Sending ${data.length} bytes...`);
    connectionStats.bytesSent += data.length;

    const response = await wasmModule.connect_quic_direct_sockets(address, data);

    if (response) {
      connectionStats.bytesReceived += response.length;
      log(`Response: ${response}`, 'success');
    }

    updateStats();
    messageData.value = '';
  } catch (err) {
    log(`Send failed: ${err.message}`, 'error');
  }
}

/**
 * Send datagram (unreliable)
 */
async function sendDatagram() {
  const data = messageData.value.trim();

  if (!data) {
    log('Please enter data to send', 'error');
    return;
  }

  if (!isConnected || !wasmModule) {
    log('Not connected', 'error');
    return;
  }

  try {
    log(`Sending datagram (${data.length} bytes)...`);
    connectionStats.bytesSent += data.length;

    // Note: Datagram support depends on quinn-wasm implementation
    if (wasmModule.send_datagram) {
      await wasmModule.send_datagram(data);
      log('Datagram sent', 'success');
    } else {
      log('Datagram sending not supported in this build', 'error');
    }

    updateStats();
  } catch (err) {
    log(`Datagram send failed: ${err.message}`, 'error');
  }
}

/**
 * Clear log
 */
function clearLog() {
  logArea.innerHTML = '';
  log('Log cleared', 'info');
}

/**
 * Export log to file
 */
function exportLog() {
  const lines = Array.from(logArea.querySelectorAll('.log-line')).map(line => {
    const time = line.querySelector('.log-time').textContent;
    const level = line.querySelector('.log-level').textContent;
    const content = line.querySelector('.log-content').textContent;
    return `[${time}] [${level.toUpperCase()}] ${content}`;
  });

  const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);

  const a = document.createElement('a');
  a.href = url;
  a.download = `freehold-quic-log-${Date.now()}.txt`;
  a.click();

  URL.revokeObjectURL(url);
  log('Log exported', 'info');
}

// Event listeners
btnConnect.addEventListener('click', connect);
btnDisconnect.addEventListener('click', disconnect);
btnPing.addEventListener('click', sendPing);
btnSend.addEventListener('click', sendMessage);
btnSendDatagram.addEventListener('click', sendDatagram);
btnClearLog.addEventListener('click', clearLog);
btnExportLog.addEventListener('click', exportLog);

// Enter key handlers
serverAddr.addEventListener('keypress', (e) => {
  if (e.key === 'Enter' && !isConnected) {
    connect();
  }
});

messageData.addEventListener('keypress', (e) => {
  if (e.key === 'Enter' && e.ctrlKey && isConnected) {
    sendMessage();
  }
});

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
  log('Freehold QUIC Test Interface starting...');

  // Check Direct Sockets API
  const apiAvailable = checkDirectSocketsAPI();

  if (apiAvailable) {
    // Initialize WASM
    await initWasm();
  }

  log('Ready', 'success');
});
