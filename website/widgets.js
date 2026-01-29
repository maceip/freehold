// Freehold Demo Widgets
// 2x2 dashboard showing H3 connectivity, stats, terminal, and WebTransport

(function() {
  'use strict';

  // Analytics helper
  const analytics = {
    track(widget, action) {
      try {
        navigator.sendBeacon('/a', JSON.stringify({
          w: widget,
          a: action,
          t: Date.now()
        }));
      } catch (e) {
        // Ignore errors
      }
    }
  };

  // ==========================================
  // Widget 1: H3 Connectivity Test
  // ==========================================
  class H3Widget {
    constructor(container) {
      this.container = container;
      this.render();
      this.test(); // Auto-test on load
    }

    render() {
      this.container.innerHTML = `
        <div class="widget-title">H3 Connectivity</div>
        <div class="widget-status">
          <span class="status-dot" id="h3-dot"></span>
          <span id="h3-status">Testing...</span>
        </div>
        <div class="widget-details" id="h3-details"></div>
        <button class="widget-btn" id="h3-test-btn">Test Connection</button>
        <div class="widget-footer" id="h3-footer"></div>
      `;

      this.container.querySelector('#h3-test-btn').addEventListener('click', () => {
        analytics.track('h3', 'click');
        this.test();
      });
    }

    async test() {
      const dot = this.container.querySelector('#h3-dot');
      const status = this.container.querySelector('#h3-status');
      const details = this.container.querySelector('#h3-details');
      const footer = this.container.querySelector('#h3-footer');

      dot.className = 'status-dot pending';
      status.textContent = 'Testing...';

      try {
        const start = performance.now();
        const res = await fetch('/health', { cache: 'no-store' });
        const latency = Math.round(performance.now() - start);
        const data = await res.json();

        // Try to detect protocol from performance API
        let protocol = 'unknown';
        const entries = performance.getEntriesByType('resource');
        const entry = entries.find(e => e.name.includes('/health'));
        if (entry && entry.nextHopProtocol) {
          protocol = entry.nextHopProtocol;
        }

        dot.className = 'status-dot success';
        status.textContent = `Connected via ${protocol.toUpperCase()}`;
        details.innerHTML = `
          <div>Latency: <strong>${latency}ms</strong></div>
          <div>Protocol: <strong>${protocol}</strong></div>
        `;
        footer.textContent = `Tested just now`;

        analytics.track('h3', 'success');
      } catch (e) {
        dot.className = 'status-dot error';
        status.textContent = 'Connection failed';
        details.innerHTML = `<div class="error-text">${e.message}</div>`;
        footer.textContent = '';

        analytics.track('h3', 'error');
      }
    }
  }

  // ==========================================
  // Widget 2: Live Relay Stats
  // ==========================================
  class StatsWidget {
    constructor(container) {
      this.container = container;
      this.sparkline = [];
      this.render();
      this.poll();
    }

    render() {
      this.container.innerHTML = `
        <div class="widget-title">Relay Stats</div>
        <div class="stats-grid">
          <div class="stat-item">
            <div class="stat-value" id="stat-connections">-</div>
            <div class="stat-label">Connections</div>
          </div>
          <div class="stat-item">
            <div class="stat-value" id="stat-bytes">-</div>
            <div class="stat-label">Forwarded</div>
          </div>
          <div class="stat-item">
            <div class="stat-value" id="stat-uptime">-</div>
            <div class="stat-label">Uptime</div>
          </div>
          <div class="stat-item">
            <div class="stat-value" id="stat-throughput">-</div>
            <div class="stat-label">Throughput</div>
          </div>
        </div>
        <div class="sparkline-container">
          <canvas id="sparkline" width="200" height="30"></canvas>
        </div>
      `;
    }

    formatBytes(bytes) {
      if (bytes === 0) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    formatUptime(secs) {
      const d = Math.floor(secs / 86400);
      const h = Math.floor((secs % 86400) / 3600);
      const m = Math.floor((secs % 3600) / 60);
      if (d > 0) return `${d}d ${h}h`;
      if (h > 0) return `${h}h ${m}m`;
      return `${m}m`;
    }

    async poll() {
      try {
        const res = await fetch('/stats', { cache: 'no-store' });
        const stats = await res.json();

        this.container.querySelector('#stat-connections').textContent = stats.connections || 0;
        this.container.querySelector('#stat-bytes').textContent = this.formatBytes(stats.bytes_forwarded || 0);
        this.container.querySelector('#stat-uptime').textContent = this.formatUptime(stats.uptime_secs || 0);
        this.container.querySelector('#stat-throughput').textContent = (stats.throughput_mbps || 0).toFixed(1) + ' Mbps';

        // Update sparkline
        this.sparkline.push(stats.throughput_mbps || 0);
        if (this.sparkline.length > 20) this.sparkline.shift();
        this.renderSparkline();

        analytics.track('stats', 'poll');
      } catch (e) {
        // Silently fail, will retry
      }

      // Poll every 5 seconds
      setTimeout(() => this.poll(), 5000);
    }

    renderSparkline() {
      const canvas = this.container.querySelector('#sparkline');
      if (!canvas) return;

      const ctx = canvas.getContext('2d');
      const w = canvas.width;
      const h = canvas.height;

      ctx.clearRect(0, 0, w, h);

      if (this.sparkline.length < 2) return;

      const max = Math.max(...this.sparkline, 1);
      const step = w / (this.sparkline.length - 1);

      ctx.beginPath();
      ctx.strokeStyle = '#9370db';
      ctx.lineWidth = 2;

      this.sparkline.forEach((val, i) => {
        const x = i * step;
        const y = h - (val / max) * (h - 4);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });

      ctx.stroke();
    }
  }

  // ==========================================
  // Widget 3: Terminal Demo
  // ==========================================
  class TerminalWidget {
    constructor(container) {
      this.container = container;
      this.lines = [];
      this.render();
    }

    render() {
      this.container.innerHTML = `
        <div class="widget-title">Terminal</div>
        <div class="terminal-output" id="terminal-output"></div>
        <div class="terminal-controls">
          <button class="widget-btn" id="terminal-run">Run Demo</button>
          <button class="widget-btn secondary" id="terminal-clear">Clear</button>
        </div>
      `;

      this.output = this.container.querySelector('#terminal-output');

      this.container.querySelector('#terminal-run').addEventListener('click', () => {
        analytics.track('terminal', 'run');
        this.runDemo();
      });

      this.container.querySelector('#terminal-clear').addEventListener('click', () => {
        this.clear();
      });

      // Show initial prompt
      this.print('$ ', 'prompt');
    }

    print(text, className = '') {
      const line = document.createElement('div');
      line.className = 'terminal-line ' + className;
      line.textContent = text;
      this.output.appendChild(line);
      this.output.scrollTop = this.output.scrollHeight;
    }

    clear() {
      this.output.innerHTML = '';
      this.print('$ ', 'prompt');
    }

    async typeText(text, delay = 30) {
      const chars = text.split('');
      const lastLine = this.output.lastElementChild;

      for (const char of chars) {
        lastLine.textContent += char;
        await this.sleep(delay);
      }
    }

    sleep(ms) {
      return new Promise(r => setTimeout(r, ms));
    }

    async runDemo() {
      this.clear();

      // Command 1: curl health
      await this.typeText('curl -s https://freehold.lit.app/health | jq');
      await this.sleep(200);
      this.print('');

      try {
        const res = await fetch('/health');
        const data = await res.json();
        this.print(JSON.stringify(data, null, 2), 'output');
      } catch (e) {
        this.print('{"error": "' + e.message + '"}', 'error');
      }

      await this.sleep(500);
      this.print('$ ', 'prompt');

      // Command 2: dig
      await this.typeText('dig freehold.lit.app HTTPS +short');
      await this.sleep(200);
      this.print('');
      this.print('1 . alpn="h3"', 'output');

      await this.sleep(500);
      this.print('$ ', 'prompt');

      // Command 3: curl headers
      await this.typeText('curl -I --http3 https://freehold.lit.app/ 2>&1 | head -5');
      await this.sleep(200);
      this.print('');
      this.print('HTTP/3 200', 'output');
      this.print('content-type: text/html; charset=utf-8', 'output');
      this.print('alt-svc: h3=":443"; ma=86400', 'output');

      await this.sleep(300);
      this.print('');
      this.print('$ ', 'prompt');
    }
  }

  // ==========================================
  // Widget 4: WebTransport Demo
  // ==========================================
  class WebTransportWidget {
    constructor(container) {
      this.container = container;
      this.transport = null;
      this.render();
    }

    render() {
      const supported = typeof WebTransport !== 'undefined';

      this.container.innerHTML = `
        <div class="widget-title">WebTransport</div>
        ${supported ? `
          <div class="widget-status">
            <span class="status-dot" id="wt-dot"></span>
            <span id="wt-status">Disconnected</span>
          </div>
          <div class="wt-log" id="wt-log"></div>
          <div class="wt-input-row">
            <input type="text" id="wt-input" placeholder="Enter message..." disabled>
            <button class="widget-btn" id="wt-send" disabled>Send</button>
          </div>
          <div class="wt-controls">
            <button class="widget-btn" id="wt-connect">Connect</button>
            <button class="widget-btn secondary" id="wt-disconnect" disabled>Close</button>
          </div>
        ` : `
          <div class="widget-unsupported">
            <div class="unsupported-icon">⚠️</div>
            <div>WebTransport not supported</div>
            <div class="unsupported-hint">Requires Chrome 97+ or Edge 97+</div>
          </div>
        `}
      `;

      if (supported) {
        this.container.querySelector('#wt-connect').addEventListener('click', () => {
          analytics.track('webtransport', 'connect');
          this.connect();
        });

        this.container.querySelector('#wt-disconnect').addEventListener('click', () => {
          this.disconnect();
        });

        this.container.querySelector('#wt-send').addEventListener('click', () => {
          this.send();
        });

        this.container.querySelector('#wt-input').addEventListener('keypress', (e) => {
          if (e.key === 'Enter') this.send();
        });
      }
    }

    log(msg, type = 'info') {
      const log = this.container.querySelector('#wt-log');
      if (!log) return;

      const line = document.createElement('div');
      line.className = 'wt-log-line ' + type;
      line.textContent = msg;
      log.appendChild(line);
      log.scrollTop = log.scrollHeight;

      // Keep only last 10 lines
      while (log.children.length > 10) {
        log.removeChild(log.firstChild);
      }
    }

    async connect() {
      const dot = this.container.querySelector('#wt-dot');
      const status = this.container.querySelector('#wt-status');

      dot.className = 'status-dot pending';
      status.textContent = 'Connecting...';
      this.log('Connecting to wss://freehold.lit.app...');

      try {
        // Note: WebTransport endpoint would need to be implemented
        // For now, show that the API is available
        this.transport = new WebTransport('https://freehold.lit.app:4433/webtransport');

        this.transport.closed.then(() => {
          this.onClose();
        }).catch((e) => {
          this.onError(e);
        });

        await this.transport.ready;

        dot.className = 'status-dot success';
        status.textContent = 'Connected';
        this.log('Connected!', 'success');

        this.container.querySelector('#wt-connect').disabled = true;
        this.container.querySelector('#wt-disconnect').disabled = false;
        this.container.querySelector('#wt-input').disabled = false;
        this.container.querySelector('#wt-send').disabled = false;

        analytics.track('webtransport', 'connected');
      } catch (e) {
        dot.className = 'status-dot error';
        status.textContent = 'Failed to connect';
        this.log('Error: ' + e.message, 'error');
        this.log('(WebTransport endpoint not yet implemented)', 'info');

        analytics.track('webtransport', 'error');
      }
    }

    onClose() {
      const dot = this.container.querySelector('#wt-dot');
      const status = this.container.querySelector('#wt-status');

      dot.className = 'status-dot';
      status.textContent = 'Disconnected';
      this.log('Connection closed');

      this.container.querySelector('#wt-connect').disabled = false;
      this.container.querySelector('#wt-disconnect').disabled = true;
      this.container.querySelector('#wt-input').disabled = true;
      this.container.querySelector('#wt-send').disabled = true;
    }

    onError(e) {
      this.log('Error: ' + e.message, 'error');
    }

    disconnect() {
      if (this.transport) {
        this.transport.close();
        this.transport = null;
      }
      this.onClose();
    }

    async send() {
      const input = this.container.querySelector('#wt-input');
      const msg = input.value.trim();
      if (!msg) return;

      this.log('TX: ' + msg, 'tx');
      input.value = '';

      // In a real implementation, we'd send via the stream
      // For now, just echo back
      setTimeout(() => {
        this.log('RX: Echo: ' + msg, 'rx');
      }, 50);

      analytics.track('webtransport', 'send');
    }
  }

  // ==========================================
  // Initialize Dashboard
  // ==========================================
  function initDashboard() {
    // Create container if it doesn't exist
    let dashboard = document.getElementById('freehold-dashboard');
    if (!dashboard) {
      dashboard = document.createElement('div');
      dashboard.id = 'freehold-dashboard';
      dashboard.className = 'widget-grid';
      dashboard.innerHTML = `
        <div class="widget" id="widget-h3"></div>
        <div class="widget" id="widget-stats"></div>
        <div class="widget" id="widget-terminal"></div>
        <div class="widget" id="widget-webtransport"></div>
      `;

      // Find a good place to insert it, or append to body
      const container = document.querySelector('.dashboard-container') || document.body;
      container.appendChild(dashboard);
    }

    // Initialize widgets
    new H3Widget(document.getElementById('widget-h3'));
    new StatsWidget(document.getElementById('widget-stats'));
    new TerminalWidget(document.getElementById('widget-terminal'));
    new WebTransportWidget(document.getElementById('widget-webtransport'));
  }

  // Export for manual initialization
  window.FreeholdDashboard = {
    init: initDashboard,
    H3Widget,
    StatsWidget,
    TerminalWidget,
    WebTransportWidget
  };

  // Auto-init when DOM is ready (if dashboard container exists)
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      if (document.getElementById('freehold-dashboard') || document.querySelector('.dashboard-container')) {
        initDashboard();
      }
    });
  }
})();
