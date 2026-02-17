"""
Freehold + Flask example.

A minimal Python backend exposed through Freehold's H3/QUIC relay.
Run with:
    python app.py                        # Flask on :5000
    freehold --backend 127.0.0.1:5000    # H3 proxy on :8443

Or use the convenience script:
    ./run.sh
"""

import time
from flask import Flask, jsonify, request

app = Flask(__name__)
start_time = time.time()


@app.route("/")
def index():
    return """
    <html>
    <head><title>Freehold + Flask</title></head>
    <body style="font-family:system-ui;max-width:600px;margin:40px auto;padding:20px">
        <h1>Freehold + Flask</h1>
        <p>This page is served through Freehold's H3/QUIC relay.</p>
        <h2>API endpoints</h2>
        <ul>
            <li><a href="/api/health">/api/health</a> — health check</li>
            <li><a href="/api/time">/api/time</a> — server time</li>
            <li><code>POST /api/echo</code> — echo JSON body</li>
        </ul>
    </body>
    </html>
    """


@app.route("/api/health")
def health():
    return jsonify(status="ok", uptime=round(time.time() - start_time, 2))


@app.route("/api/time")
def server_time():
    return jsonify(
        utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        unix=int(time.time()),
    )


@app.route("/api/echo", methods=["POST"])
def echo():
    body = request.get_json(silent=True) or {}
    return jsonify(
        received=body,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
