"use client";

import { useState, useEffect } from "react";

export default function Home() {
  const [time, setTime] = useState(null);
  const [input, setInput] = useState("");
  const [echo, setEcho] = useState(null);

  // Fetch server time on load
  useEffect(() => {
    fetch("/api/time")
      .then((r) => r.json())
      .then(setTime);
  }, []);

  async function handleEcho(e) {
    e.preventDefault();
    const res = await fetch("/api/hello", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: input }),
    });
    setEcho(await res.json());
  }

  return (
    <main style={{ fontFamily: "system-ui", maxWidth: 600, margin: "40px auto", padding: 20 }}>
      <h1>Freehold + Next.js</h1>
      <p style={{ color: "#666" }}>
        This page is served through Freehold's H3/QUIC relay. The Next.js dev
        server runs on localhost:3000 — Freehold proxies HTTP/3 to it.
      </p>

      <section style={{ marginTop: 24 }}>
        <h2>Server Time</h2>
        {time ? (
          <pre style={{ background: "#f5f5f5", padding: 12, borderRadius: 6 }}>
            {JSON.stringify(time, null, 2)}
          </pre>
        ) : (
          <p>Loading...</p>
        )}
      </section>

      <section style={{ marginTop: 24 }}>
        <h2>Echo API</h2>
        <form onSubmit={handleEcho} style={{ display: "flex", gap: 8 }}>
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Your name"
            style={{ padding: "8px 12px", borderRadius: 6, border: "1px solid #ccc", flex: 1 }}
          />
          <button type="submit" style={{ padding: "8px 16px", borderRadius: 6 }}>
            Send
          </button>
        </form>
        {echo && (
          <pre style={{ background: "#f0f9ff", padding: 12, borderRadius: 6, marginTop: 8 }}>
            {JSON.stringify(echo, null, 2)}
          </pre>
        )}
      </section>
    </main>
  );
}
