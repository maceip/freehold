# NAT Traversal: How It Works

## Your setup

- **Bob** (server): laptop on home WiFi, behind a home router NAT
- **Alice** (client): phone on cellular, behind carrier NAT
- **Relay**: public server at `142.248.222.1`

## Step by step

### 1. Bob registers

Bob's app starts and sends Register to the relay from local port 55126.
Bob's router maps it to `176.2.178.102:55126` (home routers usually
preserve the port). The relay stores Bob's NAT address.

### 2. DNS records are created

After Bob sends CreateRecords, the relay creates:

```
hash.freehold.lit.app        A    142.248.222.1         (relay)
hash.freehold.lit.app        HTTPS  relay + direct SVCB records
hash.home.freehold.lit.app   A    176.2.178.102         (Bob's NAT IP)
hash.home.freehold.lit.app   HTTPS  port=55126          (Bob's NAT port)
```

The `.home` port comes from the UDP source port the relay saw during
registration. On a cone NAT (which home routers are), this is the same
port Bob uses for ALL destinations.

### 3. Alice connects (the race)

Alice's browser or SDK resolves the DNS and sends QUIC Initials to
**both** the relay and Bob's home IP simultaneously:

```
Packet A: Alice → 142.248.222.1:2000    (relay)
Packet B: Alice → 176.2.178.102:55126   (direct, from .home DNS)
```

**Packet B gets dropped** by Bob's router — Bob never sent anything to
Alice, so Bob's NAT rejects it. But this packet opens Alice's own NAT:
Alice's carrier now expects replies from `176.2.178.102:55126`.

### 4. XDP forwards with full SNAT+DNAT (relay path)

Packet A arrives at the relay. XDP does **full SNAT+DNAT**:
- Destination rewritten to Bob's home address (`176.2.178.102:55126`)
- Source rewritten from Alice's IP to the **relay's own IP** (`142.248.222.1`)

This is critical. Without SNAT, Bob's Quinn would see Alice's real IP
as the source and respond directly to her — that response would never
pass through the relay, so the relay can't help with the return path.
With SNAT, Bob sees the relay as the client and responds to the relay.

### 5. Punch + Port Spray (parallel, for direct path)

Meanwhile, the relay sends a **Punch** message to Bob:
"Alice is at `162.120.248.180:11697` — send her a UDP packet."

Bob receives the Punch (it comes from the relay, which Bob's NAT allows).
Instead of sending a single poke, Bob **sprays** 10,000 one-byte UDP
packets to ports ±5,000 around Alice's known port (11697). This covers
the case where Alice's carrier NAT allocates a different port for the
.home path than the relay path. If the carrier assigns ports sequentially,
one of the 10,000 pokes will hit the right port and open Bob's NAT.

Total cost: ~10KB of one-byte packets, sent in <100ms.

### 6. Bob responds via relay (guaranteed path)

Bob's Quinn processes the QUIC Initial and responds to what it sees as
the source: `142.248.222.1:2000` (the relay). This response hits the
relay's XDP on the reverse path:
- Source rewritten from Bob's IP to relay's IP
- Destination rewritten from relay's IP to Alice's real IP and port

Alice receives the response from `142.248.222.1:2000` — the exact
address she sent to. Her NAT accepts it. Connection established.

### 7. Direct path upgrade (if spray worked)

If the port spray in step 5 opened Bob's NAT for Alice's carrier port,
subsequent connections via the `.home` DNS path work directly:
- Alice sends QUIC to Bob's real IP (`176.2.178.102:55126`)
- Bob's NAT accepts it (spray opened the pinhole)
- Bob responds directly to Alice
- Relay is out of the data path

If spray didn't work (random port allocation), all traffic continues
through the relay's XDP at wire speed.

## Why it works

The relay path (steps 4+6) **always works** because:
1. XDP does full SNAT+DNAT — Bob sees the relay as the client, responds
   to the relay, and the reverse XDP delivers to Alice.
2. Alice sent to the relay, so her NAT accepts responses from the relay.

The direct path (steps 5+7) works when:
1. **Bob's home router is cone NAT.** Same external port for all
   destinations — the port in DNS matches what Alice sees.
2. **Port spray hits Alice's carrier port.** If the carrier allocates
   sequential ports, one of the 10,000 sprayed ports opens Bob's NAT
   for Alice's .home traffic.

The relay carries all data until the direct path is established. After
that, QUIC connection migration moves traffic to the direct path and
the relay drops out.

## Verify NAT type

### Bob's NAT

Run on Bob's machine:

```
python3 stun_test.py
```

If it says `CONE`, the direct path will work. If it says `SYMMETRIC`,
Bob's external port changes per destination and the direct path will
not reliably work (the relay would need to proxy responses).

### Alice's NAT (carrier port allocation)

Run on Alice's phone (or any device behind carrier NAT):

```
python3 tools/nat_port_test.py
```

This tests whether the carrier allocates ports sequentially, randomly,
or in clusters. If ports are sequential or clustered within a range of
10,000, port spray will work. If they're fully random, the bidirectional
XDP relay fallback will be used instead.

## Common issues

**Connection times out after 15s:**
The Punch didn't open Bob's NAT in time, or Alice's NAT is dropping
Bob's response. Check:
- Is Bob heartbeating? (NAT mapping expires without heartbeats)
- Is the `.home` HTTPS record port correct? (`dig hash.home.zone HTTPS`)
- Is Alice's client doing the SVCB race / .home probe?

**Works on WiFi but not cellular:**
The phone's carrier NAT may be port-restricted in a way that rejects
Bob's response. Port spray handles the common case (sequential port
allocation). If spray doesn't work, the bidirectional XDP relay
provides a fallback — the relay does SNAT+DNAT both directions at
wire speed, so Bob's responses go through the relay back to Alice.

Run `tools/nat_port_test.py` on the phone to check port patterns.

**Bob's NAT is SYMMETRIC:**
The direct path won't work. Bob's external port for Alice differs from
the port in DNS. You'll need to either:
- Replace the router with one that does cone NAT (most consumer routers)
- Use UPnP if the router supports it
- The bidirectional XDP relay handles this automatically as a fallback
