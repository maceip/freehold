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

### 4. XDP forwards + Punch + Port Spray

Packet A arrives at the relay. XDP rewrites the destination to Bob and
forwards it. Bob's NAT may drop this too (source is Alice, not relay).

But the relay also sends a **Punch** message to Bob:
"Alice is at `162.120.248.180:11697` — send her a UDP packet."

Bob receives the Punch (it comes from the relay, which Bob's NAT allows).
Instead of sending a single poke, Bob **sprays** 10,000 one-byte UDP
packets to ports ±5,000 around Alice's known port (11697). This covers
the case where Alice's carrier NAT allocates a different port for the
.home path than the relay path. If the carrier assigns ports sequentially,
one of the 10,000 pokes will hit the right port and open Bob's NAT.

Total cost: ~10KB of one-byte packets, sent in <100ms.

### 5. Retransmission succeeds

QUIC retransmits automatically. Alice's next QUIC Initial to the relay
gets forwarded by XDP to Bob. This time Bob's NAT accepts it (the Punch
in step 4 opened it for Alice's IP).

Bob's Quinn processes the QUIC Initial and sends a response **directly**
to Alice at `162.120.248.180:11697`.

### 6. Alice's NAT accepts the response

Bob's response comes from `176.2.178.102:55126`. Alice's NAT checks:
did Alice send to that address? **Yes** — Packet B in step 3 opened
a pinhole for exactly `176.2.178.102:55126`.

Because Bob's home router is cone NAT, his external port is always
55126 regardless of destination. This matches Alice's pinhole.

Connection established. The relay is out of the data path.

## Why it works

Two things make this possible:

1. **Bob's home router is cone NAT.** Same external port for all
   destinations. The port the relay sees is the port Alice sees.

2. **Alice's .home probe opens a pinhole for Bob's exact address.**
   Even though the probe gets dropped, Alice's carrier NAT now
   accepts replies from Bob's IP:port.

The relay only carries data during the 1-2 second window between
Alice's first packet and the Punch completing. After that, QUIC
retransmission discovers the direct path automatically.

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
