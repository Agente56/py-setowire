# Setowire

A lightweight P2P networking library built on UDP. No central servers, no brokers — peers find each other and communicate directly.

Built to be simple enough that the protocol fits in your head.

---

## Why

Most P2P libraries are either too heavy or too tied to a specific runtime. Setowire is small, auditable, and designed to be reimplemented in any language. The wire protocol is documented and intentionally minimal.

---

## Requirements

- Python 3.11+
- `cryptography` package (X25519 + ChaCha20-Poly1305)

```bash
# Standard
pip install cryptography

# Termux (Android)
pkg install python
pip install cryptography

# Debian / Ubuntu
sudo apt install python3 python3-pip
pip install cryptography

# Arch
sudo pacman -S python python-pip
pip install cryptography

# macOS (Homebrew)
brew install python
pip install cryptography
```

---

## How it works

Peers discover each other through multiple strategies running in parallel — whichever works first wins:

- **DHT** — decentralized peer discovery by topic
- **Piping servers** — HTTPS rendezvous for peers behind strict NATs
- **LAN multicast** — instant discovery on local networks
- **HTTP bootstrap nodes** — fallback seed servers
- **Peer cache** — remembers peers from previous sessions

Once connected, all traffic is encrypted end-to-end with X25519 + ChaCha20-Poly1305. Peers that detect they have a full-cone NAT automatically become relays for others.

---

## File structure

```
constants.py   — all tuneable parameters and frame type definitions
crypto.py      — X25519 key exchange, ChaCha20-Poly1305 encrypt/decrypt
structs.py     — BloomFilter, LRU, RingBuffer, PayloadCache
framing.py     — packet fragmentation, jitter buffer, batch UDP sender
dht_lib.py     — minimal DHT for decentralized topic-based discovery
peer.py        — per-peer state: queues, congestion control, multipath
swarm.py       — main class: discovery, mesh, relay, sync, gossip
__init__.py    — entry point
chat.py        — example terminal chat app
```

---

## Quick start

```python
import asyncio
import hashlib
from swarm import Swarm

async def main():
    swarm = Swarm()
    topic = hashlib.sha256(b'my-topic').digest()

    await swarm.join(topic, announce=True, lookup=True)

    swarm.on('connection', lambda peer: peer.write(b'hello'))
    swarm.on('data', lambda data, peer: print('got:', data))

    await asyncio.sleep(3600)

asyncio.run(main())
```

---

## API

### `Swarm(opts?)`

| option | default | description |
|---|---|---|
| `seed` | random | hex string — deterministic identity |
| `max_peers` | 100 | max simultaneous connections |
| `relay` | False | force relay mode regardless of NAT |
| `bootstrap` | [] | `["host:port"]` bootstrap nodes |
| `seeds` | [] | additional hardcoded seed peers |

### `await swarm.join(topic, announce=True, lookup=True)`

Start announcing and/or looking up peers on a topic. `topic` is a `bytes` object (usually a hash).

### `swarm.broadcast(data)`

Send data to all connected peers. Returns number of peers reached.

### `swarm.store(key, value)`

Store a value locally and announce it to the mesh.

### `await swarm.fetch(key, timeout?)`

Fetch a value — returns local copy immediately or pulls from the network.

### `await swarm.destroy()`

Graceful shutdown. Notifies peers and closes the socket.

### Events

| event | args | description |
|---|---|---|
| `connection` | `peer` | new peer connected |
| `data` | `data, peer` | message received |
| `disconnect` | `peer_id` | peer dropped |
| `sync` | `key, value` | value received from network |
| `nat` | — | public address discovered |

---

## Protocol

The wire protocol is plain UDP. Each packet starts with a 1-byte frame type:

| byte | type | description |
|---|---|---|
| `0x01` | DATA | encrypted application data |
| `0x03` | PING | keepalive + RTT measurement |
| `0x04` | PONG | keepalive reply |
| `0x0A` | GOAWAY | graceful disconnect |
| `0x0B` | FRAG | fragment of a large message |
| `0x13` | BATCH | multiple frames in one datagram |
| `0x20` | RELAY_ANN | peer announcing itself as relay |
| `0x21` | RELAY_REQ | request introduction via relay |
| `0x22` | RELAY_FWD | relay forwarding an introduction |
| `0x30` | PEX | peer exchange |

Handshake is two frames: `0xA1` (hello) and `0xA2` (hello ack). Each carries the sender's ID and raw X25519 public key. After that, all data is encrypted.

The session key derivation label is `p2p-v12-session`. The peer with the lexicographically lower ID uses the first 32 bytes as send key; the other peer flips them.

---

## Chat example

```bash
python -m chat <nick> [room]
python -m chat alice myroom
```

Commands: `/peers`, `/nat`, `/quit`

---

## License

MIT

