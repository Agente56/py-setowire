import asyncio
import struct
import time

from structs import RingBuffer
from framing import FragmentAssembler, JitterBuffer, xor_hash, fragment_payload
from crypto import encrypt
from constants import (
    RTT_INIT, QUEUE_CTRL, QUEUE_DATA,
    CWND_INIT, CWND_MAX, CWND_DECAY,
    RATE_PER_SEC, RATE_BURST,
    MAX_ADDRS_PEER, F_DATA, F_FRAG,
)

def _now_ms() -> float:
    return time.monotonic() * 1000

class Peer:
    def __init__(self, swarm, peer_id: str, addr: str):
        self.id             = peer_id
        self.remote_address = addr
        self._swarm         = swarm
        self._addrs         = {addr: RTT_INIT}
        self._best          = addr
        self._seen          = _now_ms()
        self._open          = True
        self.in_mesh        = False
        self._mesh_time     = 0
        self.score          = 0
        self.rtt            = RTT_INIT
        self.bandwidth      = 0
        self._session       = None
        self._their_pub_raw = None
        self._ctrl_queue    = RingBuffer(QUEUE_CTRL)
        self._data_queue    = RingBuffer(QUEUE_DATA)
        self._draining      = False
        self._fragger       = FragmentAssembler()
        self._send_seq      = 0

        def _on_deliver(plain: bytes):
            msg_key = xor_hash(plain)
            if self._swarm._bloom.seen(msg_key):
                return
            self._swarm._emit('data', plain, self)
            self._swarm._flood_mesh(plain, self.id)

        self._jitter        = JitterBuffer(_on_deliver)
        self._cwnd          = CWND_INIT
        self._inflight      = 0
        self._last_loss     = 0.0
        self._tokens        = RATE_BURST
        self._last_rate     = _now_ms()
        self._last_ping_sent = 0.0
        self._last_pong     = _now_ms()
        self._loss_signaled = False
        self._bytes_sent    = 0
        self._bytes_window  = _now_ms()
        self._listeners: dict[str, list] = {}

    def on(self, event: str, cb):
        self._listeners.setdefault(event, []).append(cb)

    def emit(self, event: str, *args):
        for cb in self._listeners.get(event, []):
            cb(*args)

    def write_ctrl(self, data: bytes) -> bool:
        if not self._open:
            return False
        self._ctrl_queue.push(data)
        if not self._draining:
            asyncio.get_event_loop().call_soon(self._drain)
        return True

    def write(self, data: bytes) -> bool:
        if not self._open or not self._session:
            return False
        self._data_queue.push(data)
        if not self._draining:
            asyncio.get_event_loop().call_soon(self._drain)
        return True

    def _enqueue(self, raw: bytes):
        self.write(raw)

    def _drain(self):
        self._draining = True
        while not self._ctrl_queue.empty:
            raw = self._ctrl_queue.shift()
            if raw:
                self._send_raw(raw)
        while not self._data_queue.empty and self._inflight < self._cwnd:
            raw = self._data_queue.shift()
            if raw is None:
                break
            self._send_encrypted(raw)
        if not self._data_queue.empty and self._inflight < self._cwnd:
            asyncio.get_event_loop().call_soon(self._drain)
        self._draining = False

    def _send_encrypted(self, plain: bytes):
        if not self._session:
            return
        now             = _now_ms()
        delta           = (now - self._last_rate) / 1000
        self._tokens    = min(RATE_BURST, self._tokens + delta * RATE_PER_SEC)
        self._last_rate = now
        if self._tokens < 1:
            return
        self._tokens -= 1
        frags = fragment_payload(plain)
        if frags:
            for frag in frags['frags']:
                self._send_raw(bytes([F_FRAG]) + frag)
            return
        seq_buf = struct.pack('>I', self._send_seq) + plain
        self._send_seq += 1
        ct    = encrypt(self._session, seq_buf)
        frame = bytes([F_DATA]) + ct
        self._send_raw(frame)
        self._inflight += 1
        self._bytes_sent += len(frame)
        elapsed = (_now_ms() - self._bytes_window) / 1000
        if elapsed >= 1:
            self.bandwidth     = self._bytes_sent / elapsed
            self._bytes_sent   = 0
            self._bytes_window = _now_ms()

    def _send_raw(self, buf: bytes):
        ip, port = self._best.rsplit(':', 1)
        self._swarm._batch.send(ip, int(port), buf)

    def _send_raw_now(self, buf: bytes):
        ip, port = self._best.rsplit(':', 1)
        self._swarm._batch.send_now(ip, int(port), buf)

    def _on_ack(self):
        if self._inflight > 0:
            self._inflight -= 1
        if self._cwnd < CWND_MAX:
            self._cwnd = min(CWND_MAX, self._cwnd + 1)
        if not self._data_queue.empty:
            asyncio.get_event_loop().call_soon(self._drain)

    def _on_loss(self):
        now = _now_ms()
        if now - self._last_loss < 1000:
            return
        self._last_loss = now
        self._cwnd      = max(1, int(self._cwnd * CWND_DECAY))
        self._inflight  = min(self._inflight, self._cwnd)

    def _touch(self, addr: str | None, rtt: float | None = None):
        self._seen          = _now_ms()
        self._last_pong     = _now_ms()
        self._loss_signaled = False
        if addr:
            r = rtt if rtt is not None else self.rtt
            self._addrs[addr] = r
            if len(self._addrs) > MAX_ADDRS_PEER:
                worst = max(self._addrs, key=lambda a: self._addrs[a])
                if worst != addr:
                    del self._addrs[worst]
                    self._swarm._addr_to_id.pop(worst, None)
            best                = min(self._addrs, key=lambda a: self._addrs[a])
            self._best          = best
            self.remote_address = best
            self._swarm._addr_to_id[addr] = self.id

    def _score_up(self, n: int = 1):
        self.score = min(1000, self.score + n)

    def _score_down(self, n: int = 2):
        self.score = max(-1000, self.score - n)

    def destroy(self):
        self._open = False
        for addr in list(self._addrs.keys()):
            self._swarm._addr_to_id.pop(addr, None)
        self._fragger.clear()
        self._jitter.clear()
        self._ctrl_queue.clear()
        self._data_queue.clear()
        self.emit('close')
