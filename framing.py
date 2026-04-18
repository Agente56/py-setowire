import asyncio
import os
import struct
import threading

from constants import (
    MAX_PAYLOAD, FRAG_HDR, FRAG_DATA_MAX, FRAG_TIMEOUT,
    BATCH_MTU, BATCH_INTERVAL, F_BATCH,
)


class FragmentAssembler:
    def __init__(self):
        self._pending = {}

    def add(self, frag_id: bytes, frag_idx: int, frag_total: int, data: bytes):
        key = frag_id.hex()
        if key not in self._pending:
            loop = asyncio.get_event_loop()
            handle = loop.call_later(FRAG_TIMEOUT / 1000, lambda k=key: self._pending.pop(k, None))
            self._pending[key] = {'total': frag_total, 'pieces': {}, 'handle': handle}

        entry = self._pending[key]
        entry['pieces'][frag_idx] = data

        if len(entry['pieces']) == entry['total']:
            entry['handle'].cancel()
            self._pending.pop(key)
            return b''.join(entry['pieces'][i] for i in range(entry['total']))

        return None

    def clear(self):
        for e in self._pending.values():
            e['handle'].cancel()
        self._pending.clear()


def fragment_payload(payload: bytes):
    if len(payload) <= MAX_PAYLOAD:
        return None

    frag_id = os.urandom(8)
    total   = -(-len(payload) // FRAG_DATA_MAX)  # ceil
    frags   = []

    for i in range(total):
        chunk = payload[i * FRAG_DATA_MAX:(i + 1) * FRAG_DATA_MAX]
        hdr   = frag_id + struct.pack('>HH', i, total)  # 8 + 2 + 2 = 12 bytes
        frags.append(hdr + chunk)

    return {'frag_id': frag_id, 'total': total, 'frags': frags}


class JitterBuffer:
    def __init__(self, on_deliver):
        self._buf     = {}
        self._next    = 0
        self._deliver = on_deliver
        self._handles = {}

    def push(self, seq: int, data: bytes):
        if seq < self._next:
            return
        if seq == self._next:
            self._deliver(data)
            self._next += 1
            self._flush()
        else:
            self._buf[seq] = data
            loop = asyncio.get_event_loop()
            self._handles[seq] = loop.call_later(0.05, lambda s=seq: self._force(s))

    def _force(self, seq: int):
        if seq in self._buf and seq >= self._next:
            self._next = seq
            self._deliver(self._buf.pop(seq))
            self._handles.pop(seq, None)
            self._flush()

    def _flush(self):
        while self._next in self._buf:
            h = self._handles.pop(self._next, None)
            if h:
                h.cancel()
            self._deliver(self._buf.pop(self._next))
            self._next += 1

    def clear(self):
        for h in self._handles.values():
            h.cancel()
        self._buf.clear()
        self._handles.clear()


def xor_hash(buf: bytes) -> str:
    a = 0x811C9DC5
    b = 0x811C9DC5
    for i, byte in enumerate(buf):
        if i & 1:
            b ^= byte
            b = (b * 0x01000193) & 0xFFFFFFFF
        else:
            a ^= byte
            a = (a * 0x01000193) & 0xFFFFFFFF
    return struct.pack('>II', a, b).hex()


class BatchSender:
    def __init__(self, transport):
        self._transport = transport
        self._pending   = {}
        self._handle    = None

    def send(self, ip: str, port: int, buf: bytes):
        key = f'{ip}:{port}'
        self._pending.setdefault(key, []).append(buf)
        if self._handle is None:
            loop = asyncio.get_event_loop()
            self._handle = loop.call_later(BATCH_INTERVAL / 1000, self._flush)

    def send_now(self, ip: str, port: int, buf: bytes):
        try:
            self._transport.sendto(buf, (ip, int(port)))
        except Exception:
            pass

    def _flush(self):
        self._handle = None
        for key, bufs in self._pending.items():
            ip, port_s = key.rsplit(':', 1)
            port  = int(port_s)
            batch = []
            size  = 0
            for b in bufs:
                if size + len(b) + 2 > BATCH_MTU and batch:
                    self._send_batch(ip, port, batch)
                    batch = []
                    size  = 0
                batch.append(b)
                size += len(b) + 2
            if batch:
                self._send_batch(ip, port, batch)
        self._pending.clear()

    def _send_batch(self, ip: str, port: int, bufs: list):
        if len(bufs) == 1:
            try:
                self._transport.sendto(bufs[0], (ip, port))
            except Exception:
                pass
            return
        parts = [bytes([F_BATCH, len(bufs)])]
        for b in bufs:
            parts.append(struct.pack('>H', len(b)))
            parts.append(b)
        out = b''.join(parts)
        try:
            self._transport.sendto(out, (ip, port))
        except Exception:
            pass

    def destroy(self):
        if self._handle:
            self._handle.cancel()
            self._flush()
