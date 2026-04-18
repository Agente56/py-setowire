import time
from constants import BLOOM_BITS, BLOOM_HASHES, BLOOM_ROTATE


def _now_ms():
    return time.monotonic() * 1000


class BloomFilter:
    def __init__(self, bits=BLOOM_BITS, num_hashes=BLOOM_HASHES):
        self._bits        = bits
        self._hashes      = num_hashes
        size              = bits >> 3
        self._cur         = bytearray(size)
        self._old         = bytearray(size)
        self._count       = 0
        self._last_rotate = _now_ms()

    def _rotate(self):
        if _now_ms() - self._last_rotate < BLOOM_ROTATE:
            return
        self._old         = self._cur
        self._cur         = bytearray(len(self._cur))
        self._count       = 0
        self._last_rotate = _now_ms()

    def _positions(self, key):
        if isinstance(key, str):
            key = key.encode()
        out = []
        for i in range(self._hashes):
            h = (2166136261 + i * 16777619) & 0xFFFFFFFF
            for b in key:
                h ^= b
                h  = (h * 16777619) & 0xFFFFFFFF
            out.append(h % self._bits)
        return out

    def add(self, key):
        self._rotate()
        for pos in self._positions(key):
            self._cur[pos >> 3] |= (1 << (pos & 7))
        self._count += 1

    def has(self, key):
        positions = self._positions(key)
        in_cur = all(self._cur[p >> 3] & (1 << (p & 7)) for p in positions)
        if in_cur:
            return True
        return all(self._old[p >> 3] & (1 << (p & 7)) for p in positions)

    def seen(self, key):
        if self.has(key):
            return True
        self.add(key)
        return False


class LRU:
    def __init__(self, max_size, ttl=None):
        self._m   = {}
        self._max = max_size
        self._ttl = ttl

    def has(self, k):
        return k in self._m

    def add(self, k, v):
        now = _now_ms()
        if self._ttl is not None:
            to_del = []
            for i, (key, entry) in enumerate(self._m.items()):
                if i > 300:
                    break
                if now - entry['t'] > self._ttl:
                    to_del.append(key)
            for key in to_del:
                del self._m[key]
        if len(self._m) >= self._max:
            del self._m[next(iter(self._m))]
        self._m[k] = {'v': v, 't': now}

    def get(self, k):
        e = self._m.get(k)
        return e['v'] if e else None

    def seen(self, k):
        if self.has(k):
            return True
        self.add(k, 1)
        return False

    def delete(self, k):
        self._m.pop(k, None)

    def keys(self):
        return self._m.keys()

    def entries(self):
        return [(k, e['v']) for k, e in self._m.items()]

    @property
    def size(self):
        return len(self._m)


class RingBuffer:
    def __init__(self, size):
        if size & (size - 1):
            raise ValueError(f'RingBuffer: size must be a power of 2, got {size}')
        self._buf  = [None] * size
        self._mask = size - 1
        self._head = 0
        self._tail = 0

    @property
    def length(self):
        return (self._tail - self._head) & self._mask

    @property
    def full(self):
        return ((self._tail + 1) & self._mask) == (self._head & self._mask)

    @property
    def empty(self):
        return self._head == self._tail

    def push(self, item):
        if self.full:
            self._head = (self._head + 1) & self._mask
        self._buf[self._tail] = item
        self._tail = (self._tail + 1) & self._mask

    def shift(self):
        if self.empty:
            return None
        item = self._buf[self._head]
        self._buf[self._head] = None
        self._head = (self._head + 1) & self._mask
        return item

    def clear(self):
        self._head = 0
        self._tail = 0


class PayloadCache:
    def __init__(self, size):
        self._keys = [None] * size
        self._vals = [None] * size
        self._map  = {}
        self._mask = size - 1
        self._head = 0

    def set(self, msg_id, frame):
        old = self._keys[self._head]
        if old is not None:
            self._map.pop(old, None)
        self._keys[self._head] = msg_id
        self._vals[self._head] = frame
        self._map[msg_id]      = self._head
        self._head = (self._head + 1) & self._mask

    def get(self, msg_id):
        idx = self._map.get(msg_id)
        return self._vals[idx] if idx is not None else None

    def has(self, msg_id):
        return msg_id in self._map
