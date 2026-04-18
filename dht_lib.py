import asyncio
import hashlib
import json
import os
import time

K          = 20
ALPHA      = 3
ID_BITS    = 160
ID_BYTES   = 20
TIMEOUT_S  = 5.0
REPUBLISH_S = 3600.0

MSG_PING       = 0x01
MSG_PONG       = 0x02
MSG_STORE      = 0x03
MSG_FIND_NODE  = 0x04
MSG_FOUND_NODE = 0x05
MSG_FIND_VALUE = 0x06
MSG_FOUND_VAL  = 0x07


def _sha1(s: str) -> bytes:
    return hashlib.sha1(s.encode()).digest()

def _random_id() -> bytes:
    return os.urandom(ID_BYTES)

def _xor_distance(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def _cmp_distance(d1: bytes, d2: bytes) -> int:
    return (d1 > d2) - (d1 < d2)

def _bucket_index(self_id: bytes, other_id: bytes) -> int:
    d = _xor_distance(self_id, other_id)
    for i, byte in enumerate(d):
        if byte == 0:
            continue
        bit = 7
        b = byte
        while b > 1:
            b >>= 1
            bit -= 1
        return i * 8 + (7 - bit)
    return ID_BITS - 1

def _encode(msg: dict) -> bytes:
    return json.dumps(msg).encode()

def _decode(data: bytes):
    try:
        return json.loads(data)
    except Exception:
        return None


class KBucket:
    def __init__(self):
        self.nodes = []

    def add(self, node: dict):
        idx = next((i for i, n in enumerate(self.nodes) if n['id'] == node['id']), -1)
        if idx >= 0:
            self.nodes.pop(idx)
            self.nodes.append({**node, 'last_seen': time.monotonic()})
            return
        if len(self.nodes) < K:
            self.nodes.append({**node, 'last_seen': time.monotonic()})

    def remove(self, node_id: str):
        self.nodes = [n for n in self.nodes if n['id'] != node_id]

    def closest(self, target_buf: bytes, count: int = K):
        return sorted(
            self.nodes,
            key=lambda n: _xor_distance(bytes.fromhex(n['id']), target_buf),
        )[:count]


class RoutingTable:
    def __init__(self, self_id: bytes):
        self.self_id = self_id
        self.buckets = [KBucket() for _ in range(ID_BITS)]

    def add(self, node: dict):
        if node['id'] == self.self_id.hex():
            return
        idx = _bucket_index(self.self_id, bytes.fromhex(node['id']))
        self.buckets[idx].add(node)

    def remove(self, node_id: str):
        idx = _bucket_index(self.self_id, bytes.fromhex(node_id))
        self.buckets[idx].remove(node_id)

    def closest(self, target, count: int = K):
        target_buf = target if isinstance(target, bytes) else bytes.fromhex(target)
        all_nodes  = [n for b in self.buckets for n in b.nodes]
        return sorted(
            all_nodes,
            key=lambda n: _xor_distance(bytes.fromhex(n['id']), target_buf),
        )[:count]

    @property
    def size(self):
        return sum(len(b.nodes) for b in self.buckets)


class _DHTProtocol(asyncio.DatagramProtocol):
    def __init__(self, dht):
        self._dht = dht

    def connection_made(self, transport):
        self._dht._transport = transport
        self._dht._ready_event.set()

    def datagram_received(self, data: bytes, addr):
        msg = _decode(data)
        if msg:
            self._dht._on_message(msg, addr)

    def error_received(self, exc):
        pass


class SimpleDHT:
    def __init__(self, opts: dict = None):
        opts = opts or {}
        id_buf        = bytes.fromhex(opts['node_id']) if 'node_id' in opts else _random_id()
        self.node_id  = id_buf.hex()
        self._id_buf  = id_buf
        self.port     = opts.get('port', 0)
        self.storage  = {}
        self._table   = RoutingTable(id_buf)
        self._pending = {}
        self._transport      = None
        self._ready_event    = asyncio.Event()
        self._republish_handle = None

    async def start(self):
        loop = asyncio.get_event_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _DHTProtocol(self),
            local_addr=('0.0.0.0', self.port),
        )
        await self._ready_event.wait()
        self.port = self._transport.get_extra_info('sockname')[1]
        self._schedule_republish()

    async def ready(self):
        await self._ready_event.wait()

    def _send(self, ip: str, port: int, msg: dict):
        if self._transport is None:
            return
        try:
            self._transport.sendto(_encode(msg), (ip, port))
        except Exception:
            pass

    async def _rpc(self, ip: str, port: int, msg: dict):
        rpc_id = os.urandom(4).hex()
        loop   = asyncio.get_event_loop()
        fut    = loop.create_future()

        def _timeout():
            if not fut.done():
                fut.set_exception(asyncio.TimeoutError())
            self._pending.pop(rpc_id, None)

        handle = loop.call_later(TIMEOUT_S, _timeout)
        self._pending[rpc_id] = {'future': fut, 'handle': handle}
        self._send(ip, port, {**msg, 'rpcId': rpc_id})
        return await fut

    def _reply(self, ip: str, port: int, rpc_id: str, msg: dict):
        self._send(ip, port, {**msg, 'rpcId': rpc_id})

    def _on_message(self, msg: dict, addr: tuple):
        ip, port = addr

        if msg.get('from'):
            self._table.add({'id': msg['from'], 'ip': ip, 'port': port})

        rpc_id = msg.get('rpcId')
        if rpc_id and rpc_id in self._pending:
            entry = self._pending.pop(rpc_id)
            entry['handle'].cancel()
            if not entry['future'].done():
                entry['future'].set_result(msg)
            return

        msg_type = msg.get('type')

        if msg_type == MSG_PING:
            self._reply(ip, port, rpc_id, {'type': MSG_PONG, 'from': self.node_id})

        elif msg_type == MSG_STORE:
            if msg.get('key') and msg.get('value') is not None:
                self.storage[msg['key']] = msg['value']

        elif msg_type == MSG_FIND_NODE:
            closest = [
                {'id': n['id'], 'ip': n['ip'], 'port': n['port']}
                for n in self._table.closest(msg.get('target', ''), K)
            ]
            self._reply(ip, port, rpc_id, {'type': MSG_FOUND_NODE, 'from': self.node_id, 'nodes': closest})

        elif msg_type == MSG_FIND_VALUE:
            key = msg.get('key')
            if key in self.storage:
                self._reply(ip, port, rpc_id, {'type': MSG_FOUND_VAL, 'from': self.node_id, 'value': self.storage[key]})
            else:
                closest = [
                    {'id': n['id'], 'ip': n['ip'], 'port': n['port']}
                    for n in self._table.closest(bytes.fromhex(key), K)
                ]
                self._reply(ip, port, rpc_id, {'type': MSG_FOUND_NODE, 'from': self.node_id, 'nodes': closest})

    def add_node(self, node: dict):
        node_id = node.get('node_id') or node.get('id')
        ip      = node.get('ip', '127.0.0.1')
        port    = node.get('port')
        if not node_id or not port:
            return
        self._table.add({'id': node_id, 'ip': ip, 'port': port})

    def put(self, key: str, value) -> str:
        key_hash = _sha1(key).hex()
        self.storage[key_hash] = value
        for n in self._table.closest(bytes.fromhex(key_hash), K):
            self._send(n['ip'], n['port'], {'type': MSG_STORE, 'from': self.node_id, 'key': key_hash, 'value': value})
        return key_hash

    def get(self, key: str):
        key_hash = _sha1(key).hex()
        return self.storage.get(key_hash, None)

    async def find_value(self, key: str):
        local = self.get(key)
        if local is not None:
            return local

        key_hash  = _sha1(key).hex()
        key_buf   = bytes.fromhex(key_hash)
        visited   = set()
        shortlist = self._table.closest(key_buf, ALPHA)

        for _ in range(20):
            to_query = [n for n in shortlist if n['id'] not in visited][:ALPHA]
            if not to_query:
                break

            results = await asyncio.gather(
                *[self._rpc(n['ip'], n['port'], {'type': MSG_FIND_VALUE, 'from': self.node_id, 'key': key_hash})
                  for n in to_query],
                return_exceptions=True,
            )

            for n, result in zip(to_query, results):
                visited.add(n['id'])
                if isinstance(result, Exception):
                    continue
                if result.get('type') == MSG_FOUND_VAL:
                    self.storage[key_hash] = result['value']
                    return result['value']
                if result.get('type') == MSG_FOUND_NODE:
                    for nn in result.get('nodes', []):
                        self._table.add(nn)
                        if nn['id'] not in visited:
                            shortlist.append(nn)

            shortlist = sorted(
                [n for n in shortlist if n['id'] not in visited],
                key=lambda n: _xor_distance(bytes.fromhex(n['id']), key_buf),
            )

        return None

    async def bootstrap(self, nodes: list = None):
        for n in (nodes or []):
            self.add_node(n)

        closest = self._table.closest(self._id_buf, ALPHA)
        results = await asyncio.gather(
            *[self._rpc(n['ip'], n['port'], {'type': MSG_FIND_NODE, 'from': self.node_id, 'target': self.node_id})
              for n in closest],
            return_exceptions=True,
        )
        for result in results:
            if not isinstance(result, Exception):
                for nn in result.get('nodes', []):
                    self._table.add(nn)

    def _schedule_republish(self):
        loop = asyncio.get_event_loop()

        def _republish():
            for key_hash, value in self.storage.items():
                for n in self._table.closest(bytes.fromhex(key_hash), K):
                    self._send(n['ip'], n['port'], {'type': MSG_STORE, 'from': self.node_id, 'key': key_hash, 'value': value})
            self._republish_handle = loop.call_later(REPUBLISH_S, _republish)

        self._republish_handle = loop.call_later(REPUBLISH_S, _republish)

    def destroy(self):
        if self._republish_handle:
            self._republish_handle.cancel()
        if self._transport:
            self._transport.close()
