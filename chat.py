import asyncio
import hashlib
import json
import os
import sys
import json as _json

from swarm import Swarm

SEED_FILE = './identity.json'


def _load_or_create_seed() -> str:
    if os.path.exists(SEED_FILE):
        with open(SEED_FILE) as f:
            return json.load(f)['seed']
    seed = os.urandom(32).hex()
    with open(SEED_FILE, 'w') as f:
        json.dump({'seed': seed}, f)
    return seed


def _ts() -> str:
    import datetime
    now = datetime.datetime.now()
    return f'{now.hour:02d}:{now.minute:02d}'


def _sys(msg: str):
    print(f'\x1b[90m[{_ts()}] * {msg}\x1b[0m')


def _msg(nick: str, from_nick: str, text: str):
    color = '\x1b[32m' if from_nick == nick else '\x1b[35m'
    print(f'\x1b[90m[{_ts()}]\x1b[0m {color}{from_nick}\x1b[0m: {text}')


async def main():
    args = sys.argv[1:]
    if not args:
        print('usage: python -m p2p_swarm.chat <nick> [room]')
        sys.exit(1)

    nick = args[0]
    room = args[1] if len(args) > 1 else 'general'
    seed = _load_or_create_seed()

    swarm    = Swarm({'seed': seed})
    topic    = hashlib.sha256(f'chat:{room}'.encode()).digest()
    nicks    = {}
    handshook = set()

    _sys(f'starting... nick={nick} room={room}')

    swarm.on('nat',     lambda: _sys(f'nat={swarm.nat_type} addr={swarm.public_address or "LAN"}'))
    swarm.on('nattype', lambda: _sys(f'nat type refined: {swarm.nat_type}'))

    def on_connection(peer):
        peer.write(json.dumps({'type': 'JOIN', 'nick': nick}).encode())

    swarm.on('connection', on_connection)

    def on_data(data: bytes, peer):
        try:
            m = json.loads(data)
        except Exception:
            return

        if m.get('_selfId') == swarm._id:
            return

        if m.get('type') == 'JOIN':
            fresh = peer.id not in nicks
            nicks[peer.id] = m['nick']
            if fresh:
                _sys(f"{m['nick']} joined")
            if peer.id not in handshook:
                handshook.add(peer.id)
                try:
                    peer.write(json.dumps({'type': 'JOIN', 'nick': nick}).encode())
                except Exception:
                    pass
            return

        if m.get('type') == 'MSG':
            _msg(nick, m['nick'], m['text'])
            return

        if m.get('type') == 'LEAVE':
            _sys(f"{nicks.get(peer.id) or m.get('nick')} left")
            nicks.pop(peer.id, None)

    swarm.on('data', on_data)

    def on_disconnect(peer_id: str):
        name = nicks.get(peer_id) or peer_id[:8]
        _sys(f'{name} disconnected')
        nicks.pop(peer_id, None)
        handshook.discard(peer_id)

    swarm.on('disconnect', on_disconnect)

    await swarm.join(topic, announce=True, lookup=True)
    _sys(f'ready | nat={swarm.nat_type} | addr={swarm.public_address or "LAN"}')

    loop = asyncio.get_event_loop()
    _main_task = asyncio.current_task()
    _quitting  = False

    def _sigint_handler():
        nonlocal _quitting
        if _quitting:
            return
        _quitting = True
        payload = json.dumps({'type': 'LEAVE', 'nick': nick}).encode()
        swarm.broadcast(payload)
        loop.call_later(0.3, _main_task.cancel)

    loop.add_signal_handler(__import__('signal').SIGINT, _sigint_handler)

    def _handle_input(line: str):
        text = line.strip()
        if not text:
            return

        if text == '/peers':
            _sys(f'{swarm.size} peer(s) connected')
            for p in swarm.peers:
                _sys(f'  {p.id[:8]} nick={nicks.get(p.id, "?")} rtt={round(p.rtt)}ms mesh={p.in_mesh}')
            return

        if text == '/nat':
            _sys(f'nat={swarm.nat_type} addr={swarm.public_address or "LAN"}')
            return

        if text == '/quit':
            payload = json.dumps({'type': 'LEAVE', 'nick': nick}).encode()
            swarm.broadcast(payload)
            async def _quit():
                await asyncio.sleep(0.3)
                await swarm.destroy()
                sys.exit(0)
            asyncio.ensure_future(_quit())
            return

        payload = json.dumps({'type': 'MSG', 'nick': nick, 'text': text, '_selfId': swarm._id}).encode()
        if not swarm.broadcast(payload):
            for p in swarm.peers:
                if p._session:
                    p.write(payload)
        _msg(nick, nick, text)

    loop.call_later(0.5, lambda: _sys('commands: /peers  /nat  /quit'))

    reader = asyncio.StreamReader()
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)

    print(f'\x1b[32m{nick}\x1b[0m > ', end='', flush=True)

    while True:
        try:
            line = await reader.readline()
            if not line:
                break
            _handle_input(line.decode())
            print(f'\x1b[32m{nick}\x1b[0m > ', end='', flush=True)
        except (EOFError, KeyboardInterrupt, asyncio.CancelledError):
            break

    await swarm.destroy()


if __name__ == '__main__':
    asyncio.run(main())
