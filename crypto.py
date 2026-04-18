import hashlib
import struct
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from constants import TAG_LEN, NONCE_LEN


def generate_x25519(seed=None):
    if seed is not None:
        if isinstance(seed, str):
            seed = bytes.fromhex(seed)
        derived = hashlib.sha256(seed).digest()
        private_key = X25519PrivateKey.from_private_bytes(derived)
    else:
        private_key = X25519PrivateKey.generate()

    pub_raw = private_key.public_key().public_bytes_raw()
    return {'private_key': private_key, 'pub_raw': pub_raw}


def derive_session(my_priv, their_pub_raw: bytes) -> dict:
    their_pub = X25519PublicKey.from_public_bytes(their_pub_raw)
    shared    = my_priv.exchange(their_pub)

    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=68,
        salt=b'',
        info=b'p2p-v12-session',
    ).derive(shared)

    return {
        'send_key':   derived[0:32],
        'recv_key':   derived[32:64],
        'session_id': struct.unpack('>I', derived[64:68])[0],
        'send_ctr':   0,
    }


def encrypt(sess: dict, plaintext: bytes) -> bytes:
    nonce = struct.pack('>I', sess['session_id']) + struct.pack('>Q', sess['send_ctr'])
    sess['send_ctr'] += 1
    ct_tag = ChaCha20Poly1305(sess['send_key']).encrypt(nonce, plaintext, None)
    return nonce + ct_tag


def decrypt(sess: dict, buf: bytes):
    if len(buf) < NONCE_LEN + TAG_LEN:
        return None
    nonce      = buf[:NONCE_LEN]
    ct_and_tag = buf[NONCE_LEN:]
    try:
        return ChaCha20Poly1305(sess['recv_key']).decrypt(nonce, ct_and_tag, None)
    except Exception:
        return None
