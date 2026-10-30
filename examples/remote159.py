"""Official Android 1.59 protocol, offline only; never sends vehicle commands."""
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
import base64
import hashlib
import json
import re
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

ROOT = Path(__file__).resolve().parents[1]
PARAMETERS = json.loads((ROOT / 'resources/remote-159.json').read_text())
API_BASE = 'https://tbox.zontesmotor.com/zontespkeapp/api'
TCP_HOST, TCP_PORT = 'www.sharpon.com', 4510


def _ascii_field(value, maximum, name):
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or any(
        not 0x21 <= ord(c) <= 0x7e or c in ',#' for c in value
    ):
        raise ValueError(f'{name}: invalid ASCII field')


def _hex(value, size):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-fA-F]{%d}' % (size * 2), value):
        raise ValueError(f'expected {size} hexadecimal bytes')
    return bytes.fromhex(value)


def cbc_base64(kind, plaintext):
    """Hex-decode key/IV, ASCII input, AES-128-CBC + PKCS#7, standard Base64."""
    p = PARAMETERS['wrapping'][kind]
    return base64.b64encode(AES.new(_hex(p['key'], 16), AES.MODE_CBC, _hex(p['iv'], 16)).encrypt(
        pad(plaintext.encode('ascii'), 16)
    )).decode('ascii')


def signature(seed_hex, nonce, timestamp):
    """Return two encrypted fields separated by one comma (24 and 64 chars)."""
    if not re.fullmatch('[0-9]{8}', nonce) or not re.fullmatch('[0-9]{14}', timestamp):
        raise ValueError('nonce requires 8 decimal digits; time requires 14 decimal digits')
    key = bytearray(AES.new(_hex(PARAMETERS['seed_key'], 16), AES.MODE_ECB).encrypt(_hex(seed_hex, 16)))
    # Although nonce characters are decimal digits, Android parses them as HEX bytes.
    for i, value in enumerate(bytes.fromhex(nonce)):
        key[12 + i] ^= value
    inner = AES.new(bytes(key), AES.MODE_ECB).encrypt(timestamp.encode('ascii') + b'\0\0').hex()
    return cbc_base64('nonce', nonce) + ',' + cbc_base64('signature', inner)


def transport_device_id(device_uuid):
    """Independent stable 18-byte device tag; not the official UTDevice SDK generator.

    This representation was accepted in authentication and a signed read. A port
    may use its own persistent per-install tag; never copy a real user's UTDID.
    """
    return base64.b64encode(hashlib.sha256(device_uuid.encode('utf-8')).digest()[:18]).decode('ascii')


def encode_transport(inner, device_tag):
    if not re.fullmatch('[A-Za-z0-9+/]{24}', device_tag):
        raise ValueError('device tag must be the Base64 representation of 18 bytes')
    return cbc_base64('packet', inner + ',' + cbc_base64('device', device_tag)).encode('ascii')


@dataclass(frozen=True)
class Packets:
    authentication_plaintext: str
    command_plaintext: str
    authentication: bytes
    command: bytes


def build_packets(command, user_code, device_id, mcuid, pke_code, *,
                  auth_nonce=None, auth_time=None, command_nonce=None, command_time=None):
    """Build in memory. Physical execution of find/lock/unlock remains owner-tested."""
    prefixes = {'refresh': '*RE', 'find': '*UF', 'lock': '*ULoc', 'unlock': '*UClear'}
    if command not in prefixes:
        raise ValueError('this current example exposes refresh/find/lock/unlock only')
    _ascii_field(user_code, 32, 'UserCode')
    _ascii_field(device_id, 64, 'device UUID')
    _ascii_field(pke_code, 64, 'PKECode')
    _hex(mcuid, 16)
    now = lambda: datetime.now(timezone(timedelta(hours=8))).strftime('%Y%m%d%H%M%S')
    random_nonce = lambda: ''.join(str(secrets.randbelow(10)) for _ in range(8))
    auth_nonce = random_nonce() if auth_nonce is None else auth_nonce
    command_nonce = random_nonce() if command_nonce is None else command_nonce
    auth_time = now() if auth_time is None else auth_time
    command_time = now() if command_time is None else command_time
    seed = ''.join(c for c in user_code if c in '0123456789')[:32].ljust(32, '0')
    auth = f'*UL,{user_code},{device_id},0.0,0.0,{signature(seed, auth_nonce, auth_time)},1.59#'
    cmd = f'{prefixes[command]},{user_code},{pke_code},{signature(mcuid, command_nonce, command_time)}'
    tag = transport_device_id(device_id)
    return Packets(auth, cmd, encode_transport(auth, tag), encode_transport(cmd, tag))
