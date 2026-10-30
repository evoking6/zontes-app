"""Offline mPaaS request builder. Accepts caller-supplied authorized configuration.

No sockets or login requests are made. Keep real bodies, tokens and keys out of logs.
"""
from dataclasses import dataclass
import base64
import hashlib
import json
import uuid
from urllib.parse import urlsplit

ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/'


def timestamp(milliseconds):
    if not isinstance(milliseconds, int) or milliseconds < 0:
        raise ValueError('nonnegative integer milliseconds required')
    out = ''
    while milliseconds:
        out = ALPHABET[milliseconds % 64] + out
        milliseconds //= 64
    return out or '0'


def sign_body(body, operation, stamp, secret):
    """secret is 32 UTF-8/ASCII bytes, not HEX_DECODE(secret)."""
    if len(secret.encode('utf-8')) != 32:
        raise ValueError('this sample requires a 32-byte signing secret')
    content = 'Operation-Type=' + operation + '&Request-Data=' + base64.b64encode(body).decode() + '&Ts=' + stamp
    return hashlib.md5((secret + '&' + content).encode('utf-8')).hexdigest()


@dataclass(frozen=True)
class RPCRequest:
    gateway: str
    headers: dict
    body: bytes


def build_request(configuration, fields, device_id, milliseconds, trace_id=None):
    """Build only in memory. configuration/vectors use fake keys in this repository."""
    cfg = configuration
    if urlsplit(cfg['gateway']).scheme != 'https' or not device_id:
        raise ValueError('HTTPS and persistent device identity required')
    body = json.dumps([{'_requestBody': fields}], ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    stamp = timestamp(milliseconds)
    tag = base64.b64encode(hashlib.sha256(device_id.encode()).digest()[:18]).decode()
    headers = dict(cfg['headers'])
    headers.update({'Content-Type': 'application/json', 'Accept': 'application/json', 'Accept-Encoding': 'gzip',
                    'Operation-Type': cfg['operation'], 'Ts': stamp, 'Sign': sign_body(body, cfg['operation'], stamp, cfg['secret']),
                    'signType': '0', 'x-request-deviceid': tag, 'Did': cfg['did_prefix'] + tag + cfg['did_suffix'],
                    'RpcId': '1', 'TRACEID': trace_id or uuid.uuid4().hex})
    return RPCRequest(cfg['gateway'], headers, body)


def decode_response(http_status, headers, body):
    """body must already be decompressed by the HTTP client."""
    lower = {k.lower(): v for k, v in headers.items()}
    gateway = lower.get('result-status')
    if http_status != 200 or gateway != '1000':
        raise ValueError(f'gateway rejected request: HTTP {http_status}, status {gateway}')
    result = json.loads(body)
    if result.get('code') != 200:
        raise ValueError('business request rejected')
    return result
