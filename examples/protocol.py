"""Offline Zontes interoperability examples. No sockets, BLE or account access.

The default RSA key is the key extracted from ShiRide 1.3.0. Fixed randomness
is accepted only to compare native fixtures; omit it in application code.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
import json
import re
import secrets
from urllib.parse import urlencode

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / "resources/whitebox.json").read_text())
TABLES = (ROOT / "resources/c9x_tables.bin").read_bytes()
if len(TABLES) != 372736 or hashlib.sha256(TABLES).hexdigest() != CONFIG["tables_sha256"]:
    raise ValueError("whitebox table length/hash mismatch")
COMMANDS = ("lock", "unlock", "find", "refresh", "diagnose", "freeze", "unfreeze", "track", "untrack")
PREFIXES = ("*ULoc", "*UClear", "*UF", "*RE", "*UKEY", "*UFreeze", "*UFreeze", "*UChase", "*UChase")
BLE_ACTIONS = {"1": "lock", "2": "unlock", "5": "fuel_lid", "6": "seat"}
API_BASE = "https://www.ifino.com:8081/zontespkeapp/api"
BLE_SERVICE = "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
BLE_WRITE = "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"
BLE_NOTIFY = "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"


def field(value: str, maximum: int, name: str) -> None:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or any(
        not 0x21 <= ord(c) <= 0x7e or c in ",#" for c in value
    ):
        raise ValueError(f"{name}: expected 1..{maximum} ASCII bytes, excluding space/comma/#")


def hex_bytes(value: str, length: int, name: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{%d}" % (length * 2), value):
        raise ValueError(f"{name}: expected exactly {length * 2} hex digits")
    return bytes.fromhex(value)


def whitebox_block(block: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("whitebox input must be exactly 16 bytes")
    state = block
    for round_index in range(9):
        output = bytearray()
        for column in range(4):
            words = []
            for position in CONFIG["permutation"]["round"][column * 4:column * 4 + 4]:
                offset = ((round_index * 16 + position) * 256 + state[position]) * 4
                words.append(TABLES[offset:offset + 4])
            for row in range(4):
                a, b, c, d = (word[row] for word in words)
                base = 0x24000 + round_index * 0x6000 + (column * 4 + row) * 0x600
                high_ab = TABLES[base + (a & 0xf0) + (b >> 4)]
                high_cd = TABLES[base + 0x100 + (c & 0xf0) + (d >> 4)]
                high = TABLES[base + 0x200 + (high_ab << 4) + high_cd]
                low_ab = TABLES[base + 0x300 + ((a & 15) << 4) + (b & 15)]
                low_cd = TABLES[base + 0x400 + ((c & 15) << 4) + (d & 15)]
                low = TABLES[base + 0x500 + (low_ab << 4) + low_cd]
                output.append((high << 4) | low)
        state = bytes(output)
    output = bytearray(16)
    for i in range(16):
        output[CONFIG["permutation"]["final"][i]] = TABLES[0x5a000 + i * 256 + state[i]]
    return bytes(output)


def mixed_key(mcuid_or_seed: str, challenge: str) -> bytes:
    key = bytearray(whitebox_block(hex_bytes(mcuid_or_seed, 16, "seed")))
    for i, value in enumerate(hex_bytes(challenge, 4, "nonce/challenge")):
        key[12 + i] ^= value
    return bytes(key)


def timestamp() -> str:
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y%m%d%H%M%S")


def nonce() -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(8))


def remote_signature(seed_hex: str, random_digits: str, time_digits: str) -> str:
    if not re.fullmatch(r"[0-9]{8}", random_digits):
        raise ValueError("remote nonce must be 8 ASCII decimal digits")
    if not re.fullmatch(r"[0-9]{14}", time_digits):
        raise ValueError("remote time must be 14 ASCII decimal digits")
    return AES.new(mixed_key(seed_hex, random_digits), AES.MODE_ECB).encrypt(
        time_digits.encode("ascii") + b"\x00\x00"
    ).hex().upper()


@dataclass(frozen=True)
class PlainPackets:
    authentication: bytes
    command: bytes


def build_plaintexts(command: str, user_code: str, device_id: str, mcuid: str,
                     target_code: str, *, auth_nonce=None, auth_time=None,
                     command_nonce=None, command_time=None) -> PlainPackets:
    if command not in COMMANDS:
        raise ValueError("unknown remote command")
    field(user_code, 32, "UserCode")
    field(device_id, 64, "deviceID")
    field(target_code, 64, "PKECode")
    hex_bytes(mcuid, 16, "MCUID")
    auth_nonce = nonce() if auth_nonce is None else auth_nonce
    auth_time = timestamp() if auth_time is None else auth_time
    command_nonce = nonce() if command_nonce is None else command_nonce
    command_time = timestamp() if command_time is None else command_time
    seed = "".join(c for c in user_code if c in "0123456789")[:32].ljust(32, "0")
    auth_sig = remote_signature(seed, auth_nonce, auth_time)
    cmd_sig = remote_signature(mcuid, command_nonce, command_time)
    auth = f"*UL,{user_code},{device_id},0.0,0.0,{auth_nonce},{auth_sig},1.56#"
    extra = {"diagnose": "3,", "freeze": "1,", "unfreeze": "0,", "track": "1,", "untrack": "0,"}.get(command, "")
    suffix = "#" if command in ("freeze", "unfreeze", "track", "untrack") else ""
    cmd = f"{PREFIXES[COMMANDS.index(command)]},{user_code},{target_code},{extra}{command_nonce},{cmd_sig}{suffix}"
    result = PlainPackets(auth.encode("ascii"), cmd.encode("ascii"))
    if not all(1 <= len(p) <= 245 for p in (result.authentication, result.command)):
        raise ValueError("RSA plaintext exceeds 245 bytes")
    return result


def rsa_encrypt(plaintext: bytes, *, version="1.3.0", padding: bytes | None = None) -> bytes:
    """PKCS#1 v1.5 encryption. Explicit padding is ONLY for offline vectors."""
    if version not in ("1.2.25", "1.3.0"):
        raise ValueError("unknown bundled RSA key version")
    if not 1 <= len(plaintext) <= 245:
        raise ValueError("RSA plaintext must contain 1..245 bytes")
    public_key = RSA.import_key((ROOT / f"resources/remote-rsa-shiride-{version}.pem").read_bytes())
    length = 253 - len(plaintext)
    padding = bytes(secrets.randbelow(255) + 1 for _ in range(length)) if padding is None else padding
    if len(padding) != length or 0 in padding:
        raise ValueError("RSA padding must be nonzero, length 253 - plaintext length")
    encoded = b"\x00\x02" + padding + b"\x00" + plaintext
    return pow(int.from_bytes(encoded, "big"), public_key.e, public_key.n).to_bytes(256, "big")


def build_packets(*args, version="1.3.0", **kwargs) -> tuple[bytes, bytes]:
    """Offline Native RSA envelopes, NOT a verified live transport.

    Kept for compatibility with the original example. Live 2026-10-30 probes
    received no authentication response to either bundled RSA key; see evidence.
    """
    plain = build_plaintexts(*args, **kwargs)
    return rsa_encrypt(plain.authentication, version=version), rsa_encrypt(plain.command, version=version)


def build_text_frames(*args, **kwargs) -> tuple[bytes, bytes]:
    """Text transport candidate: authentication verified, vehicle action pending.

    This serializer appends one # to the Native command plaintext. That framing
    choice is not proof that all nine commands are accepted by a live vehicle.
    Inner AES signatures remain intact. No network I/O is performed here.
    """
    plain = build_plaintexts(*args, **kwargs)
    return plain.authentication, plain.command.rstrip(b"#") + b"#"


def bluetooth_signature(mcuid: str, pke_code: str, challenge: str) -> str:
    field(pke_code, 64, "PKECode")
    # Native q1 copies at most 15 ASCII bytes into a zero-initialized 16-byte
    # block. The full PKECode is still emitted on the wire. This matters for
    # PKECode lengths 16..64; it differs from simply encrypting 16 PKE bytes.
    block = pke_code.encode("ascii")[:15].ljust(16, b"\x00")
    return AES.new(mixed_key(mcuid, challenge), AES.MODE_ECB).encrypt(block).hex().upper()


def bluetooth_command(action: str, pke_code: str, mcuid: str, challenge: str) -> bytes:
    if action not in BLE_ACTIONS:
        raise ValueError("authenticated BLE action must be 1, 2, 5 or 6")
    signature = bluetooth_signature(mcuid, pke_code, challenge)
    return f"*BT,{pke_code},10,001,{action},{signature}#".encode("ascii")


def bluetooth_challenge_request(pke_code: str) -> bytes:
    field(pke_code, 64, "PKECode")
    return f"*BT,{pke_code},10,008#".encode("ascii")


def bluetooth_prime(pke_code: str) -> bytes:
    field(pke_code, 64, "PKECode")
    return f"*BT,{pke_code},10,001,7#".encode("ascii")


class FrameBuffer:
    """Incremental *...# ASCII framing for TCP replies and BLE notifications.

    AT+ text uses a separate CRLF/token accumulator, not this parser.
    Malformed nested starts are resynchronized; incomplete frames are retained.
    """
    def __init__(self, maximum=65536):
        self.pending = bytearray()
        self.maximum = maximum

    def feed(self, chunk: bytes) -> list[str]:
        self.pending.extend(chunk)
        if len(self.pending) > self.maximum:
            self.pending.clear()
            raise ValueError("response buffer limit exceeded")
        frames = []
        while True:
            start = self.pending.find(b"*")
            if start < 0:
                self.pending.clear()
                return frames
            del self.pending[:start]
            end = self.pending.find(b"#")
            nested = self.pending.find(b"*", 1)
            if nested >= 0 and (end < 0 or nested < end):
                del self.pending[:nested]
                continue
            if end < 0:
                return frames
            frame = bytes(self.pending[:end + 1])
            del self.pending[:end + 1]
            frames.append(frame.decode("ascii", errors="strict"))


def fields(frame: str) -> list[str]:
    if not frame.startswith("*") or not frame.endswith("#") or "*" in frame[1:] or "#" in frame[:-1]:
        raise ValueError("expected one complete *...# frame")
    return frame[:-1].split(",")


def bluetooth_challenge(frame: str, pke_code: str) -> str | None:
    f = fields(frame)
    if len(f) != 5 or f[0] not in ("*AT", "*BT") or f[1:4] != [pke_code, "10", "008"]:
        return None
    hex_bytes(f[4], 4, "BLE challenge")
    return f[4].upper()


def bluetooth_ack(frame: str, pke_code: str, action: str) -> str:
    """Return confirmed/rejected/ignored. Correlate target/action before status."""
    f = fields(frame)
    if len(f) < 5 or f[:4] != ["*AT", pke_code, "10", "001"] or f[4] != action:
        return "ignored"
    if len(f) == 5:
        return "confirmed"  # observed legacy five-field echo acknowledgment
    if len(f) == 6 and f[5] == "0":
        return "rejected"
    # A sixth-field success code has not been established by current evidence.
    return "ignored"


def remote_ack(frame: str, command: str, user_code: str, pke_code: str, *, command_echo: str | None = None) -> str:
    """Conservative interpretation; 'received' never implies physical success."""
    if command not in COMMANDS:
        raise ValueError("unknown command")
    if frame == command_echo:
        return "ignored"
    if frame in (",OK#", ",FAIL#"):
        return "ignored"  # No command/vehicle identity; not a vehicle ACK.
    f = fields(frame)
    prefix = PREFIXES[COMMANDS.index(command)]
    ac_code = {"freeze": "009", "unfreeze": "010", "track": "007", "untrack": "008"}.get(command)
    if ac_code and len(f) == 5 and f[:4] == ["*AC", user_code, pke_code, ac_code]:
        return {"0": "rejected", "1": "confirmed"}.get(f[4], "ignored")
    if len(f) < 3 or f[:3] != [prefix, user_code, pke_code]:
        return "ignored"
    if f[-1] == "FAIL":
        return "rejected"
    if f[-1] == "OK":
        return "confirmed"
    if command == "diagnose" and len(f) >= 6 and f[3:5] == ["003", "3"]:
        if re.fullmatch(r"[0-9]+", f[5]) and int(f[5]) == len(f) - 6:
            return "received"
    return "received" if command == "refresh" else "ignored"


def login_form(account: str, password: str) -> bytes:
    return urlencode({"password": password, "grant_type": "password", "sys": "209",
                      "lang": "CH", "usercode": account, "brand": "升仕"}).encode("ascii")


def refresh_form(token: str, *, field_name="refresh_token") -> bytes:
    if field_name not in ("refresh_token", "refreshToken"):
        raise ValueError("unsupported refresh token field")
    return urlencode({field_name: token, "grant_type": "refresh_token", "sys": "209",
                      "lang": "CH", "brand": "升仕"}).encode("ascii")


def settings_command(mode: int, timeout_minutes: int, ess: bool, seat: bool, handbrake: bool) -> bytes:
    if type(mode) is not int or mode not in (0, 1, 2) or type(timeout_minutes) is not int or not 1 <= timeout_minutes <= 30:
        raise ValueError("mode must be 0..2; timeout must be 1..30 minutes")
    if not all(type(v) is bool for v in (ess, seat, handbrake)):
        raise ValueError("settings flags must be bool")
    return f"AT+SET_PARAM=5,{mode},{timeout_minutes},{int(ess)},{int(seat)},{int(handbrake)}\r\n".encode("ascii")


def rgb_command(enabled: bool, red: int, green: int, blue: int) -> bytes:
    if type(enabled) is not bool or any(type(v) is not int or not 0 <= v <= 255 for v in (red, green, blue)):
        raise ValueError("RGB channels must be integers 0..255")
    return f"AT+SET_RGB={int(enabled)},{red},{green},{blue}\r\n".encode("ascii")
