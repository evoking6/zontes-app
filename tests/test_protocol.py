from pathlib import Path
import hashlib
import json
import random
import re
import sys
import unittest
from urllib.parse import parse_qs, unquote

from Crypto.PublicKey import RSA

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples"))
import protocol as p


class NativeVectorTests(unittest.TestCase):
    def test_remote_plaintexts_and_complete_rsa_bytes_for_both_versions(self):
        for version in ("1.2.25", "1.3.0"):
            f = json.loads((ROOT / f"vectors/remote-{version}.json").read_text())
            self.assertEqual({v["command"] for v in f["vectors"]}, set(p.COMMANDS))
            for vector in f["vectors"]:
                with self.subTest(version=version, command=vector["command"]):
                    plain = p.build_plaintexts(vector["command"], **f["input"])
                    for label, block in (("authentication", plain.authentication), ("command_packet", plain.command)):
                        expected = vector[label]
                        self.assertEqual(block.decode(), expected["plaintext"])
                        self.assertEqual(p.rsa_encrypt(block, version=version, padding=bytes.fromhex(expected["test_padding_hex"])).hex(), expected["ciphertext_hex"])

    def test_bluetooth_packets_match_original_native_in_both_versions(self):
        f = json.loads((ROOT / "vectors/bluetooth.json").read_text())
        self.assertEqual(f["native_versions"], ["1.2.25", "1.3.0"])
        self.assertEqual(len(f["vectors"]), 96)
        for v in f["vectors"]:
            with self.subTest(pke=v["pke_code"], action=v["action"], challenge=v["challenge"]):
                actual = p.bluetooth_command(v["action"], v["pke_code"], v["mcuid"], v["challenge"])
                self.assertEqual(actual.decode(), v["packet_ascii"])
                self.assertEqual(actual.hex(), v["packet_hex"])
                self.assertEqual(len(actual), 47 + len(v["pke_code"]))

    def test_whitebox_vectors(self):
        for v in json.loads((ROOT / "vectors/whitebox.json").read_text()):
            self.assertEqual(p.whitebox_block(bytes.fromhex(v["input_hex"])).hex(), v["output_hex"])

    def test_public_key_fingerprints_are_spki_der(self):
        expected = {"1.2.25": "55ff3f80ced07f771ddb2b3c8880b1763b03f56deb0dc885968cc1e730e903b2",
                    "1.3.0": "1387b90a10cf6b55fd86a2f614c46e4e67ba3154be4f38cdddb02bdd5d01d19f"}
        for version, fingerprint in expected.items():
            k = RSA.import_key((ROOT / f"resources/remote-rsa-shiride-{version}.pem").read_bytes())
            self.assertFalse(k.has_private())
            self.assertEqual(k.e, 65537)
            self.assertEqual(k.size_in_bits(), 2048)
            self.assertEqual(hashlib.sha256(k.public_key().export_key(format="DER")).hexdigest(), fingerprint)

    def test_rsa_production_randomness_is_not_fixed_fixture_padding(self):
        self.assertNotEqual(p.rsa_encrypt(b"synthetic"), p.rsa_encrypt(b"synthetic"))


class BoundaryTests(unittest.TestCase):
    MCU = "12345678901234567890123456789012"

    def test_long_pke_native_truncation_preserves_full_wire_target(self):
        a = p.bluetooth_command("5", "A" * 15, self.MCU, "89ABCDEF")
        b = p.bluetooth_command("5", "A" * 16, self.MCU, "89ABCDEF")
        self.assertEqual(a.split(b",")[-1], b.split(b",")[-1])
        self.assertIn(b"A" * 16, b)
        self.assertTrue(b.endswith(b"120A41E2ABA1E492BE45F978F6389FAC#"))

    def test_remote_nonce_decimal_but_bluetooth_challenge_hex(self):
        self.assertEqual(p.bluetooth_signature(self.MCU, "PKE123", "89ABCDEF"), "409777E819ACBBDFF1F9A9FBAD70E349")
        with self.assertRaises(ValueError):
            p.remote_signature(self.MCU, "89ABCDEF", "20260909123456")

    def test_rejects_malformed_identity_and_challenge(self):
        for bad in ("", "A" * 65, "has space", "bad,pke", "bad#", "中文", "abc\n"):
            with self.subTest(pke=bad), self.assertRaises(ValueError):
                p.bluetooth_command("5", bad, self.MCU, "12345678")
        for bad in ("1234567", "123456789", "GGGGGGGG", "12 34 56"):
            with self.subTest(challenge=bad), self.assertRaises(ValueError):
                p.bluetooth_command("6", "PKE123", self.MCU, bad)
        for bad in ("0", "3", "4", "7", "8", "9", "10", "A"):
            with self.subTest(action=bad), self.assertRaises(ValueError):
                p.bluetooth_command(bad, "PKE123", self.MCU, "12345678")

    def test_malformed_mcuid(self):
        for bad in ("short", "g" * 32, "f" * 31, "f" * 33, "12 " * 16):
            with self.assertRaises(ValueError):
                p.bluetooth_command("1", "PKE123", bad, "12345678")

    def test_rsa_limits_and_padding(self):
        for n in (0, 246):
            with self.assertRaises(ValueError):
                p.rsa_encrypt(b"a" * n)
        for n in (1, 245):
            self.assertEqual(len(p.rsa_encrypt(b"a" * n)), 256)
        for padding in (b"", b"\0" * 252, b"a" * 251):
            with self.assertRaises(ValueError):
                p.rsa_encrypt(b"a", padding=padding)


class FramingAndResultTests(unittest.TestCase):
    def test_every_byte_split_and_concatenated_frames(self):
        data = b"noise*BR,1#*AT,PKE123,10,008,12345678#*AT,PKE123,10,001,6#"
        expected = ["*BR,1#", "*AT,PKE123,10,008,12345678#", "*AT,PKE123,10,001,6#"]
        for split in range(len(data) + 1):
            parser = p.FrameBuffer()
            self.assertEqual(parser.feed(data[:split]) + parser.feed(data[split:]), expected)
        parser = p.FrameBuffer()
        actual = []
        for b in data:
            actual += parser.feed(bytes([b]))
        self.assertEqual(actual, expected)

    def test_fragmented_tail_and_nested_noise(self):
        parser = p.FrameBuffer()
        self.assertEqual(parser.feed(b"xx*garbage*AT,PKE123,10,008,1234"), [])
        self.assertEqual(parser.feed(b"5678#extra"), ["*AT,PKE123,10,008,12345678#"])
        self.assertEqual(parser.feed(b"\r\n*BR,1#"), ["*BR,1#"])

    def test_bounded_buffer_and_non_ascii(self):
        with self.assertRaises(ValueError):
            p.FrameBuffer(maximum=10).feed(b"*" + b"A" * 10)
        with self.assertRaises(UnicodeDecodeError):
            p.FrameBuffer().feed(b"*\xff#")

    def test_challenge_correlation(self):
        self.assertEqual(p.bluetooth_challenge("*BT,PKE123,10,008,89abcdef#", "PKE123"), "89ABCDEF")
        self.assertIsNone(p.bluetooth_challenge("*AT,OTHER,10,008,12345678#", "PKE123"))
        self.assertIsNone(p.bluetooth_challenge("*AT,PKE123,10,001,7#", "PKE123"))

    def test_bluetooth_negative_ack_precedes_confirmation(self):
        self.assertEqual(p.bluetooth_ack("*AT,PKE123,10,001,6,0#", "PKE123", "6"), "rejected")
        self.assertEqual(p.bluetooth_ack("*AT,PKE123,10,001,6#", "PKE123", "6"), "confirmed")
        for frame in ("*AT,PKE123,10,001,7#", "*AT,OTHER,10,001,6#", "*AT,PKE123,10,001,5#", "*BT,PKE123,10,001,6#", "*AT,PKE123,10,001,6,1#"):
            self.assertEqual(p.bluetooth_ack(frame, "PKE123", "6"), "ignored")

    def test_remote_separates_received_ack_and_failure(self):
        self.assertEqual(p.remote_ack("*ULoc,USER123,PKE123,OK#", "lock", "USER123", "PKE123"), "confirmed")
        self.assertEqual(p.remote_ack("*ULoc,USER123,PKE123,FAIL#", "lock", "USER123", "PKE123"), "rejected")
        self.assertEqual(p.remote_ack("*RE,USER123,PKE123,DATA#", "refresh", "USER123", "PKE123"), "received")
        self.assertEqual(p.remote_ack("*AC,USER123,PKE123,009,0#", "freeze", "USER123", "PKE123"), "rejected")
        self.assertEqual(p.remote_ack("*AC,USER123,PKE123,008,1#", "track", "USER123", "PKE123"), "ignored")
        self.assertEqual(p.remote_ack("*UClear,USER123,PKE123,OK#", "lock", "USER123", "PKE123"), "ignored")


class HttpAndSettingsTests(unittest.TestCase):
    def test_form_encoding_does_not_inject_password_delimiters(self):
        password = "synthetic+&=# 中文"
        parsed = parse_qs(p.login_form("sample-account", password).decode())
        self.assertEqual(parsed["password"], [password])
        self.assertEqual(parsed["brand"], ["升仕"])
        self.assertEqual(parsed["grant_type"], ["password"])

    def test_refresh_fields_are_explicit(self):
        for name in ("refresh_token", "refreshToken"):
            self.assertEqual(parse_qs(p.refresh_form("synthetic-token", field_name=name).decode())[name], ["synthetic-token"])
        with self.assertRaises(ValueError):
            p.refresh_form("synthetic-token", field_name="accessToken")

    def test_settings_and_rgb_wire_bytes(self):
        self.assertEqual(p.settings_command(1, 10, False, True, False), b"AT+SET_PARAM=5,1,10,0,1,0\r\n")
        self.assertEqual(p.rgb_command(True, 0, 137, 95), b"AT+SET_RGB=1,0,137,95\r\n")
        for args in ((3, 10, False, False, False), (1, 0, False, False, False), (1, 31, False, False, False)):
            with self.assertRaises(ValueError):
                p.settings_command(*args)
        with self.assertRaises(ValueError):
            p.rgb_command(True, 256, 0, 0)


class DocumentationTests(unittest.TestCase):
    def test_documented_python_examples_execute_offline(self):
        for path in (ROOT / "docs").glob("*.md"):
            for code in re.findall(r"```python\n(.*?)\n```", path.read_text(), re.S):
                exec(compile(code, str(path), "exec"), {"__name__": "documentation_example"})

    def test_two_protocol_documents_and_local_links_resolve(self):
        self.assertEqual({f.name for f in (ROOT / "docs").glob("*.md")}, {"远端控车协议.md", "蓝牙控车协议.md"})
        for path in [ROOT / "README.md", *(ROOT / "docs").glob("*.md")]:
            text = path.read_text()
            self.assertEqual(len(re.findall(r"^```", text, re.M)) % 2, 0, path)
            for target in re.findall(r"\]\(([^)]+)\)", text):
                if "://" not in target and not target.startswith("#"):
                    target = unquote(target.split("#")[0])
                    self.assertTrue((path.parent / target).exists(), (path, target))

    def test_resources_match_recorded_hashes(self):
        index = json.loads((ROOT / "evidence/source-index.json").read_text())
        for name, digest in index["published_resources_sha256"].items():
            self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), digest)

    def test_no_binary_apps_private_keys_or_local_absolute_paths(self):
        for path in ROOT.rglob("*"):
            if not path.is_file() or ".git" in path.parts or "__pycache__" in path.parts:
                continue
            self.assertNotIn(path.suffix.lower(), (".apk", ".ipa", ".so", ".p12", ".mobileprovision"))
            if path.suffix in (".md", ".json", ".pem", ".py", ".txt"):
                content = path.read_text()
                self.assertNotIn("-----BEGIN " + "PRIVATE KEY-----", content)
                self.assertNotIn("-----BEGIN RSA " + "PRIVATE KEY-----", content)
                self.assertNotIn("/Users/" + "tanxw/", content)


if __name__ == "__main__":
    unittest.main(verbosity=2)
