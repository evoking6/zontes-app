"""Verify checked-in synthetic native vectors without network/device access."""
import json
from protocol import ROOT, build_plaintexts, rsa_encrypt, bluetooth_command, whitebox_block


def main():
    from remote159 import build_packets as build_current
    v = json.loads((ROOT / "vectors/remote-159.json").read_text())
    p = build_current("refresh", v["user_code"], v["device_id"], v["mcuid"], v["pke_code"],
                      auth_nonce=v["authentication_nonce"], auth_time=v["authentication_time"],
                      command_nonce=v["command_nonce"], command_time=v["command_time"])
    assert p.authentication.decode() == v["authentication_wire"]
    assert p.command.decode() == v["command_wire"]
    print("current Android 1.59: auth/read CBC vectors match; iOS login port and physical actions pending")
    for version in ("1.2.25", "1.3.0"):
        fixture = json.loads((ROOT / f"vectors/remote-{version}.json").read_text())
        for vector in fixture["vectors"]:
            packets = build_plaintexts(vector["command"], **fixture["input"])
            for name, plain in (("authentication", packets.authentication), ("command_packet", packets.command)):
                expected = vector[name]
                assert plain.decode() == expected["plaintext"]
                assert rsa_encrypt(plain, version=version, padding=bytes.fromhex(expected["test_padding_hex"])).hex() == expected["ciphertext_hex"]
        print(f"historical remote {version}: 9 commands / 18 RSA packets match native fixtures")
    fixture = json.loads((ROOT / "vectors/bluetooth.json").read_text())
    for v in fixture["vectors"]:
        packet = bluetooth_command(v["action"], v["pke_code"], v["mcuid"], v["challenge"])
        assert packet.decode() == v["packet_ascii"] and packet.hex() == v["packet_hex"]
    print(f"bluetooth: {len(fixture['vectors'])} packets match both native versions")
    for v in json.loads((ROOT / "vectors/whitebox.json").read_text()):
        assert whitebox_block(bytes.fromhex(v["input_hex"])).hex() == v["output_hex"]
    print("whitebox: all vectors match; no network or vehicle operation performed")


if __name__ == "__main__":
    main()
