import base64
import json
from pathlib import Path
import sys
import unittest
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'examples'))
import remote159

class CurrentRemoteProtocolTests(unittest.TestCase):
    def setUp(self):
        self.v = json.loads((ROOT / 'vectors/remote-159.json').read_text())

    def build(self, command='refresh'):
        v = self.v
        return remote159.build_packets(command, v['user_code'], v['device_id'], v['mcuid'], v['pke_code'],
            auth_nonce=v['authentication_nonce'], auth_time=v['authentication_time'],
            command_nonce=v['command_nonce'], command_time=v['command_time'])

    def test_current_runtime_signer_and_transport_vector(self):
        p = self.build()
        self.assertEqual(p.authentication_plaintext, self.v['authentication_plaintext'])
        self.assertEqual(p.command_plaintext, self.v['command_plaintext'])
        self.assertEqual(p.authentication.decode(), self.v['authentication_wire'])
        self.assertEqual(p.command.decode(), self.v['command_wire'])

    def test_wire_decrypts_to_inner_and_encrypted_device_field(self):
        p = self.build()
        c = remote159.PARAMETERS['wrapping']['packet']
        plain = unpad(AES.new(bytes.fromhex(c['key']), AES.MODE_CBC, bytes.fromhex(c['iv'])).decrypt(base64.b64decode(p.command)), 16).decode()
        self.assertEqual(plain, p.command_plaintext + ',' + remote159.cbc_base64('device', self.v['transport_device_id']))
        self.assertFalse(p.command.startswith(b'*'))
        self.assertFalse(p.command.endswith(b'#'))
        self.assertNotIn(b'\n', p.command)

    def test_legacy_time_or_nonce_rejected(self):
        for n,t in [('ABCD1234','20261030123456'),('12345678','2026103012345678'),('１２３４５６７８','20261030123456')]:
            with self.assertRaises(ValueError): remote159.signature(self.v['mcuid'], n, t)

    def test_device_identity_is_stable_and_independent(self):
        self.assertEqual(remote159.transport_device_id(self.v['device_id']), self.v['transport_device_id'])
        self.assertNotEqual(remote159.transport_device_id('OTHER'), self.v['transport_device_id'])
        self.assertEqual(len(base64.b64decode(self.v['transport_device_id'])), 18)

    def test_only_memory_builds_and_no_injected_fields(self):
        for command in ['find','lock','unlock','refresh']:
            self.assertTrue(self.build(command).command_plaintext.startswith('*'))
        with self.assertRaises(ValueError): remote159.build_packets('find','BAD,#','DEV',self.v['mcuid'],'PKE')
        with self.assertRaises(ValueError): self.build('unknown')

if __name__ == '__main__': unittest.main()
