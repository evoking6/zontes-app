import json
from pathlib import Path
import sys
import unittest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'examples'))
import mpaas_rpc

class MpaasRPCTests(unittest.TestCase):
    def setUp(self):
        self.v = json.loads((ROOT / 'vectors/mpaas-rpc.json').read_text())

    def test_synthetic_native_sdk_signature_and_body_vector(self):
        v = self.v
        r = mpaas_rpc.build_request(v['configuration'], v['fields'], v['device_id'], v['timestamp_milliseconds'], 'fixture-trace')
        self.assertEqual(r.body.decode(), v['body'])
        self.assertEqual(r.headers['Ts'], v['timestamp'])
        self.assertEqual(r.headers['Sign'], v['signature'])
        self.assertEqual(r.headers['Did'], 'TEMP-' + r.headers['x-request-deviceid'])
        self.assertEqual(r.headers['TRACEID'], 'fixture-trace')
        self.assertEqual(json.loads(r.body)[0]['_requestBody']['sys'], 209)

    def test_timestamp_and_invalid_clock(self):
        for n,want in [(0,'0'),(63,'/'),(64,'10')]: self.assertEqual(mpaas_rpc.timestamp(n),want)
        with self.assertRaises(ValueError): mpaas_rpc.timestamp(-1)

    def test_sign_uses_exact_utf8_body_and_text_key(self):
        v = self.v
        sig = mpaas_rpc.sign_body(v['body'].encode(), v['configuration']['operation'], v['timestamp'], v['configuration']['secret'])
        self.assertEqual(sig, v['signature'])
        self.assertNotEqual(mpaas_rpc.sign_body(v['body'].encode()+b' ', v['configuration']['operation'], v['timestamp'], v['configuration']['secret']),sig)

    def test_http200_without_gateway_success_is_rejected(self):
        for status in ['7014','7002','6666',None]:
            with self.assertRaises(ValueError): mpaas_rpc.decode_response(200, {'Result-Status':status}, b'{"code":200}')
        self.assertEqual(mpaas_rpc.decode_response(200, {'result-status':'1000'}, b'{"code":200}'), {'code':200})

    def test_configuration_requires_tls_and_device_identity(self):
        c = dict(self.v['configuration']);c['gateway']='http://example.com/mgw.htm'
        with self.assertRaises(ValueError): mpaas_rpc.build_request(c, {}, 'fixture',0)

if __name__ == '__main__': unittest.main()
