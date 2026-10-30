from pathlib import Path
import json
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples"))
import dashcam as d


class DashcamProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads((ROOT / "vectors/dashcam.json").read_text())

    def test_read_only_request_bodies_match_documented_schema(self):
        self.assertEqual(json.loads(d.dates_request("rear")), {"METHOD": "VIDEO.DATE", "previewType": "rear"})
        self.assertEqual(json.loads(d.recordings_request("front", "2026-10-30")), self.fixture["list_request"])
        self.assertEqual(json.loads(d.recordings_request("rear", "2026-10-29", index=2, num=10, sort="asc"))["index"], 2)

    def test_request_validation_does_not_emit_unknown_firmware_sort_or_camera(self):
        for camera in ("", "both", "FRONT", "1"):
            with self.assertRaises(ValueError): d.dates_request(camera)
        for date in ("2026-2-1", "2026-02-30", "2026-10-30T00:00:00", None):
            with self.assertRaises(ValueError): d.recordings_request("front", date)
        for kwargs in ({"sort": "desc"}, {"sort": ""}, {"num": 0}, {"num": 101},
                       {"num": True}, {"index": -1}, {"index": True}, {"index": 2**31}):
            with self.assertRaises(ValueError): d.recordings_request("front", "2026-10-30", **kwargs)

    def test_actual_scheme_less_firmware_shape_becomes_playable_http_url(self):
        rows = d.parse_recordings(json.dumps(self.fixture["list_response"]).encode())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].play_url, self.fixture["normalized_play_url"])
        self.assertEqual(rows[0].thumbnail_url, self.fixture["normalized_thumbnail_url"])
        self.assertFalse(rows[0].thumbnail_url.endswith(".mp4.jpg"))
        self.assertEqual(rows[0].record_time, "11-26-00")
        self.assertEqual(rows[0].raw["duration"], 180)
        self.assertEqual(rows[0].raw["size"], 12345678)
        self.assertEqual(rows[0].raw["exigency"], "false")
        self.assertIsInstance(rows[0].raw["id"], int)

    def test_authority_normalization_preserves_media_path_and_escapes(self):
        path = "/media/emmc/videostoragefolder/rearVideo1/rear_20261030_112600.mp4"
        for prefix in ("192.168.3.1:7686", "192.168.2.1:7686", "http://192.168.2.1:7686",
                       "http://192.168.3.1:7686", "//192.168.3.1:7686", ""):
            self.assertEqual(d.normalize_media_url(prefix + path), "http://192.168.3.1:7686" + path)
        self.assertEqual(d.normalize_media_url("/media/clip%20one.mp4"), "http://192.168.3.1:7686/media/clip%20one.mp4")

    def test_unknown_hosts_ports_protocols_credentials_and_controls_are_rejected(self):
        for value in (None, "", "http://example.com:7686/a.mp4", "http://192.168.3.1:80/a.mp4",
                      "https://192.168.3.1:7686/a.mp4", "ftp://192.168.3.1:7686/a.mp4",
                      "file:///private/a.mp4", "192.168.3.1.evil:7686/a.mp4",
                      "http://user@192.168.3.1:7686/a.mp4", "http://192.168.3.1:invalid/a.mp4",
                      "http://192.168.3.1:7686/a\r\n.mp4"):
            with self.subTest(value=value): self.assertIsNone(d.normalize_media_url(value))

    def test_dates_are_validated_deduplicated_and_sorted(self):
        body = dict(self.fixture["date_response"], dateList=["2026-10-29", "bad", "2026-02-30", None,
                                                          "2026-10-30", "2026-10-29"])
        self.assertEqual(d.parse_dates(json.dumps(body).encode()), ["2026-10-30", "2026-10-29"])

    def test_bad_media_address_does_not_hide_a_valid_recording_row(self):
        body = dict(self.fixture["list_response"], videoBeanList=[{"name": "broken.mp4", "playUrl": "https://example.com/a.mp4"}])
        rows = d.parse_recordings(json.dumps(body).encode())
        self.assertEqual(rows[0].title, "broken.mp4")
        self.assertIsNone(rows[0].play_url)  # UI should show a clear per-record error.

    def test_rejections_wrong_methods_and_bad_schema_are_not_empty_success(self):
        for body in (b"not-json", b"[]", b'{"METHOD":"OTHER","code":0}',
                     b'{"METHOD":"VIDEO.INFO.LIST","code":1,"videoBeanList":[]}',
                     b'{"METHOD":"VIDEO.INFO.LIST","code":false,"videoBeanList":[]}',
                     b'{"METHOD":"VIDEO.INFO.LIST","code":5,"videoBeanList":[]}',
                     b'{"METHOD":"VIDEO.INFO.LIST","code":-1,"videoBeanList":[]}',
                     b'{"METHOD":"VIDEO.INFO.LIST","code":0,"videoBeanList":{}}',
                     b'{"METHOD":"VIDEO.INFO.LIST","code":0,"videoBeanList":[1]}'):
            with self.assertRaises((ValueError, TypeError)): d.parse_recordings(body)

    def test_documented_json_is_valid_and_only_constructs_read_requests(self):
        text = (ROOT / "docs/行车记录仪协议.md").read_text()
        for snippet in re.findall(r"```json\n(.*?)\n```", text, re.S):
            value = json.loads(snippet)
            if "METHOD" in value:
                self.assertIn(value["METHOD"], ("VIDEO.DATE", "VIDEO.INFO.LIST"))
        dates = dict(self.fixture["date_response"], code=-1, dateList=[])
        with self.assertRaises(ValueError): d.parse_dates(json.dumps(dates).encode())


if __name__ == "__main__": unittest.main()
