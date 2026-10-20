import json
from http.server import ThreadingHTTPServer
from pathlib import Path
import sys
import tempfile
from threading import Thread
import unittest
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parent / "app"))
from server import HubState, make_handler


SAMPLE_LINE = {
    "recv_at": "2026-10-20T15:20:24.163+02:00",
    "gps": None,
    "payload": {
        "v": 1,
        "mode": "scan",
        "scan_type": "passive",
        "session_id": "9f3a21c4",
        "scan_id": 1,
        "device_ts_us": 496234567,
        "scan_duration_ms": 4200,
        "total_detected": 1,
        "stored": 1,
        "dropped": 0,
        "lost_before": 0,
        "buffered": False,
        "devices": [
            {
                "ssid": "CorpNet",
                "bssid": "BC:30:D9:A4:2E:5C",
                "rssi": -48,
                "primary_channel": 6,
                "secondary_channel": 0,
                "auth_mode": "WPA_WPA2_PSK",
                "pairwise_cipher": "TKIP_CCMP",
                "group_cipher": "TKIP_CCMP",
                "proto": "bgn",
                "band_mhz": 20,
                "wps": True,
                "hidden": False,
            }
        ],
        "promisc": {
            "mgmt_frames": 20,
            "data_frames": 10,
            "probe_req_frames": 3,
            "deauth_frames": 0,
            "probes": [
                {
                    "sta_mac": "00:7C:2D:E2:69:48",
                    "ssid": "CorpNet",
                    "rssi": -55,
                    "channel": 6,
                    "count": 2,
                }
            ],
            "clients": [
                {
                    "sta_mac": "00:7C:2D:E2:69:48",
                    "bssid": "BC:30:D9:A4:2E:5C",
                    "rssi": -55,
                    "channel": 6,
                    "frames": 8,
                }
            ],
        },
    },
}


class SigintConsoleServerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.hub = HubState(Path(self.tmp.name))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.hub))
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.tmp.cleanup()

    def test_import_tags_and_dashboard_render(self):
        body = (json.dumps(SAMPLE_LINE) + "\n").encode("utf-8")
        req = Request(
            f"{self.url}/api/import?filename=wardrive_test.jsonl",
            data=body,
            headers={"Content-Type": "application/x-ndjson"},
        )
        with urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            res_json = json.loads(resp.read())
            self.assertEqual(res_json["imported"], 1)

        tag_payload = {
            "sessions": {"9f3a21c4": {"name": "Planta 1"}},
            "networks": {},
            "devices": {"00:7C:2D:E2:69:48": {"label": "Samsung Corporativo", "category": "CONOCIDO"}},
        }
        req_tags = Request(
            f"{self.url}/api/tags",
            data=json.dumps(tag_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urlopen(req_tags) as resp:
            self.assertEqual(resp.status, 200)

        with urlopen(f"{self.url}/") as resp:
            html = resp.read().decode("utf-8")
            self.assertIn("SIGINT // 802.11", html)
            self.assertIn("Samsung Electronics", html)
            self.assertIn("Planta 1", html)

        # Verificar que reimportar el mismo JSONL deduplica al 100 %
        req_dup = Request(
            f"{self.url}/api/sync/push?filename=wardrive_test.jsonl",
            data=body,
            headers={"Content-Type": "application/x-ndjson"},
        )
        with urlopen(req_dup) as resp:
            res_dup = json.loads(resp.read())
            self.assertEqual(res_dup["imported"], 0)
            self.assertEqual(res_dup["skipped_duplicates"], 1)

        with urlopen(f"{self.url}/api/sync/status") as resp:
            st = json.loads(resp.read())
            self.assertEqual(st["magic"], "SIGINT-CONSOLE-V1")
            self.assertEqual(st["sessions"]["9f3a21c4"]["max_scan_id"], 1)


if __name__ == "__main__":
    unittest.main()
