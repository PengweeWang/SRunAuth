import unittest

from srun_auth import SRunError, encode_info, parse_jsonp, parse_online_devices, xencode


class ProtocolTests(unittest.TestCase):
    def test_parse_jsonp(self):
        self.assertEqual(parse_jsonp(b'_cb({"error":"ok","code":0})'), {
            "error": "ok",
            "code": 0,
        })

    def test_xencode_is_deterministic(self):
        self.assertEqual(
            xencode("hello", "token").hex(),
            "bb00d00c966e78bfb80ef138",
        )

    def test_encode_info_prefix(self):
        result = encode_info(
            {
                "username": "test",
                "password": "secret",
                "ip": "10.0.0.2",
                "acid": "1",
                "enc_ver": "srun_bx1",
            },
            "0123456789abcdef",
        )
        self.assertTrue(result.startswith("{SRBX1}"))
        self.assertEqual(len(result), 131)

    def test_parse_online_devices(self):
        devices = parse_online_devices(
            {
                "online_device_detail": (
                    '{"11524":{"class_name":"Linux","ip":"10.128.85.48",'
                    '"ip6":"::","os_name":"Linux","rad_online_id":"11524"}}'
                )
            }
        )
        self.assertEqual(
            devices,
            [
                {
                    "id": "11524",
                    "ipv4": "10.128.85.48",
                    "ipv6": "::",
                    "device": "Linux",
                    "os": "Linux",
                }
            ],
        )

    def test_parse_online_devices_rejects_invalid_json(self):
        with self.assertRaises(SRunError):
            parse_online_devices({"online_device_detail": "not-json"})


if __name__ == "__main__":
    unittest.main()
