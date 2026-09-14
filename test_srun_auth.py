import hashlib
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout

from srun_auth import (
    SRunError,
    SRunClient,
    _display_width,
    _pad_string,
    _print_table,
    dm_sign,
    encode_info,
    format_add_time,
    is_dm_success,
    is_no_response_error,
    is_overlimit_error,
    parse_access_context,
    parse_device_manager_list,
    parse_jsonp,
    parse_online_devices,
    print_devices,
    response_message,
    xencode,
)


class ProtocolTests(unittest.TestCase):
    """Unit tests for SRun protocol and authentication client."""

    def test_parse_jsonp(self):
        """Test parsing JSONP response into a dictionary."""
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

    def test_parse_access_context(self):
        context = parse_access_context(
            "http://10.20.69.103/index_1.html?ac_id=2&user_ip=10.1.2.3&"
            "nas_ip=10.9.8.7&ap_id=42&ap_ip=10.4.5.6&user_mac=aabbccddeeff",
            "http://10.20.69.103",
        )
        self.assertEqual(
            context,
            {
                "ac_id": "2",
                "ip": "10.1.2.3",
                "nas_ip": "10.9.8.7",
                "ap_id": "42",
                "ap_ip": "10.4.5.6",
                "mac": "aabbccddeeff",
            },
        )

    def test_parse_access_context_rejects_other_host(self):
        self.assertEqual(
            parse_access_context(
                "http://example.com/?user_ip=10.1.2.3",
                "http://10.20.69.103",
            ),
            {},
        )

    def test_parse_access_context_with_aliases_and_fragment(self):
        context = parse_access_context(
            "http://10.20.69.103/#/login?ac=3&wlanuserip=192.168.1.100&"
            "acip=10.9.8.7&usermac=11-22-33-44-55-66",
            "http://10.20.69.103",
        )
        self.assertEqual(
            context,
            {
                "ac_id": "3",
                "ip": "192.168.1.100",
                "nas_ip": "10.9.8.7",
                "ap_id": "",
                "ap_ip": "",
                "mac": "11-22-33-44-55-66",
            },
        )

    def test_parse_access_context_from_index_path_and_wlan_params(self):
        url = (
            "http://10.20.69.103/index_4.html?wlanssid=NUDT-WLAN-SS&"
            "wlanuserip=10.126.47.40&wlanusermac=D8:3A:DD:F1:DC:39&"
            "redirect=http://auth-a186061.wifi.com/&wlanacip=0.0.0.0&"
            "wlanacname=GFKD&wlan_tstamp=1789392543"
        )
        context = parse_access_context(url, "http://10.20.69.103")
        self.assertEqual(
            context,
            {
                "ac_id": "4",
                "ip": "10.126.47.40",
                "nas_ip": "",
                "ap_id": "",
                "ap_ip": "",
                "mac": "D8:3A:DD:F1:DC:39",
            },
        )

    def test_refresh_access_context_verbose_logs(self):
        from unittest.mock import MagicMock, patch

        client = SRunClient(portal="http://10.20.69.103", verbose=True)
        mock_response = MagicMock()
        mock_response.headers.get.return_value = "http://10.20.69.103/index.html?user_ip=10.0.0.99&ac_id=5"
        mock_opener = MagicMock()
        mock_opener.open.return_value.__enter__.return_value = mock_response

        stderr_buf = io.StringIO()
        with patch("urllib.request.build_opener", return_value=mock_opener):
            with redirect_stderr(stderr_buf):
                ctx = client.refresh_access_context()

        output = stderr_buf.getvalue()
        self.assertIn("HTTP probe redirected to: http://10.20.69.103/index.html?user_ip=10.0.0.99&ac_id=5", output)
        self.assertIn("Refreshed access parameters from gateway redirect: ac_id=5, ip=10.0.0.99", output)
        self.assertEqual(client.ip, "10.0.0.99")
        self.assertEqual(client.ac_id, "5")

    def test_no_response_detection(self):
        self.assertTrue(is_no_response_error({"error_msg": "no_response_data_error"}))
        self.assertTrue(is_no_response_error({"error": "RD000"}))
        self.assertFalse(is_no_response_error({"error": "password_error"}))

    def test_login_retries_no_response_with_fresh_context(self):
        class RetryClient:
            retries = 1
            retry_delay = 0

            def __init__(self):
                self.status_calls = 0
                self.refresh_calls = 0
                self.login_calls = 0

            def status(self):
                self.status_calls += 1
                return {"error": "not_online_error"}

            @staticmethod
            def is_online(response):
                return response.get("error") == "ok"

            def refresh_access_context(self):
                self.refresh_calls += 1
                return {"nas_ip": "10.9.8.7"}

            def _login_once(self, username, password):
                self.login_calls += 1
                if self.login_calls == 1:
                    return {"error": "fail", "error_msg": "no_response_data_error"}
                return {"error": "ok", "suc_msg": "login_ok"}

            def _portal_log(self, username):
                return None

            def _log(self, message):
                pass

        client = RetryClient()
        response = SRunClient.login(client, "test", "secret")
        self.assertEqual(response["error"], "ok")
        self.assertEqual(client.login_calls, 2)
        self.assertEqual(client.refresh_calls, 2)

    def test_dm_sign(self):
        expected = hashlib.sha1(b"1700000000user10.1.2.311700000000").hexdigest()
        self.assertEqual(dm_sign("1700000000", "user", "10.1.2.3", "1"), expected)

    def test_is_dm_success(self):
        self.assertTrue(is_dm_success({"error": "ok"}))
        self.assertTrue(is_dm_success({"res": "ok"}))
        self.assertTrue(is_dm_success({"error_msg": "LogoutOK"}))
        self.assertTrue(is_dm_success({"code": 0}))
        self.assertFalse(is_dm_success({"error": "not_online_error"}))
        self.assertFalse(is_dm_success({"code": 1, "message": "fail"}))

    def test_is_overlimit_error(self):
        self.assertTrue(is_overlimit_error({"ecode": "E2620"}))
        self.assertTrue(is_overlimit_error({"error": "E3008"}))
        self.assertTrue(is_overlimit_error({"error_msg": "E2620: already online"}))
        self.assertTrue(is_overlimit_error({"error": "ok", "overlimit_token": "token123"}))
        self.assertTrue(is_overlimit_error({"message": "Maximum online devices reached"}))
        self.assertTrue(is_overlimit_error({"message": "\u5728\u7ebf\u8bbe\u5907\u6570\u91cf\u5df2\u8fbe\u4e0a\u9650"}))
        self.assertFalse(is_overlimit_error({"error": "password_error"}))
        self.assertFalse(is_overlimit_error({"error": "ok"}))

    def test_format_add_time(self):
        formatted = format_add_time("1788603888")
        self.assertTrue(formatted.startswith("2026-"))
        self.assertEqual(format_add_time(""), "")
        self.assertEqual(format_add_time("invalid"), "invalid")

    def test_parse_device_manager_list(self):
        payload = {
            "code": 0,
            "data": [
                {
                    "is_online": True,
                    "rad_online_id": "101",
                    "os_name": "AndroidOS",
                    "ip": "10.1.1.1",
                    "user_mac": "aa-bb-cc-dd-ee-ff",
                    "add_time": "1788603888",
                    "device_name": "Phone",
                },
                {
                    "is_online": False,
                    "rad_online_id": "102",
                    "ip": "10.1.1.2",
                },
            ],
        }
        devices = parse_device_manager_list(payload)
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["id"], "101")
        self.assertEqual(devices[0]["ip"], "10.1.1.1")
        self.assertEqual(devices[0]["mac"], "aa-bb-cc-dd-ee-ff")
        self.assertEqual(devices[0]["device"], "Phone")
        self.assertEqual(devices[0]["os"], "AndroidOS")

    def test_login_overlimit_auto_kicks_oldest(self):
        class OverlimitClient(SRunClient):
            def __init__(self):
                super().__init__(retries=0, retry_delay=0)
                self.login_attempts = 0
                self.kicked_ips = []
                self.ip = "10.1.1.99"

            def status(self):
                return {"error": "not_online_error"}

            def refresh_access_context(self):
                return {}

            def _login_once(self, username, password):
                self.login_attempts += 1
                if self.login_attempts == 1:
                    return {
                        "ecode": "E2620",
                        "error_msg": "E2620: already online",
                        "overlimit_token": "tok",
                    }
                return {"error": "ok", "suc_msg": "login_ok"}

            def get_online_devices(self, username="", overlimit_token=""):
                return [
                    {
                        "id": "1",
                        "ip": "10.1.1.2",
                        "raw_add_time": "1700000000",
                        "device": "old_dev",
                    },
                    {
                        "id": "2",
                        "ip": "10.1.1.3",
                        "raw_add_time": "1700000500",
                        "device": "new_dev",
                    },
                ]

            def dm_logout(self, username, ip):
                self.kicked_ips.append(ip)
                return {"error": "ok"}

            def _log(self, message):
                pass

        client = OverlimitClient()
        resp = client.login("test", "pass", auto_kick="oldest", interactive=False)
        self.assertEqual(resp["error"], "ok")
        self.assertEqual(client.login_attempts, 2)
        self.assertEqual(client.kicked_ips, ["10.1.1.2"])

    def test_login_overlimit_auto_kicks_newest(self):
        class OverlimitClient(SRunClient):
            def __init__(self):
                super().__init__(retries=0, retry_delay=0)
                self.login_attempts = 0
                self.kicked_ips = []
                self.ip = "10.1.1.99"

            def status(self):
                return {"error": "not_online_error"}

            def refresh_access_context(self):
                return {}

            def _login_once(self, username, password):
                self.login_attempts += 1
                if self.login_attempts == 1:
                    return {"ecode": "E2620", "error_msg": "E2620: already online"}
                return {"error": "ok"}

            def get_online_devices(self, username="", overlimit_token=""):
                return [
                    {
                        "id": "1",
                        "ip": "10.1.1.2",
                        "raw_add_time": "1700000000",
                        "device": "old_dev",
                    },
                    {
                        "id": "2",
                        "ip": "10.1.1.3",
                        "raw_add_time": "1700000500",
                        "device": "new_dev",
                    },
                ]

            def dm_logout(self, username, ip):
                self.kicked_ips.append(ip)
                return {"error": "ok"}

            def _log(self, message):
                pass

        client = OverlimitClient()
        resp = client.login("test", "pass", auto_kick="newest", interactive=False)
        self.assertEqual(resp["error"], "ok")
        self.assertEqual(client.kicked_ips, ["10.1.1.3"])

    def test_login_overlimit_auto_kicks_all(self):
        class OverlimitClient(SRunClient):
            def __init__(self):
                super().__init__(retries=0, retry_delay=0)
                self.login_attempts = 0
                self.kicked_ips = []
                self.ip = "10.1.1.99"

            def status(self):
                return {"error": "not_online_error"}

            def refresh_access_context(self):
                return {}

            def _login_once(self, username, password):
                self.login_attempts += 1
                if self.login_attempts == 1:
                    return {"ecode": "E2620", "error_msg": "E2620: already online"}
                return {"error": "ok"}

            def get_online_devices(self, username="", overlimit_token=""):
                return [
                    {"id": "1", "ip": "10.1.1.2", "raw_add_time": "1700000000"},
                    {"id": "2", "ip": "10.1.1.3", "raw_add_time": "1700000500"},
                ]

            def dm_logout(self, username, ip):
                self.kicked_ips.append(ip)
                return {"error": "ok"}

            def _log(self, message):
                pass

        client = OverlimitClient()
        resp = client.login("test", "pass", auto_kick="all", interactive=False)
        self.assertEqual(resp["error"], "ok")
        self.assertEqual(client.kicked_ips, ["10.1.1.2", "10.1.1.3"])

    def test_login_overlimit_non_interactive_raises_error(self):
        class OverlimitClient(SRunClient):
            def __init__(self):
                super().__init__(retries=0, retry_delay=0)
                self.ip = "10.1.1.99"

            def status(self):
                return {"error": "not_online_error"}

            def refresh_access_context(self):
                return {}

            def _login_once(self, username, password):
                return {"ecode": "E2620", "error_msg": "E2620: already online"}

            def get_online_devices(self, username="", overlimit_token=""):
                return [{"id": "1", "ip": "10.1.1.2", "raw_add_time": "1700000000"}]

            def _log(self, message):
                pass

        client = OverlimitClient()
        with self.assertRaises(SRunError) as ctx:
            client.login("test", "pass", auto_kick="none", interactive=False)
        self.assertIn("Maximum online devices limit reached", str(ctx.exception))

    def test_login_overlimit_interactive_prompt(self):
        from unittest.mock import patch

        class OverlimitClient(SRunClient):
            def __init__(self):
                super().__init__(retries=0, retry_delay=0)
                self.login_attempts = 0
                self.kicked_ips = []
                self.ip = "10.1.1.99"

            def status(self):
                return {"error": "not_online_error"}

            def refresh_access_context(self):
                return {}

            def _login_once(self, username, password):
                self.login_attempts += 1
                if self.login_attempts == 1:
                    return {"ecode": "E2620", "error_msg": "E2620: already online"}
                return {"error": "ok"}

            def get_online_devices(self, username="", overlimit_token=""):
                return [
                    {
                        "id": "1",
                        "ip": "10.1.1.2",
                        "raw_add_time": "1700000000",
                        "device": "dev1",
                    },
                    {
                        "id": "2",
                        "ip": "10.1.1.3",
                        "raw_add_time": "1700000500",
                        "device": "dev2",
                    },
                ]

            def dm_logout(self, username, ip):
                self.kicked_ips.append(ip)
                return {"error": "ok"}

            def _log(self, message):
                pass

        client = OverlimitClient()
        with patch("builtins.input", return_value="2"):
            resp = client.login("test", "pass", auto_kick="interactive", interactive=True)
            self.assertEqual(resp["error"], "ok")
            self.assertEqual(client.kicked_ips, ["10.1.1.3"])


if __name__ == "__main__":
    unittest.main()
