import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import MagicMock, patch

from srun_auth import (
    CONFIG_VERSION,
    CredentialsResult,
    SRunClient,
    SRunError,
    _display_width,
    _pad_string,
    _print_table,
    build_parser,
    decrypt_secret,
    delete_config,
    dm_sign,
    encode_info,
    encrypt_secret,
    format_add_time,
    get_default_config_path,
    get_machine_identity,
    handle_config_command,
    is_dm_success,
    is_no_response_error,
    is_overlimit_error,
    load_config,
    load_credentials,
    main,
    parse_access_context,
    parse_device_manager_list,
    parse_jsonp,
    parse_online_devices,
    print_devices,
    response_message,
    save_config,
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
            "http://10.20.69.103/index_4.html?wlanssid=CAMPUS-WLAN&"
            "wlanuserip=10.10.10.40&wlanusermac=AA:BB:CC:DD:EE:FF&"
            "redirect=http://example.com/&wlanacip=0.0.0.0&"
            "wlanacname=AC-GW-01&wlan_tstamp=1789392543"
        )
        context = parse_access_context(url, "http://10.20.69.103")
        self.assertEqual(
            context,
            {
                "ac_id": "4",
                "ip": "10.10.10.40",
                "nas_ip": "",
                "ap_id": "",
                "ap_ip": "",
                "mac": "AA:BB:CC:DD:EE:FF",
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


class ConfigAndCredentialsTests(unittest.TestCase):
    """Unit tests for configuration file, encryption, and credential handling."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.temp_dir.name, "srun_test_config.json")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_get_default_config_path_resolution(self):
        with patch.dict(os.environ, {"SRUN_CONFIG": "/tmp/custom_srun.json"}):
            self.assertEqual(get_default_config_path(), "/tmp/custom_srun.json")

        with patch.dict(os.environ, {"SRUN_CONFIG": "", "XDG_CONFIG_HOME": "/custom/xdg"}, clear=False):
            expected = os.path.join("/custom/xdg", "srunauth", "config.json")
            self.assertEqual(get_default_config_path(), expected)

        with patch.dict(os.environ, {}, clear=True):
            expected = os.path.expanduser("~/.config/srunauth/config.json")
            self.assertEqual(get_default_config_path(), expected)

    def test_encrypt_and_decrypt_secret_roundtrip(self):
        secret = "MyP@ssw0rd!#$ 校园网认证密钥 123"
        encrypted = encrypt_secret(secret)

        self.assertEqual(encrypted["version"], CONFIG_VERSION)
        self.assertEqual(encrypted["algorithm"], "PBKDF2-HMAC-SHA256-CTR")
        self.assertNotIn("MyP@ssw0rd", json.dumps(encrypted))
        self.assertNotIn("校园网", json.dumps(encrypted))

        decrypted = decrypt_secret(encrypted)
        self.assertEqual(decrypted, secret)

    def test_encrypt_produces_unique_ciphertexts(self):
        secret = "static_password"
        c1 = encrypt_secret(secret)
        c2 = encrypt_secret(secret)
        self.assertNotEqual(c1["salt"], c2["salt"])
        self.assertNotEqual(c1["nonce"], c2["nonce"])
        self.assertNotEqual(c1["ciphertext"], c2["ciphertext"])
        self.assertEqual(decrypt_secret(c1), secret)
        self.assertEqual(decrypt_secret(c2), secret)

    def test_decrypt_fails_on_tampering(self):
        encrypted = encrypt_secret("secure_text")

        # Tampered tag
        tampered_tag = dict(encrypted)
        tampered_tag["tag"] = "0" * len(encrypted["tag"])
        with self.assertRaises(SRunError) as ctx:
            decrypt_secret(tampered_tag)
        self.assertIn("authentication tag mismatch", str(ctx.exception))

        # Tampered ciphertext
        tampered_cipher = dict(encrypted)
        cipher_bytes = bytearray(bytes.fromhex(encrypted["ciphertext"]))
        cipher_bytes[0] ^= 0xFF
        tampered_cipher["ciphertext"] = cipher_bytes.hex()
        with self.assertRaises(SRunError) as ctx:
            decrypt_secret(tampered_cipher)
        self.assertIn("authentication tag mismatch", str(ctx.exception))

        # Mismatched machine identity
        wrong_identity = b"different_machine_identity_32byt"
        with self.assertRaises(SRunError) as ctx:
            decrypt_secret(encrypted, identity=wrong_identity)
        self.assertIn("authentication tag mismatch", str(ctx.exception))

    def test_save_config_and_load_config(self):
        path = self.config_path
        saved_path = save_config(
            username="student_007",
            password="my_secret_password",
            portal="http://10.20.69.103",
            ac_id="3",
            config_path=path,
        )
        self.assertEqual(saved_path, path)
        self.assertTrue(os.path.isfile(path))

        # Check file permissions (0600)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode, 0o600)

        # Ensure plaintext password is NOT in raw file
        with open(path, "r", encoding="utf-8") as f:
            raw_content = f.read()
            self.assertNotIn("my_secret_password", raw_content)
            data = json.loads(raw_content)
            self.assertIn("auth_secret", data)
            self.assertEqual(data["username"], "student_007")
            self.assertEqual(data["portal"], "http://10.20.69.103")
            self.assertEqual(data["ac_id"], "3")

        # Load and verify decryption
        loaded = load_config(path)
        self.assertEqual(loaded["username"], "student_007")
        self.assertEqual(loaded["password"], "my_secret_password")
        self.assertTrue(loaded["has_password"])
        self.assertEqual(loaded["portal"], "http://10.20.69.103")
        self.assertEqual(loaded["ac_id"], "3")

    def test_save_config_merge_preserves_existing_password(self):
        path = self.config_path
        save_config(username="user1", password="original_password", config_path=path)

        # Update portal without providing password (password=None, merge=True)
        save_config(username="user1", portal="http://new-portal", config_path=path)

        loaded = load_config(path)
        self.assertEqual(loaded["username"], "user1")
        self.assertEqual(loaded["password"], "original_password")
        self.assertEqual(loaded["portal"], "http://new-portal")

    def test_delete_config(self):
        path = self.config_path
        save_config(username="temp_user", config_path=path)
        self.assertTrue(os.path.isfile(path))

        self.assertTrue(delete_config(path))
        self.assertFalse(os.path.isfile(path))
        self.assertFalse(delete_config(path))

    def test_load_config_nonexistent_returns_empty(self):
        loaded = load_config(os.path.join(self.temp_dir.name, "does_not_exist.json"))
        self.assertEqual(loaded, {})

    def test_load_credentials_from_config(self):
        path = self.config_path
        save_config(username="auto_user", password="auto_password", config_path=path)

        parser = build_parser()
        args = parser.parse_args(["login", "--config-path", path])

        with patch.dict(os.environ, {}, clear=True):
            creds = load_credentials(args)
            self.assertEqual(creds.username, "auto_user")
            self.assertEqual(creds.password, "auto_password")
            self.assertTrue(creds.from_config)
            self.assertFalse(creds.is_interactive)
            # Verify 2-tuple unpacking works identically
            u, p = creds
            self.assertEqual(u, "auto_user")
            self.assertEqual(p, "auto_password")

    def test_load_credentials_cli_and_env_precedence(self):
        path = self.config_path
        save_config(username="config_user", password="config_password", config_path=path)

        parser = build_parser()

        # Env precedence over config
        args1 = parser.parse_args(["login", "--config-path", path])
        with patch.dict(os.environ, {"SRUN_USERNAME": "env_user", "SRUN_PASSWORD": "env_password"}):
            creds1 = load_credentials(args1)
            self.assertEqual(creds1.username, "env_user")
            self.assertEqual(creds1.password, "env_password")
            self.assertFalse(creds1.from_config)

        # CLI precedence over env and config
        args2 = parser.parse_args(["login", "-u", "cli_user", "-p", "cli_password", "--config-path", path])
        with patch.dict(os.environ, {"SRUN_USERNAME": "env_user", "SRUN_PASSWORD": "env_password"}):
            creds2 = load_credentials(args2)
            self.assertEqual(creds2.username, "cli_user")
            self.assertEqual(creds2.password, "cli_password")
            self.assertFalse(creds2.from_config)

    def test_config_subcommand_show_and_clear(self):
        path = self.config_path
        save_config(username="cfg_demo", password="secret_val", portal="http://portal.local", config_path=path)

        buf = io.StringIO()
        with redirect_stdout(buf):
            ret = main(["config", "--config-path", path])
        self.assertEqual(ret, 0)
        out = buf.getvalue()
        self.assertIn("cfg_demo", out)
        self.assertIn("[Stored & Encrypted with machine key]", out)
        self.assertNotIn("secret_val", out)

        buf_clear = io.StringIO()
        with redirect_stdout(buf_clear):
            ret_clear = main(["config", "--clear-config", "--config-path", path])
        self.assertEqual(ret_clear, 0)
        self.assertFalse(os.path.isfile(path))

    def test_config_save_subcommand(self):
        path = self.config_path
        buf = io.StringIO()
        with redirect_stdout(buf):
            ret = main(["config", "--save", "-u", "manual_user", "-p", "manual_pass", "--config-path", path])
        self.assertEqual(ret, 0)
        loaded = load_config(path)
        self.assertEqual(loaded["username"], "manual_user")
        self.assertEqual(loaded["password"], "manual_pass")

    def test_login_save_flag(self):
        path = self.config_path

        class DummyClient(SRunClient):
            def __init__(self, *args, **kwargs):
                super().__init__(retries=0, retry_delay=0)

            def login(self, username, password, **kwargs):
                return {"error": "ok", "ecode": "0", "error_msg": "Login success"}

        with patch("srun_auth.cli.SRunClient", DummyClient):
            buf = io.StringIO()
            with redirect_stdout(buf):
                ret = main(["login", "-u", "save_flag_user", "-p", "save_flag_pass", "--save", "--config-path", path])
            self.assertEqual(ret, 0)

        loaded = load_config(path)
        self.assertEqual(loaded["username"], "save_flag_user")
        self.assertEqual(loaded["password"], "save_flag_pass")


if __name__ == "__main__":
    unittest.main()
