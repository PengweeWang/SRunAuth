"""SRun authentication client and protocol implementation."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import struct
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


DEFAULT_PORTAL = "http://10.20.69.103"
DEFAULT_PROBE_URL = "http://www.baidu.com/"
SRUN_BASE64_ALPHABET = (
    "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
)
STANDARD_BASE64_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)


class SRunError(RuntimeError):
    """An expected portal or protocol error."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _u32(value: int) -> int:
    return value & 0xFFFFFFFF


def _utf16_code_units(value: str) -> list[int]:
    raw = value.encode("utf-16-le", errors="surrogatepass")
    return list(struct.unpack(f"<{len(raw) // 2}H", raw)) if raw else []


def _sencode(value: str, include_length: bool) -> list[int]:
    units = _utf16_code_units(value)
    result = []
    for offset in range(0, len(units), 4):
        chunk = units[offset : offset + 4]
        chunk.extend([0] * (4 - len(chunk)))
        result.append(
            chunk[0] | chunk[1] << 8 | chunk[2] << 16 | chunk[3] << 24
        )
    if include_length:
        result.append(len(units))
    return result


def xencode(value: str, key: str) -> bytes:
    """Return bytes encrypted using the portal's XXTEA-like algorithm."""
    if not value:
        return b""

    values = _sencode(value, True)
    keys = _sencode(key, False)
    keys.extend([0] * (4 - len(keys)))

    n = len(values) - 1
    z = values[n]
    total = 0
    rounds = 6 + 52 // (n + 1)
    delta = 0x9E3779B9

    for _ in range(rounds):
        total = _u32(total + delta)
        e = total >> 2 & 3
        for p in range(n):
            y = values[p + 1]
            mixed = (z >> 5) ^ _u32(y << 2)
            mixed += (y >> 3) ^ _u32(z << 4) ^ (total ^ y)
            mixed += keys[(p & 3) ^ e] ^ z
            values[p] = _u32(values[p] + mixed)
            z = values[p]

        y = values[0]
        mixed = (z >> 5) ^ _u32(y << 2)
        mixed += (y >> 3) ^ _u32(z << 4) ^ (total ^ y)
        mixed += keys[(n & 3) ^ e] ^ z
        values[n] = _u32(values[n] + mixed)
        z = values[n]

    return b"".join(struct.pack("<I", item) for item in values)


def encode_info(info: dict[str, Any], token: str) -> str:
    """Encode authentication info using the portal's custom {SRBX1} format."""
    payload = json.dumps(info, ensure_ascii=False, separators=(",", ":"))
    encoded = base64.b64encode(xencode(payload, token)).decode("ascii")
    translation = str.maketrans(STANDARD_BASE64_ALPHABET, SRUN_BASE64_ALPHABET)
    return "{SRBX1}" + encoded.translate(translation)


def parse_jsonp(payload: bytes) -> dict[str, Any]:
    """Parse JSONP response from portal into a dictionary."""
    text = payload.decode("utf-8-sig").strip()
    if text.startswith("{"):
        value = json.loads(text)
    else:
        left = text.find("(")
        right = text.rfind(")")
        if left < 0 or right <= left:
            raise SRunError(f"Failed to parse portal response: {text[:200]}")
        value = json.loads(text[left + 1 : right])
    if not isinstance(value, dict):
        raise SRunError("Portal response is not a JSON object")
    return value


PORTAL_MESSAGES: dict[str, str] = {
    "login_ok": "Login successful",
    "already_online": "Already online",
    "online_after_no_response": "Online detected after retry",
    "LogoutOK": "Logout successful",
    "logout_ok": "Logout successful",
    "not_online_error": "Not online",
    "password_error": "Incorrect password",
    "user_not_found": "Account not found",
    "user_not_exist": "Account does not exist",
    "user_is_not_exist": "Account does not exist",
    "no_response_data_error": "Authentication gateway no response",
    "RD000": "Authentication gateway no response (RD000)",
    "portal_is_busy": "Portal is busy",
    "ip_error": "IP address error",
    "mac_error": "MAC address error",
    "acid_error": "Access Controller (AC) ID error",
    "user_name_error": "Username error",
    "user_password_error": "Incorrect password",
    "users_over": "Maximum online users limit reached",
    "flow_over": "Data usage limit exceeded",
    "fee_over": "Insufficient balance or overdue account",
    "time_over": "Online duration limit exceeded",
    "ip_limit": "IP binding restricted",
    "mac_limit": "MAC binding restricted",
    "auth_times_over": "Authentication attempts too frequent",
}


def response_message(response: dict[str, Any]) -> str:
    """Extract message from portal response and convert known status codes to readable text."""
    for field in ("error_msg", "suc_msg", "error", "res", "message"):
        value = response.get(field)
        if value:
            msg = str(value)
            return PORTAL_MESSAGES.get(msg, msg)
    return json.dumps(response, ensure_ascii=False)


def parse_access_context(redirect_url: str, portal: str) -> dict[str, str]:
    """Parse network access parameters (ac_id, ip, mac, etc.) from gateway redirect URL."""
    redirect = urllib.parse.urlsplit(redirect_url)
    portal_url = urllib.parse.urlsplit(portal)
    if redirect.hostname != portal_url.hostname:
        return {}

    query_str = redirect.query
    if not query_str and "?" in redirect.fragment:
        query_str = redirect.fragment.split("?", 1)[1]

    query = {
        key.lower(): values[0]
        for key, values in urllib.parse.parse_qs(
            query_str, keep_blank_values=False
        ).items()
        if values
    }

    def first(*names: str) -> str:
        return next((query[name] for name in names if query.get(name)), "")

    ac_id = first("ac_id", "acid", "ac")
    if not ac_id and redirect.path:
        path_match = re.search(
            r"(?:index|srun_portal(?:_pc)?)_(\d+)\.html?", redirect.path, re.IGNORECASE
        )
        if path_match:
            ac_id = path_match.group(1)

    nas_ip = first("nas_ip", "ac_ip", "nasip", "acip", "wlanacip")
    if nas_ip == "0.0.0.0":
        nas_ip = ""

    return {
        "ac_id": ac_id,
        "ip": first("user_ip", "client_ip", "online_ip", "ip", "wlanuserip", "userip", "user-ip"),
        "nas_ip": nas_ip,
        "ap_id": first("ap_id", "apid"),
        "ap_ip": first("ap_ip", "apip"),
        "mac": first("user_mac", "client_mac", "mac", "usermac", "wlanusermac", "user-mac"),
    }


def is_no_response_error(response: dict[str, Any]) -> bool:
    """Check if the portal response indicates a gateway no-response error."""
    values = (
        response.get("error"),
        response.get("error_msg"),
        response.get("res"),
        response.get("ecode"),
        response.get("message"),
    )
    return any(value in {"no_response_data_error", "RD000"} for value in values)


def parse_online_devices(response: dict[str, Any]) -> list[dict[str, str]]:
    """Parse online device details returned by rad_user_info."""
    details = response.get("online_device_detail") or {}
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except json.JSONDecodeError as exc:
            raise SRunError(f"Failed to parse online device details: {exc}") from exc
    if not isinstance(details, dict):
        raise SRunError("Invalid online device details format returned by portal")

    devices = []
    for record_id, value in details.items():
        if not isinstance(value, dict):
            continue
        devices.append(
            {
                "id": str(value.get("rad_online_id") or record_id),
                "ipv4": str(value.get("ip") or ""),
                "ipv6": str(value.get("ip6") or ""),
                "device": str(value.get("class_name") or ""),
                "os": str(value.get("os_name") or ""),
            }
        )
    return devices


def format_add_time(timestamp: Any) -> str:
    """Format Unix timestamp into yyyy-MM-dd HH:mm:ss string."""
    if not timestamp:
        return ""
    try:
        val = int(timestamp)
        if 1000000000 <= val <= 2500000000:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(val))
    except (ValueError, TypeError, OSError):
        pass
    return str(timestamp)


def parse_device_manager_list(response: dict[str, Any]) -> list[dict[str, str]]:
    """Parse online device list returned by /v1/auth/device/get."""
    raw_list = response.get("data") or []
    if not isinstance(raw_list, list):
        return []
    devices = []
    for item in raw_list:
        if not isinstance(item, dict):
            continue
        if item.get("is_online") is False:
            continue
        ip = str(item.get("ip") or item.get("online_ip") or item.get("user_ip") or "")
        devices.append(
            {
                "id": str(item.get("rad_online_id") or ""),
                "ip": ip,
                "mac": str(item.get("user_mac") or ""),
                "device": str(
                    item.get("device_name")
                    or item.get("device_type")
                    or item.get("class_name")
                    or ""
                ),
                "os": str(item.get("os_name") or ""),
                "add_time": format_add_time(item.get("add_time")),
                "raw_add_time": str(item.get("add_time") or "0"),
            }
        )
    return devices


def dm_sign(timestamp: str, username: str, ip: str, unbind: str = "1") -> str:
    """Calculate SHA-1 signature for SRun DM logout request."""
    source = f"{timestamp}{username}{ip}{unbind}{timestamp}"
    return hashlib.sha1(source.encode("utf-8")).hexdigest()


def is_dm_success(response: dict[str, Any]) -> bool:
    """Check if rad_user_dm logout call was successful."""
    values = (
        response.get("error"),
        response.get("res"),
        response.get("error_msg"),
        response.get("suc_msg"),
        response.get("message"),
    )
    if any(val in {"ok", "LogoutOK"} for val in values):
        return True
    if response.get("code") == 0 and response.get("error") in {None, "", "ok"}:
        return True
    return False


def is_overlimit_error(response: dict[str, Any]) -> bool:
    """Check if the response indicates maximum online devices limit reached (E2620 / E3008)."""
    code = str(response.get("ecode") or response.get("error") or "")
    msg = str(
        response.get("message")
        or response.get("error_msg")
        or response.get("res")
        or ""
    )
    if code in {"E2620", "E3008"}:
        return True
    if msg.startswith("E2620") or msg.startswith("E3008"):
        return True
    if bool(response.get("overlimit_token")):
        return True
    overlimit_keywords = (
        "maximum online devices reached",
        "exceeded allowed online count",
        "excessive connections",
        "online users full",
        "exceededonlinenumber",
        "\u8d85\u51fa\u5141\u8bb8\u7684\u5728\u7ebf\u6570\u91cf",
        "\u8fde\u7ebf\u6570\u8d85\u989d",
        "\u5728\u7ebf\u8bbe\u5907\u6570\u91cf\u5df2\u8fbe\u4e0a\u9650",
        "\u5728\u7ebf\u7528\u6237\u5df2\u6ee1",
    )
    msg_lower = msg.lower()
    return any(k.lower() in msg_lower or k in msg for k in overlimit_keywords)


def _display_width(text: str) -> int:
    """Calculate display width of a string in terminal (handling wide characters)."""
    return sum(2 if unicodedata.east_asian_width(c) in ("F", "W") else 1 for c in text)


def _pad_string(text: str, width: int) -> str:
    """Pad string to align with terminal display width."""
    dw = _display_width(text)
    return text + " " * max(0, width - dw)


def _print_table(rows: list[list[str]], indent: str = "") -> None:
    """Print aligned table columns (supporting mixed East Asian and Western text)."""
    if not rows:
        return
    widths = [
        max(_display_width(row[col]) for row in rows)
        for col in range(len(rows[0]))
    ]
    for row in rows:
        print(indent + "  ".join(_pad_string(val, widths[col]) for col, val in enumerate(row)).rstrip())


@dataclass
class SRunClient:
    """SRun campus network authentication client."""
    portal: str = DEFAULT_PORTAL
    ac_id: str = "1"
    timeout: float = 8.0
    ip: str = ""
    probe_url: str = DEFAULT_PROBE_URL
    retries: int = 1
    retry_delay: float = 3.0
    verbose: bool = False
    nas_ip: str = ""
    ap_id: str = ""
    ap_ip: str = ""
    mac: str = ""
    auto_kick: str = "none"
    kick_ip: str = ""
    interactive: bool = True

    def __post_init__(self) -> None:
        self.portal = self.portal.rstrip("/")
        parsed = urllib.parse.urlsplit(self.portal)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise SRunError(f"Invalid portal URL: {self.portal}")
        if self.retries < 0 or self.retries > 3:
            raise SRunError("Authentication retries must be between 0 and 3")
        if self.retry_delay < 0:
            raise SRunError("Authentication retry delay cannot be negative")
        valid_auto_kicks = {"none", "interactive", "oldest", "newest", "all"}
        if self.auto_kick not in valid_auto_kicks:
            raise SRunError(f"Invalid auto-kick policy: {self.auto_kick}")
        self._fixed_ip = bool(self.ip)

    def _log(self, message: str) -> None:
        if self.verbose:
            print(f"[srun] {message}", file=sys.stderr)

    def _get(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        query = urllib.parse.urlencode(
            {key: value for key, value in params.items() if value is not None}
        )
        url = f"{self.portal}{path}?{query}"
        if self.verbose:
            debug_params = {}
            for k, v in params.items():
                if v is None:
                    continue
                if k == "password":
                    debug_params[k] = "{MD5}***" if str(v).startswith("{MD5}") else "***"
                elif k == "info" and isinstance(v, str) and len(v) > 30:
                    debug_params[k] = f"{v[:16]}...({len(v)} chars)"
                elif k == "chksum" and isinstance(v, str) and len(v) > 16:
                    debug_params[k] = f"{v[:8]}..."
                else:
                    debug_params[k] = v
            self._log(f"HTTP GET {path} with params: {debug_params}")

        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "User-Agent": "srun-auth/1.0",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                result = parse_jsonp(response.read())
                if self.verbose:
                    self._log(f"HTTP response from {path}: {result}")
                return result
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:300]
            self._log(f"HTTP error from {path}: HTTP {exc.code} - {detail}")
            raise SRunError(f"Portal returned HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            self._log(f"Network error requesting {path}: {exc}")
            raise SRunError(f"Cannot connect to portal {self.portal}: {exc}") from exc

    def status(self) -> dict[str, Any]:
        return self._get(
            "/cgi-bin/rad_user_info",
            {"callback": "_srun_cb", "ip": self.ip if self._fixed_ip else ""},
        )

    @staticmethod
    def is_online(response: dict[str, Any]) -> bool:
        return response.get("error") == "ok" and bool(response.get("user_name"))

    def refresh_access_context(self) -> dict[str, str]:
        if not self.probe_url:
            return {}

        if not self._fixed_ip:
            self.ip = ""
        self.nas_ip = ""
        self.ap_id = ""
        self.ap_ip = ""
        self.mac = ""

        self._log(f"Probing network gateway redirect via {self.probe_url}")
        request = urllib.request.Request(
            self.probe_url,
            headers={"User-Agent": "Mozilla/5.0 srun-auth/1.1"},
        )
        opener = urllib.request.build_opener(_NoRedirect)
        location = ""
        try:
            with opener.open(request, timeout=self.timeout) as response:
                location = response.headers.get("Location", "")
                if not location:
                    self._log(f"HTTP probe returned HTTP {response.status} without redirect header")
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                location = exc.headers.get("Location", "")
            else:
                self._log(f"HTTP probe returned HTTP {exc.code}; continuing with portal-detected IP")
                return {}
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            self._log(f"HTTP probe failed: {exc}; continuing with portal-detected IP")
            return {}

        if not location:
            self._log(f"HTTP probe was not redirected by gateway (target: {self.probe_url})")
            return {}
        location = urllib.parse.urljoin(self.probe_url, location)
        self._log(f"HTTP probe redirected to: {location}")

        target_host = urllib.parse.urlsplit(location).hostname
        configured_host = urllib.parse.urlsplit(self.portal).hostname
        if target_host != configured_host:
            self._log(
                f"HTTP probe redirected to {location}, but target hostname '{target_host}' "
                f"does not match configured portal '{configured_host}' "
                f"(hint: check if --portal should be set to http://{target_host})"
            )
            return {}

        context = parse_access_context(location, self.portal)
        if not context:
            self._log("HTTP probe redirected, but target is not the current SRun portal")
            return {}

        if context["ac_id"]:
            self.ac_id = context["ac_id"]
        if context["ip"] and not self._fixed_ip:
            self.ip = context["ip"]
        self.nas_ip = context["nas_ip"]
        self.ap_id = context["ap_id"]
        self.ap_ip = context["ap_ip"]
        self.mac = context["mac"]

        present_items = [f"{key}={value}" for key, value in context.items() if value]
        if present_items:
            self._log(f"Refreshed access parameters from gateway redirect: {', '.join(present_items)}")
        else:
            raw_query = urllib.parse.urlsplit(location).query
            if not raw_query and "?" in urllib.parse.urlsplit(location).fragment:
                raw_query = urllib.parse.urlsplit(location).fragment.split("?", 1)[1]
            self._log(f"Refreshed access parameters from gateway redirect: none (query: '{raw_query or 'none'}')")
        return context

    def _challenge(self, username: str) -> tuple[str, str]:
        response = self._get(
            "/cgi-bin/get_challenge",
            {"callback": "_srun_cb", "username": username, "ip": self.ip},
        )
        if response.get("error") != "ok" or not response.get("challenge"):
            raise SRunError(f"Failed to get challenge: {response_message(response)}")
        client_ip = self.ip or str(response.get("client_ip") or "")
        if not client_ip:
            raise SRunError("No client IP in challenge response; please specify explicitly with --ip")
        if not self._fixed_ip:
            self.ip = client_ip
        self._log(f"Challenge acquired: token={response['challenge'][:8]}..., client_ip={client_ip}")
        return str(response["challenge"]), client_ip

    def _check_captcha(self, username: str, ip: str) -> None:
        try:
            response = self._get(
                "/v2/srun_portal_captcha_image_info",
                {"user_name": username, "ip": ip},
            )
        except SRunError as exc:
            if "HTTP 404" in str(exc):
                return
            raise
        if response.get("code") == 0 and str(response.get("data")) == "1":
            raise SRunError("Portal requires captcha image; automatic authentication stopped. Please verify in web browser first")

    def _login_once(self, username: str, password: str) -> dict[str, Any]:
        token, client_ip = self._challenge(username)
        self._check_captcha(username, client_ip)

        hmd5 = hmac.new(
            token.encode("utf-8"), password.encode("utf-8"), hashlib.md5
        ).hexdigest()
        info = encode_info(
            {
                "username": username,
                "password": password,
                "ip": client_ip,
                "acid": self.ac_id,
                "enc_ver": "srun_bx1",
            },
            token,
        )
        checksum_source = "".join(
            token + value
            for value in (username, hmd5, self.ac_id, client_ip, "200", "1", info)
        )
        checksum = hashlib.sha1(checksum_source.encode("utf-8")).hexdigest()

        response = self._get(
            "/cgi-bin/srun_portal",
            {
                "callback": "_srun_cb",
                "action": "login",
                "username": username,
                "password": "{MD5}" + hmd5,
                "os": "Linux",
                "name": "Linux",
                "nas_ip": self.nas_ip,
                "double_stack": "0",
                "chksum": checksum,
                "info": info,
                "ac_id": self.ac_id,
                "ip": client_ip,
                "n": "200",
                "type": "1",
                "ap_id": self.ap_id,
                "ap_ip": self.ap_ip,
                "mac": self.mac,
            },
        )
        return response

    def _portal_log(self, username: str) -> dict[str, Any] | None:
        try:
            log_resp = self._get("/v1/srun_portal_log", {"username": username})
            if log_resp:
                self._log(f"Portal log query result: {log_resp}")
            return log_resp
        except SRunError as exc:
            self._log(f"Failed to query portal log: {exc}")
            return None

    def dm_logout(self, username: str, ip: str) -> dict[str, Any]:
        """Send DM logout request to specified IP."""
        if not username:
            raise SRunError("Failed to logout device: Missing username")
        if not ip:
            raise SRunError("Failed to logout device: Missing target IP")

        now = str(int(time.time()))
        unbind = "1"
        sign = dm_sign(now, username, ip, unbind)

        response = self._get(
            "/cgi-bin/rad_user_dm",
            {
                "callback": "_srun_cb",
                "ip": ip,
                "username": username,
                "time": now,
                "unbind": unbind,
                "sign": sign,
            },
        )
        if is_dm_success(response):
            return response
        raise SRunError(f"Failed to logout device {ip}: {response_message(response)}")

    def get_online_devices(
        self, username: str = "", overlimit_token: str = ""
    ) -> list[dict[str, str]]:
        """Get user online device list via /v1/auth/device/get or rad_user_info."""
        if username:
            try:
                resp = self._get(
                    "/v1/auth/device/get",
                    {"user_name": username, "overlimit_token": overlimit_token},
                )
                if resp.get("code") == 0 and isinstance(resp.get("data"), list):
                    devices = parse_device_manager_list(resp)
                    if devices:
                        return devices
            except SRunError as exc:
                self._log(f"Failed to get online devices via /v1/auth/device/get: {exc}")

        # Fallback to online_device_detail from status() if available
        try:
            status = self.status()
            if status.get("online_device_detail"):
                raw_devices = parse_online_devices(status)
                return [
                    {
                        "id": str(d.get("id") or ""),
                        "ip": str(d.get("ipv4") or ""),
                        "mac": "",
                        "device": str(d.get("device") or ""),
                        "os": str(d.get("os") or ""),
                        "add_time": "",
                        "raw_add_time": "0",
                    }
                    for d in raw_devices
                    if d.get("ipv4")
                ]
        except SRunError as exc:
            self._log(f"Failed to get online devices via rad_user_info: {exc}")
        return []

    def prompt_select_devices_to_kick(
        self,
        username: str,
        devices: list[dict[str, str]],
        response: dict[str, Any],
    ) -> list[str]:
        """Interactively display online devices and prompt user to select devices to kick/logout."""
        print(f"\nAccount {username} online devices limit reached ({response_message(response)})")
        print("Current online devices list:")
        rows = [["#", "IP", "MAC", "Device/Type", "OS", "Login Time"]]
        for idx, dev in enumerate(devices, 1):
            rows.append(
                [
                    str(idx),
                    dev.get("ip", "-"),
                    dev.get("mac", "-") or "-",
                    dev.get("device", "-") or "-",
                    dev.get("os", "-") or "-",
                    dev.get("add_time", "-") or "-",
                ]
            )
        _print_table(rows, indent="  ")
        print()

        prompt_msg = (
            f"Select device index to logout [1-{len(devices)}] "
            "(enter 'all' to logout all, 'q' to cancel): "
        )
        while True:
            choice = input(prompt_msg).strip()
            if not choice or choice.lower() in {"q", "quit", "exit"}:
                raise SRunError("Device logout cancelled")
            if choice.lower() == "all":
                return [d["ip"] for d in devices if d.get("ip")]
            try:
                idx = int(choice)
                if 1 <= idx <= len(devices):
                    target = devices[idx - 1].get("ip")
                    if target:
                        return [target]
            except ValueError:
                pass
            print(f"Invalid input '{choice}'. Please enter a number between 1 and {len(devices)}, 'all', or 'q'")

    def handle_overlimit(
        self,
        username: str,
        response: dict[str, Any],
        auto_kick: str = "none",
        kick_ip: str = "",
        interactive: bool = True,
    ) -> bool:
        """Handle online device limit exceeded (E2620) error by kicking other devices according to policy."""
        token = str(response.get("overlimit_token") or "")
        devices = self.get_online_devices(username=username, overlimit_token=token)

        # Exclude current device's own IP if known
        current_ip = getattr(self, "ip", "")
        candidates = [d for d in devices if d.get("ip") and d.get("ip") != current_ip]
        if not candidates:
            candidates = [d for d in devices if d.get("ip")]

        if not candidates:
            raise SRunError(
                f"Maximum online devices limit reached ({response_message(response)}), but unable to retrieve kickable device list."
            )

        target_ips: list[str] = []
        if kick_ip:
            target_ips = [kick_ip]
        elif auto_kick == "oldest":
            sorted_devs = sorted(
                candidates,
                key=lambda d: int(d.get("raw_add_time") or "0") or 9999999999,
            )
            oldest = sorted_devs[0]
            target_ips = [oldest["ip"]]
            desc = oldest.get("device") or oldest.get("os") or "Unknown Device"
            print(f"Device limit exceeded. Automatically kicking oldest device: {oldest['ip']} ({desc})")
        elif auto_kick == "newest":
            sorted_devs = sorted(
                candidates,
                key=lambda d: int(d.get("raw_add_time") or "0"),
                reverse=True,
            )
            newest = sorted_devs[0]
            target_ips = [newest["ip"]]
            desc = newest.get("device") or newest.get("os") or "Unknown Device"
            print(f"Device limit exceeded. Automatically kicking newest device: {newest['ip']} ({desc})")
        elif auto_kick == "all":
            target_ips = [d["ip"] for d in candidates if d.get("ip")]
            print(f"Device limit exceeded. Automatically kicking all {len(target_ips)} other devices")
        elif interactive:
            target_ips = self.prompt_select_devices_to_kick(username, candidates, response)
        else:
            dev_ips = ", ".join(d["ip"] for d in candidates)
            raise SRunError(
                f"Authentication failed: Maximum online devices limit reached ({response_message(response)}).\n"
                f"Currently online devices: {dev_ips}.\n"
                f"Hint: Use interactive terminal to select devices to kick, or use --auto-kick [oldest|newest|all]."
            )

        if not target_ips:
            return False

        for ip in target_ips:
            self._log(f"Sending DM logout request: {ip}")
            self.dm_logout(username=username, ip=ip)
            print(f"Logged out device: {ip}")
        return True

    def login(
        self,
        username: str,
        password: str,
        auto_kick: str | None = None,
        kick_ip: str | None = None,
        interactive: bool | None = None,
    ) -> dict[str, Any]:
        """Perform authentication login, handling device overlimit by kicking devices and retrying."""
        current = self.status()
        if self.is_online(current):
            return {"error": "ok", "suc_msg": "already_online", **current}

        auto_kick = (
            auto_kick
            if auto_kick is not None
            else getattr(self, "auto_kick", "none")
        )
        kick_ip = (
            kick_ip if kick_ip is not None else getattr(self, "kick_ip", "")
        )
        if interactive is None:
            interactive = getattr(self, "interactive", True)

        last_response: dict[str, Any] = {}
        portal_log = None
        for attempt in range(self.retries + 1):
            if attempt > 0:
                self._log(f"Starting login attempt {attempt + 1}/{self.retries + 1}...")
            self.refresh_access_context()
            target_ip = getattr(self, "ip", "") or "auto"
            target_acid = getattr(self, "ac_id", "1")
            self._log(f"Attempting login for user '{username}' (IP: {target_ip}, ac_id: {target_acid})")
            last_response = self._login_once(username, password)
            if last_response.get("error") == "ok":
                self._log(f"Login successful: {response_message(last_response)}")
                return last_response

            if is_overlimit_error(last_response):
                self._log(f"Login returned device limit exceeded: {response_message(last_response)}")
                if hasattr(self, "handle_overlimit"):
                    kicked = self.handle_overlimit(
                        username=username,
                        response=last_response,
                        auto_kick=auto_kick,
                        kick_ip=kick_ip,
                        interactive=interactive,
                    )
                    if kicked:
                        time.sleep(1.5)
                        last_response = self._login_once(username, password)
                        if last_response.get("error") == "ok":
                            return last_response
                raise SRunError(f"Authentication failed: {response_message(last_response)}")

            if not is_no_response_error(last_response):
                raise SRunError(f"Authentication failed: {response_message(last_response)}")

            portal_log = self._portal_log(username)
            if portal_log and is_overlimit_error(portal_log):
                self._log(f"Portal log indicates device limit exceeded: {response_message(portal_log)}")
                if hasattr(self, "handle_overlimit"):
                    kicked = self.handle_overlimit(
                        username=username,
                        response=portal_log,
                        auto_kick=auto_kick,
                        kick_ip=kick_ip,
                        interactive=interactive,
                    )
                    if kicked:
                        time.sleep(1.5)
                        last_response = self._login_once(username, password)
                        if last_response.get("error") == "ok":
                            return last_response
                raise SRunError(f"Authentication failed: {response_message(portal_log)}")

            if attempt >= self.retries:
                break
            self._log(
                f"Received {response_message(last_response)}, "
                f"refreshing access parameters and retrying in {self.retry_delay:g}s"
            )
            time.sleep(self.retry_delay)
            current = self.status()
            if self.is_online(current):
                return {
                    "error": "ok",
                    "suc_msg": "online_after_no_response",
                    **current,
                }

        detail = response_message(last_response)
        if portal_log:
            log_message = response_message(portal_log)
            if log_message != detail:
                detail += f"; Portal log: {log_message}"
        raise SRunError(f"Authentication failed: {detail}")

