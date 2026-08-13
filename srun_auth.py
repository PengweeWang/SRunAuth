#!/usr/bin/env python3
"""Authenticate against the SRun portal used by this campus network."""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


DEFAULT_PORTAL = "http://10.20.69.103"
SRUN_BASE64_ALPHABET = (
    "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
)
STANDARD_BASE64_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)


class SRunError(RuntimeError):
    """An expected portal or protocol error."""


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
    """Return the byte string produced by the portal's XXTEA-like encoder."""
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
    payload = json.dumps(info, ensure_ascii=False, separators=(",", ":"))
    encoded = base64.b64encode(xencode(payload, token)).decode("ascii")
    translation = str.maketrans(STANDARD_BASE64_ALPHABET, SRUN_BASE64_ALPHABET)
    return "{SRBX1}" + encoded.translate(translation)


def parse_jsonp(payload: bytes) -> dict[str, Any]:
    text = payload.decode("utf-8-sig").strip()
    if text.startswith("{"):
        value = json.loads(text)
    else:
        left = text.find("(")
        right = text.rfind(")")
        if left < 0 or right <= left:
            raise SRunError(f"无法解析门户响应: {text[:200]}")
        value = json.loads(text[left + 1 : right])
    if not isinstance(value, dict):
        raise SRunError("门户返回的不是 JSON 对象")
    return value


def response_message(response: dict[str, Any]) -> str:
    for field in ("error_msg", "suc_msg", "error", "res", "message"):
        value = response.get(field)
        if value:
            return str(value)
    return json.dumps(response, ensure_ascii=False)


def parse_online_devices(response: dict[str, Any]) -> list[dict[str, str]]:
    details = response.get("online_device_detail") or {}
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except json.JSONDecodeError as exc:
            raise SRunError(f"无法解析在线设备详情: {exc}") from exc
    if not isinstance(details, dict):
        raise SRunError("门户返回的在线设备详情格式不正确")

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


@dataclass
class SRunClient:
    portal: str = DEFAULT_PORTAL
    ac_id: str = "1"
    timeout: float = 8.0
    ip: str = ""

    def __post_init__(self) -> None:
        self.portal = self.portal.rstrip("/")
        parsed = urllib.parse.urlsplit(self.portal)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise SRunError(f"无效的门户地址: {self.portal}")

    def _get(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        query = urllib.parse.urlencode(
            {key: value for key, value in params.items() if value is not None}
        )
        url = f"{self.portal}{path}?{query}"
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "User-Agent": "srun-auth/1.0",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return parse_jsonp(response.read())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:300]
            raise SRunError(f"门户返回 HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise SRunError(f"无法连接门户 {self.portal}: {exc}") from exc

    def status(self) -> dict[str, Any]:
        return self._get(
            "/cgi-bin/rad_user_info",
            {"callback": "_srun_cb", "ip": self.ip},
        )

    @staticmethod
    def is_online(response: dict[str, Any]) -> bool:
        return response.get("error") == "ok" and bool(response.get("user_name"))

    def _challenge(self, username: str) -> tuple[str, str]:
        response = self._get(
            "/cgi-bin/get_challenge",
            {"callback": "_srun_cb", "username": username, "ip": self.ip},
        )
        if response.get("error") != "ok" or not response.get("challenge"):
            raise SRunError(f"获取 challenge 失败: {response_message(response)}")
        client_ip = self.ip or str(response.get("client_ip") or "")
        if not client_ip:
            raise SRunError("challenge 响应中没有客户端 IP，请用 --ip 显式指定")
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
            raise SRunError("门户要求图片验证码，自动认证已停止；请先在网页中完成验证")

    def login(self, username: str, password: str) -> dict[str, Any]:
        current = self.status()
        if self.is_online(current):
            return {"error": "ok", "suc_msg": "already_online", **current}

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
                "nas_ip": "",
                "double_stack": "0",
                "chksum": checksum,
                "info": info,
                "ac_id": self.ac_id,
                "ip": client_ip,
                "n": "200",
                "type": "1",
            },
        )
        if response.get("error") != "ok":
            raise SRunError(f"认证失败: {response_message(response)}")
        self.ip = client_ip
        return response


def load_credentials(args: argparse.Namespace) -> tuple[str, str]:
    username = args.username or os.environ.get("SRUN_USERNAME", "")
    if not username:
        username = input("校园网账号: ").strip()
    password = os.environ.get("SRUN_PASSWORD", "")
    if not password and not args.no_prompt:
        password = getpass.getpass("校园网密码: ")
    if not username or not password:
        raise SRunError("缺少账号或密码；自动运行时请设置 SRUN_USERNAME/SRUN_PASSWORD")
    return username, password


def print_status(client: SRunClient, response: dict[str, Any]) -> None:
    if client.is_online(response):
        ip = response.get("online_ip") or client.ip or "未知"
        print(f"在线: {response.get('user_name')} ({ip})")
    else:
        print(f"离线: {response_message(response)}")


def print_devices(client: SRunClient, response: dict[str, Any]) -> None:
    if not client.is_online(response):
        raise SRunError(f"当前 IP 未在线，无法查询所属账号的设备: {response_message(response)}")

    devices = parse_online_devices(response)
    current_ip = str(response.get("online_ip") or client.ip or "")
    reported_total = response.get("online_device_total", len(devices))
    print(f"账号: {response.get('user_name')}  在线设备: {reported_total}")
    if not devices:
        print("门户没有返回设备详情")
        return

    rows = [["CURRENT", "ID", "IPV4", "IPV6", "DEVICE", "OS"]]
    for device in devices:
        rows.append(
            [
                "*" if device["ipv4"] == current_ip else "",
                device["id"],
                device["ipv4"] or "-",
                device["ipv6"] or "-",
                device["device"] or "-",
                device["os"] or "-",
            ]
        )
    widths = [max(len(row[index]) for row in rows) for index in range(len(rows[0]))]
    for row in rows:
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)).rstrip())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="深澜 SRun 校园网自动认证")
    parser.add_argument(
        "command",
        nargs="?",
        choices=("status", "devices", "login", "watch"),
        default="login",
    )
    parser.add_argument("-u", "--username", help="校园网账号，也可使用 SRUN_USERNAME")
    parser.add_argument("--portal", default=os.environ.get("SRUN_PORTAL", DEFAULT_PORTAL))
    parser.add_argument("--ac-id", default=os.environ.get("SRUN_AC_ID", "1"))
    parser.add_argument("--ip", default=os.environ.get("SRUN_IP", ""), help="通常留空，由门户识别")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--interval", type=float, default=30.0, help="watch 检查间隔（秒）")
    parser.add_argument("--no-prompt", action="store_true", help="禁止交互读取密码")
    parser.add_argument("--json", action="store_true", help="原样输出门户 JSON 响应")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    client = SRunClient(args.portal, args.ac_id, args.timeout, args.ip)

    if args.command in {"status", "devices"}:
        response = client.status()
        if args.json:
            print(json.dumps(response, ensure_ascii=False, indent=2, sort_keys=True))
        elif args.command == "status":
            print_status(client, response)
        else:
            print_devices(client, response)
        return 0

    username, password = load_credentials(args)
    if args.command == "login":
        response = client.login(username, password)
        print(f"认证成功: {response_message(response)}")
        return 0

    if args.interval < 5:
        raise SRunError("watch 的 --interval 不能小于 5 秒")
    print(f"开始监测，每 {args.interval:g} 秒检查一次；按 Ctrl-C 退出")
    while True:
        try:
            status = client.status()
            if not client.is_online(status):
                response = client.login(username, password)
                print(f"[{time.strftime('%F %T')}] 认证成功: {response_message(response)}")
        except SRunError as exc:
            print(f"[{time.strftime('%F %T')}] {exc}", file=sys.stderr)
        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n已停止")
        raise SystemExit(130)
    except SRunError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        raise SystemExit(1)
