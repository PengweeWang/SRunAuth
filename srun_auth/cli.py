"""Command-line interface for SRun campus network authentication."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from typing import Any

from .client import (
    DEFAULT_PORTAL,
    DEFAULT_PROBE_URL,
    SRunClient,
    SRunError,
    _print_table,
    parse_online_devices,
    response_message,
)

def load_credentials(args: argparse.Namespace) -> tuple[str, str]:
    """Read campus network username and password from CLI args, environment, or interactive input."""
    username = args.username or os.environ.get("SRUN_USERNAME", "")
    if not username:
        username = input("Username: ").strip()
    password = os.environ.get("SRUN_PASSWORD", "")
    if not password and not args.no_prompt:
        password = getpass.getpass("Password: ")
    if not username or not password:
        raise SRunError("Missing username or password; set SRUN_USERNAME/SRUN_PASSWORD for automated runs")
    return username, password


def print_status(client: SRunClient, response: dict[str, Any]) -> None:
    """Print current authentication online or offline status."""
    if client.is_online(response):
        ip = response.get("online_ip") or client.ip or "Unknown"
        print(f"Online: {response.get('user_name')} ({ip})")
    else:
        print(f"Offline: {response_message(response)}")


def print_devices(
    client: SRunClient, response: dict[str, Any], username: str = ""
) -> None:
    """Display online devices list for specified account or current IP."""
    if client.is_online(response):
        user_name = response.get("user_name") or username
        devices = parse_online_devices(response)
        current_ip = str(response.get("online_ip") or client.ip or "")
        reported_total = response.get("online_device_total", len(devices))
        print(f"Account: {user_name}  Online devices: {reported_total}")
        if not devices:
            print("Portal did not return device details")
            return

        rows = [["CURRENT", "ID", "IPv4", "IPv6", "Device/Type", "OS"]]
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
        _print_table(rows)
        return

    if username:
        devices_list = client.get_online_devices(username=username)
        if not devices_list:
            print(f"Account: {username}  No online devices found")
            return
        print(f"Account: {username}  Online devices: {len(devices_list)}")
        rows = [["ID", "IP", "MAC", "Device/Type", "OS", "Login Time"]]
        for d in devices_list:
            rows.append(
                [
                    d.get("id", "-"),
                    d.get("ip", "-"),
                    d.get("mac", "-") or "-",
                    d.get("device", "-") or "-",
                    d.get("os", "-") or "-",
                    d.get("add_time", "-") or "-",
                ]
            )
        _print_table(rows)
        return

    raise SRunError(
        f"Current IP is not online, unable to query account devices: {response_message(response)}; specify account with -u"
    )


def build_parser() -> argparse.ArgumentParser:
    """Build command-line argument parser."""
    parser = argparse.ArgumentParser(description="SRun Campus Network Automatic Authentication")
    parser.add_argument(
        "command",
        nargs="?",
        choices=("status", "devices", "login", "logout", "kick", "watch"),
        default="login",
        help="Action to execute: status, devices, login, logout/kick, watch",
    )
    parser.add_argument("-u", "--username", help="Campus network username, or use env SRUN_USERNAME")
    parser.add_argument(
        "--portal",
        default=os.environ.get("SRUN_PORTAL", DEFAULT_PORTAL),
        help=f"SRun portal URL (default: {DEFAULT_PORTAL}, or use env SRUN_PORTAL)",
    )
    parser.add_argument(
        "--ac-id",
        default=os.environ.get("SRUN_AC_ID", "1"),
        help="Access controller ID (ac_id) (default: 1, or use env SRUN_AC_ID)",
    )
    parser.add_argument(
        "--ip",
        default=os.environ.get("SRUN_IP", ""),
        help="Local IP address, usually left empty for portal auto-detection (or use env SRUN_IP)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="HTTP request timeout in seconds (default: 8.0)",
    )
    parser.add_argument(
        "--probe-url",
        default=os.environ.get("SRUN_PROBE_URL", DEFAULT_PROBE_URL),
        help=f"HTTP URL to trigger gateway redirect; pass empty string to disable (default: {DEFAULT_PROBE_URL}, or use env SRUN_PROBE_URL)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=1,
        help="Retry count on no-response error (default: 1)",
    )
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=3.0,
        help="Retry delay in seconds (default: 3.0)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=30.0,
        help="Interval in seconds between watch checks (default: 30.0)",
    )
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="Disable interactive password prompt and interactive device kick selection",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON response from portal",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Output access parameter refresh details and debug logs",
    )
    parser.add_argument(
        "--auto-kick",
        nargs="?",
        const="oldest",
        choices=("oldest", "newest", "all", "none", "interactive"),
        default=None,
        help="Automatic kick policy when device limit is exceeded (E2620): oldest, newest, all, none, interactive. Defaults to oldest if specified without value",
    )
    parser.add_argument(
        "--kick-ip",
        default="",
        help="Target device IP to logout/kick",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Logout all online devices under the account when using logout/kick command",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Command-line main entry point."""
    args = build_parser().parse_args(argv)
    auto_kick_arg = args.auto_kick
    if auto_kick_arg is None:
        if args.no_prompt or not sys.stdin.isatty():
            auto_kick_arg = "none"
        else:
            auto_kick_arg = "interactive"

    client = SRunClient(
        portal=args.portal,
        ac_id=args.ac_id,
        timeout=args.timeout,
        ip=args.ip,
        probe_url=args.probe_url,
        retries=args.retries,
        retry_delay=args.retry_delay,
        verbose=args.verbose,
        auto_kick=auto_kick_arg,
        kick_ip=args.kick_ip,
        interactive=not args.no_prompt,
    )

    if args.command in {"status", "devices"}:
        response = client.status()
        if args.json:
            print(json.dumps(response, ensure_ascii=False, indent=2, sort_keys=True))
        elif args.command == "status":
            print_status(client, response)
        else:
            username = args.username or os.environ.get("SRUN_USERNAME", "")
            print_devices(client, response, username=username)
        return 0

    if args.command in {"logout", "kick"}:
        current_status = client.status()
        online = client.is_online(current_status)
        current_ip = str(current_status.get("online_ip") or client.ip or "")
        current_user = str(current_status.get("user_name") or "")

        username = args.username or os.environ.get("SRUN_USERNAME", "") or current_user
        if not username:
            if not args.no_prompt and sys.stdin.isatty():
                username = input("Username: ").strip()
            if not username:
                raise SRunError("Missing username; please specify account with -u/--username")

        if args.all:
            devices = client.get_online_devices(username=username)
            if not devices:
                print(f"No online devices found for account {username}")
                return 0
            print(f"Logging out all online devices for account {username} ({len(devices)} device(s)):")
            for dev in devices:
                ip = dev.get("ip")
                if not ip:
                    continue
                try:
                    client.dm_logout(username, ip)
                    print(f"  Logged out: {ip} ({dev.get('os') or dev.get('device') or 'Unknown Device'})")
                except SRunError as exc:
                    print(f"  Failed to logout {ip}: {exc}", file=sys.stderr)
            return 0

        target_ip = args.ip or args.kick_ip
        if target_ip:
            client.dm_logout(username, target_ip)
            print(f"Logout successful: Logged out device for {username} ({target_ip})")
            return 0

        if online and current_ip:
            client.dm_logout(username, current_ip)
            print(f"Logout successful: Logged out local device {username} ({current_ip})")
            return 0

        devices = client.get_online_devices(username=username)
        if not devices:
            print("Current device is offline, and no other online devices were found for this account")
            return 0

        if not args.no_prompt and sys.stdin.isatty():
            target_ips = client.prompt_select_devices_to_kick(
                username, devices, {"message": "Current device is offline, please select an online device to logout"}
            )
            for ip in target_ips:
                client.dm_logout(username, ip)
                print(f"Logout successful: Logged out device ({ip})")
            return 0
        else:
            raise SRunError("Current device is not online; please specify device to logout using --ip <IP> or --all")

    username, password = load_credentials(args)
    auto_kick = args.auto_kick
    if auto_kick is None:
        if args.no_prompt or not sys.stdin.isatty():
            auto_kick = "none"
        else:
            auto_kick = "interactive"
    interactive = (not args.no_prompt) and sys.stdin.isatty() and auto_kick == "interactive"

    if args.command == "login":
        response = client.login(
            username,
            password,
            auto_kick=auto_kick,
            kick_ip=args.kick_ip,
            interactive=interactive,
        )
        print(f"Authentication successful: {response_message(response)}")
        return 0

    if args.interval < 5:
        raise SRunError("Watch --interval cannot be less than 5 seconds")
    print(f"Started monitoring, checking every {args.interval:g}s; press Ctrl-C to stop")
    while True:
        try:
            status = client.status()
            if not client.is_online(status):
                response = client.login(
                    username,
                    password,
                    auto_kick=auto_kick,
                    kick_ip=args.kick_ip,
                    interactive=interactive,
                )
                print(f"[{time.strftime('%F %T')}] Authentication successful: {response_message(response)}")
        except SRunError as exc:
            print(f"[{time.strftime('%F %T')}] {exc}", file=sys.stderr)
        time.sleep(args.interval)




def cli_entry() -> None:
    """CLI entry point for console scripts with friendly error output."""
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nStopped")
        sys.exit(130)
    except SRunError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    cli_entry()
