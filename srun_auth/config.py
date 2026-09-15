"""Configuration file and encrypted credential management for SRun authentication."""
from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import platform
import secrets
import struct
import uuid
from typing import Any

from .client import SRunError

CONFIG_VERSION = 1
ALGORITHM_NAME = "PBKDF2-HMAC-SHA256-CTR"
PBKDF2_ROUNDS = 100000


def get_default_config_path() -> str:
    """Return default configuration file path following XDG spec."""
    env_path = os.environ.get("SRUN_CONFIG")
    if env_path:
        return os.path.abspath(os.path.expanduser(env_path))

    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config:
        base_dir = os.path.abspath(os.path.expanduser(xdg_config))
    else:
        base_dir = os.path.expanduser("~/.config")
    return os.path.join(base_dir, "srunauth", "config.json")


def get_machine_identity() -> bytes:
    """Gather unique machine and user identity elements to bind credentials locally."""
    parts: list[str] = []

    # 1. System machine-id
    machine_id = ""
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id", "/etc/hostid"):
        try:
            if os.path.isfile(path):
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if content:
                        machine_id = content
                        break
        except OSError:
            pass

    if machine_id:
        parts.append(f"machine_id:{machine_id}")
    else:
        # Fallback for systems without /etc/machine-id (e.g. macOS/BSD/Windows)
        try:
            node = uuid.getnode()
            parts.append(f"mac:{node}")
        except Exception:
            pass
        parts.append(f"host:{platform.node()}")

    parts.append(f"system:{platform.system()}")

    # User identity (binds to the specific local user account)
    try:
        parts.append(f"uid:{os.getuid()}")
    except AttributeError:
        pass
    try:
        parts.append(f"user:{getpass.getuser()}")
    except Exception:
        pass

    raw = "|".join(parts).encode("utf-8")
    return hashlib.sha256(b"srunauth:identity:v1:" + raw).digest()


def encrypt_secret(plaintext: str, identity: bytes | None = None) -> dict[str, Any]:
    """Encrypt a secret string using machine-bound PBKDF2-HMAC-SHA256-CTR and HMAC tag."""
    if not isinstance(plaintext, str):
        raise TypeError("Plaintext secret must be a string")

    if identity is None:
        identity = get_machine_identity()

    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)

    # Derive 64 bytes: 32 bytes encryption key, 32 bytes MAC key
    derived = hashlib.pbkdf2_hmac("sha256", identity, salt, PBKDF2_ROUNDS, 64)
    enc_key = derived[:32]
    mac_key = derived[32:]

    plain_bytes = plaintext.encode("utf-8")

    # Generate keystream using HMAC-SHA256 in counter mode
    keystream = b""
    counter = 0
    while len(keystream) < len(plain_bytes):
        block = hmac.new(enc_key, nonce + struct.pack(">I", counter), hashlib.sha256).digest()
        keystream += block
        counter += 1

    ciphertext = bytes(p ^ k for p, k in zip(plain_bytes, keystream[:len(plain_bytes)]))
    tag = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).hexdigest()

    return {
        "version": CONFIG_VERSION,
        "algorithm": ALGORITHM_NAME,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag,
    }


def decrypt_secret(secret_dict: dict[str, Any], identity: bytes | None = None) -> str:
    """Decrypt a machine-bound secret dictionary into plaintext string."""
    if not isinstance(secret_dict, dict):
        raise SRunError("Invalid secret format: expected JSON object")

    try:
        salt = bytes.fromhex(secret_dict["salt"])
        nonce = bytes.fromhex(secret_dict["nonce"])
        ciphertext = bytes.fromhex(secret_dict["ciphertext"])
        tag = str(secret_dict["tag"])
    except (KeyError, ValueError, TypeError) as exc:
        raise SRunError(f"Malformed encrypted secret data: {exc}") from exc

    if identity is None:
        identity = get_machine_identity()

    derived = hashlib.pbkdf2_hmac("sha256", identity, salt, PBKDF2_ROUNDS, 64)
    enc_key = derived[:32]
    mac_key = derived[32:]

    expected_tag = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(tag, expected_tag):
        raise SRunError(
            "Failed to decrypt stored credentials: authentication tag mismatch "
            "(credential data was corrupted or copied from another machine/user)"
        )

    keystream = b""
    counter = 0
    while len(keystream) < len(ciphertext):
        block = hmac.new(enc_key, nonce + struct.pack(">I", counter), hashlib.sha256).digest()
        keystream += block
        counter += 1

    plain_bytes = bytes(p ^ k for p, k in zip(ciphertext, keystream[:len(ciphertext)]))
    try:
        return plain_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SRunError(f"Decrypted credential payload is not valid UTF-8: {exc}") from exc


def save_config(
    username: str,
    password: str | None = None,
    portal: str | None = None,
    ac_id: str | None = None,
    config_path: str | None = None,
    extra: dict[str, Any] | None = None,
    merge: bool = True,
) -> str:
    """Save credentials and configuration to secure config file with 0600 permissions."""
    path = config_path or get_default_config_path()
    dir_path = os.path.dirname(path)
    if dir_path:
        os.makedirs(dir_path, mode=0o700, exist_ok=True)

    data: dict[str, Any] = {}
    if merge and os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    data = loaded
        except Exception:
            data = {}

    data["version"] = CONFIG_VERSION
    data["username"] = username

    if portal is not None:
        data["portal"] = portal
    if ac_id is not None:
        data["ac_id"] = str(ac_id)

    if extra:
        for k, v in extra.items():
            if k not in {"password", "auth_secret"}:
                data[k] = v

    if password is not None:
        if password:
            data["auth_secret"] = encrypt_secret(password)
        else:
            data.pop("auth_secret", None)
    elif "auth_secret" in data and data.get("username") != username:
        data.pop("auth_secret", None)

    content = json.dumps(data, ensure_ascii=False, indent=2)

    # Secure write with 0600 permissions
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    mode = 0o600
    fd = os.open(path, flags, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content + "\n")
    except Exception:
        raise

    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

    return path


def load_config(config_path: str | None = None) -> dict[str, Any]:
    """Load configuration from file, decrypting stored credentials if present."""
    path = config_path or get_default_config_path()
    if not os.path.isfile(path):
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise SRunError(f"Failed to read config file {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise SRunError(f"Invalid config format in {path}: expected JSON object")

    result: dict[str, Any] = {
        "config_path": path,
        "username": str(data.get("username") or ""),
        "portal": str(data.get("portal") or ""),
        "ac_id": str(data.get("ac_id") or ""),
    }

    for k, v in data.items():
        if k not in result and k not in {"auth_secret"}:
            result[k] = v

    auth_secret = data.get("auth_secret")
    if auth_secret:
        if isinstance(auth_secret, dict):
            try:
                result["password"] = decrypt_secret(auth_secret)
                result["has_password"] = True
            except SRunError as exc:
                result["password_error"] = str(exc)
                result["has_password"] = False
        else:
            result["password_error"] = "Invalid auth_secret structure"
            result["has_password"] = False
    else:
        result["has_password"] = False

    return result


def delete_config(config_path: str | None = None) -> bool:
    """Delete configuration file if present."""
    path = config_path or get_default_config_path()
    if os.path.isfile(path):
        try:
            os.remove(path)
            return True
        except OSError as exc:
            raise SRunError(f"Failed to delete config file {path}: {exc}") from exc
    return False
