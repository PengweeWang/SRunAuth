# SRun Campus Network Automatic Authentication (SRunAuth)

An automatic authentication client and Python package for the SRun portal system (e.g., `http://10.20.69.103/`).

## Installation

Install via pip into your Python environment:

```sh
# Install from local source
pip install .

# Or install in editable / development mode
pip install -e .

# Or install directly from GitHub
pip install git+https://github.com/PengweeWang/SRunAuth.git
```

Once installed, the `srunauth` and `srun-auth` command-line tools are available globally in your environment.
Running directly via `python3 srun_auth.py` or `python3 -m srun_auth` without installation is also fully supported.

## CLI Usage

### Check Connection Status

Check current online status (no username or password required):

```sh
srunauth status
# Or: python3 srun_auth.py status
```

### Manage Online Devices

Query all online devices under the account:

```sh
srunauth devices
```

View the raw JSON response, including portal fields and `online_device_detail`:

```sh
srunauth devices --json
```

*Note: This query looks up the account by the current IP, so no password is required, but the current IP must already be online.*

### Login Authentication

Interactive login (password will be masked):

```sh
srunauth login -u your_username -v
```

After successful authentication in an interactive terminal, `srunauth` prompts whether to save your credentials. Once saved, future logins will authenticate automatically without re-entering your username or password:

```sh
# Future logins require no arguments:
srunauth login
```

You can also explicitly save credentials or skip saving:

```sh
# Force save/update credentials to configuration file
srunauth login -u your_username --save

# Disable credential saving and suppress prompt
srunauth login -u your_username --no-save
```

Before authenticating, the client probes `http://www.baidu.com/` to capture gateway redirection and automatically refreshes `ac_id` (including automatic extraction from redirect paths such as `/index_4.html`), `nas_ip`, `ap_id`, `ap_ip`, client IP, and MAC address.

If a `no_response_data_error` or `RD000` occurs, the client waits 3 seconds, checks current online status, refreshes parameters, and retries. Retries can be disabled using `--retries 0`, or gateway probing can be disabled with `--probe-url ''`.

### Configuration and Encrypted Credential Storage

`srunauth` supports storing credentials and portal settings in a local configuration file (`~/.config/srunauth/config.json`, or customized via `$SRUN_CONFIG` / `--config-path`).

**Security Design**:
- **No Plaintext Passwords**: Passwords are never written to disk in plaintext.
- **Machine & User Bound**: Credentials are encrypted using `PBKDF2-HMAC-SHA256-CTR` authenticated encryption with 100,000 PBKDF2 iterations. The encryption key is cryptographically tied to the local machine identity (`/etc/machine-id`) and user ID (`UID`). Even if the configuration file is copied to another device or user account, it cannot be decrypted.
- **Strict POSIX Permissions**: The configuration directory is created with `0700` (`rwx------`) and the configuration file with `0600` (`rw-------`), blocking access from other users on the system.
- **Zero Third-Party Dependencies**: The encryption is implemented entirely with Python standard library modules (`hashlib`, `hmac`, `secrets`, `struct`).

> **Why machine-bound encryption instead of a static hash?**
> The SRun 4K portal protocol generates a dynamic, random challenge token on every login. Both `hmd5 = HMAC_MD5(token, password)` and `info = xencode({"password": password, ...}, token)` dynamically depend on this random token, and the backend server decrypts `info` to verify against RADIUS/LDAP. Therefore, a static password hash (e.g. SHA-256) cannot be used by the protocol. Machine-bound authenticated local encryption securely solves credential reuse without exposing plaintext passwords.

**Manage Configuration**:

- Check configuration status (passwords are always masked):
  ```sh
  srunauth config
  ```
- Manually save or update credentials without logging in:
  ```sh
  srunauth config --save -u your_username
  ```
- Remove stored configuration:
  ```sh
  srunauth config --clear
  # Or: srunauth --clear-config
  ```

### Device Limit Exceeded (E2620) Handling

When maximum concurrent device limit is reached:

- **Interactive Selection** (default when running in an interactive terminal): lists all online devices under your account; enter the index number to kick the device and complete login.
- **Auto-Kick Oldest Device**:
  ```sh
  srunauth login -u your_username --auto-kick oldest
  ```
- **Auto-Kick Newest Device / All Other Devices**: use `--auto-kick newest` or `--auto-kick all`.
- **Kick Specific IP**: use `--kick-ip <IP>`.

### Logout / Kick Devices

- Log out the current local device:
  ```sh
  srunauth logout
  ```
- Log out a specific device by IP (e.g., remote kick your phone or another machine):
  ```sh
  srunauth logout -u your_username --ip 10.0.0.54
  ```
- Log out all online devices under your account:
  ```sh
  srunauth logout -u your_username --all
  ```

### Daemon / Unattended Monitoring

Keep the connection alive continuously in the background. With saved credentials, no environment variables or arguments are needed:

```sh
srunauth watch --auto-kick oldest --interval 30
```

Or configure via environment variables if preferred:

```sh
export SRUN_USERNAME='your_username'
export SRUN_PASSWORD='your_password'
srunauth watch --no-prompt --auto-kick oldest --interval 30
```

`watch` periodically checks connection status, and only re-authenticates when offline is detected. If a device limit is exceeded upon reconnecting, `--auto-kick oldest` automatically logs out the oldest device to restore access.

For 24/7 background operation, it is recommended to manage the process via systemd, OpenWrt procd, or a supervisor daemon. With `srunauth config --save`, your credentials remain securely encrypted with `0600` permissions.

## Python API Usage

After installing the package, you can import and use `SRunClient` directly in Python:

```python
from srun_auth import SRunClient

# Initialize client
client = SRunClient(portal="http://10.20.69.103", verbose=True)

# Query status
status = client.status()
if client.is_online(status):
    print("Online user:", status.get("user_name"))
else:
    # Perform login
    client.login(username="your_username", password="your_password")
```

## Authentication Protocol Flow

1. `GET /cgi-bin/rad_user_info`: Checks if current IP is already online.
2. Probes plain HTTP address to capture gateway 302 redirection and extract access context (`ac_id`, IP, MAC, NAS IP).
3. `GET /cgi-bin/get_challenge`: Requests a challenge token (valid for 60s) and detected client IP.
4. Computes HMAC-MD5 of password using the challenge token as key.
5. Encodes username, plaintext password, IP, `ac_id`, and `srun_bx1` into `{SRBX1}` format using custom XXTEA encryption and modified Base64 alphabet.
6. Concatenates fields according to portal specification and computes SHA-1 `chksum`.
7. `GET /cgi-bin/srun_portal?action=login...`: Submits authentication request.

If the portal requires captcha verification, automatic authentication halts and prompts user to verify via web browser first to avoid account locking.
