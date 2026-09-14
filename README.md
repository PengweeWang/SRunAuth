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

Before authenticating, the client probes `http://www.baidu.com/` to capture gateway redirection and automatically refreshes `ac_id` (including automatic extraction from redirect paths such as `/index_4.html`), `nas_ip`, `ap_id`, `ap_ip`, client IP, and MAC address.

If a `no_response_data_error` or `RD000` occurs, the client waits 3 seconds, checks current online status, refreshes parameters, and retries. Retries can be disabled using `--retries 0`, or gateway probing can be disabled with `--probe-url ''`.

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
  srunauth logout -u your_username --ip 10.126.13.54
  ```
- Log out all online devices under your account:
  ```sh
  srunauth logout -u your_username --all
  ```

### Daemon / Unattended Monitoring

Keep the connection alive continuously in the background:

```sh
export SRUN_USERNAME='your_username'
export SRUN_PASSWORD='your_password'
srunauth watch --no-prompt --auto-kick oldest --interval 30
```

`watch` periodically checks connection status, and only re-authenticates when offline is detected. If a device limit is exceeded upon reconnecting, `--auto-kick oldest` automatically logs out the oldest device to restore access.

For 24/7 background operation, it is recommended to manage the process via systemd, OpenWrt procd, or a supervisor daemon, with credentials protected (`chmod 0600`). Avoid committing passwords to Git or embedding them into cleartext scripts.

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
