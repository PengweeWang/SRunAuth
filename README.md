# SRun 校园网自动认证 (SRunAuth)

适用于深澜 SRun 门户（如 `http://10.20.69.103/`）的校园网自动认证客户端与 Python 工具包。

## 安装

可以通过 pip 安装到当前 Python 环境：

```sh
# 本地源码安装
pip install .

# 可编辑模式安装（方便本地修改调试）
pip install -e .

# 或直接通过 Git 仓库安装
pip install git+https://github.com/PengweeWang/SRunAuth.git
```

安装完成后即可直接在命令行中使用 `srunauth` 或 `srun-auth` 命令。
同时也保留对直接运行 `python3 srun_auth.py` 和 `python3 -m srun_auth` 的完整兼容支持。

## 命令行使用

查询当前状态（不需要账号密码）：

```sh
srunauth status
# 或：python3 srun_auth.py status
```

查询当前账号的全部在线设备及详情：

```sh
srunauth devices
```

查看门户返回的完整字段，包括原始 `online_device_detail`：

```sh
srunauth devices --json
```

该接口根据发起请求的当前 IP 查找账号，因此无需传入密码，但当前 IP 必须已经认证在线。

交互登录（密码不会显示）：

```sh
srunauth login -u 你的账号 -v
```

认证前脚本会访问 `http://www.baidu.com/`，捕获校园网网关的重定向地址，并
自动刷新 `ac_id`（支持从重定向页面如 `/index_4.html` 自动提取）、`nas_ip`、`ap_id`、`ap_ip`、客户端 IP 和 MAC。遇到
`no_response_data_error` 或 `RD000` 时，脚本会等待 3 秒、确认实际在线状态、
重新获取 challenge 并重试一次。可使用 `--retries 0` 禁用重试，或使用
`--probe-url ''` 禁用 HTTP 探测。

遇到设备数超限（E2620）处理：

- **交互选择**（默认终端模式）：当登录触发设备数超限时，会自动列出名下所有在线设备，输入序号即可将其注销并自动完成重新登录。
- **自动踢出最早设备**：
  ```sh
  srunauth login -u 你的账号 --auto-kick oldest
  ```
- **自动踢出最新设备 / 全部其他设备**：可使用 `--auto-kick newest` 或 `--auto-kick all`。
- **指定 IP 踢出**：使用 `--kick-ip 目标IP`。

注销/下线设备（logout / kick）：

- 注销当前设备：
  ```sh
  srunauth logout
  ```
- 注销指定 IP 设备（支持踢掉手机等其他设备）：
  ```sh
  srunauth logout -u 你的账号 --ip 10.126.13.54
  ```
- 注销该账号下的全部在线设备：
  ```sh
  srunauth logout -u 你的账号 --all
  ```

无人值守后台运行 / 守护监听：

```sh
export SRUN_USERNAME='你的账号'
export SRUN_PASSWORD='你的密码'
srunauth watch --no-prompt --auto-kick oldest --interval 30
```

`watch` 在线时只查询状态，检测到离线后才重新认证。若掉线重连时遇到设备超限，配置 `--auto-kick oldest` 可自动下线最早设备保证上线。长期运行建议由
systemd、OpenWrt procd 或其他服务管理器托管，并将凭据文件权限设为 `0600`。
基于代码进行修改时不要把密码直接写进脚本、命令行参数或提交到 Git。

## Python 代码调用

作为 Python 包安装后，也可以直接在代码中导入使用：

```python
from srun_auth import SRunClient

# 创建客户端
client = SRunClient(portal="http://10.20.69.103", verbose=True)

# 查询在线状态
status = client.status()
if client.is_online(status):
    print("已在线:", status.get("user_name"))
else:
    # 登录认证
    client.login(username="your_username", password="your_password")
```

## 登录过程

1. `GET /cgi-bin/rad_user_info` 判断当前 IP 是否已在线。
2. 访问普通 HTTP 地址，捕获认证网关重定向并自动刷新接入参数（包括从页面路径解析无线 AC ID 等）。
3. `GET /cgi-bin/get_challenge` 获取 60 秒有效的 challenge 和客户端 IP。
4. 用 challenge 作为密钥计算密码的 HMAC-MD5。
5. 将账号、明文密码、IP、`ac_id` 和 `srun_bx1` 编码为
   `{SRBX1}` 信息字段。编码过程为门户实现的 XXTEA 变体和自定义 Base64。
6. 将各字段按门户规定拼接后计算 SHA-1 `chksum`。
7. `GET /cgi-bin/srun_portal?action=login...` 提交认证。

门户要求图片验证码时，脚本会停止并提示先使用网页认证，避免反复失败导致账号锁定。
