# SRun 校园网自动认证

适用于 `http://10.20.69.103/` 的深澜 SRun 门户。

## 使用

查询当前状态（不需要账号密码）：

```sh
python3 srun_auth.py status
```

查询当前账号的全部在线设备及详情：

```sh
python3 srun_auth.py devices
```

查看门户返回的完整字段，包括原始 `online_device_detail`：

```sh
python3 srun_auth.py devices --json
```

该接口根据发起请求的当前 IP 查找账号，因此无需传入密码，但当前 IP 必须已经认证在线。

交互登录（密码不会显示）：

```sh
python3 srun_auth.py login -u 你的账号 -v
```

认证前脚本会访问 `https://www.baidu.com/`，捕获校园网网关的重定向地址，并
刷新 `ac_id`、`nas_ip`、`ap_id`、`ap_ip`、客户端 IP 和 MAC。遇到
`no_response_data_error` 或 `RD000` 时，脚本会等待 3 秒、确认实际在线状态、
重新获取 challenge 并重试一次。可使用 `--retries 0` 禁用重试，或使用
`--probe-url ''` 禁用 HTTP 探测。

遇到设备数超限（E2620）处理：

- **交互选择**（默认终端模式）：当登录触发设备数超限时，会自动列出名下所有在线设备，输入序号即可将其注销并自动完成重新登录。
- **自动踢出最早设备**：
  ```sh
  python3 srun_auth.py login -u 你的账号 --auto-kick oldest
  ```
- **自动踢出最新设备 / 全部其他设备**：可使用 `--auto-kick newest` 或 `--auto-kick all`。
- **指定 IP 踢出**：使用 `--kick-ip 目标IP`。

注销/下线设备（logout / kick）：

- 注销当前设备：
  ```sh
  python3 srun_auth.py logout
  ```
- 注销指定 IP 设备（支持踢掉手机等其他设备）：
  ```sh
  python3 srun_auth.py logout -u 你的账号 --ip 10.126.13.54
  ```
- 注销该账号下的全部在线设备：
  ```sh
  python3 srun_auth.py logout -u 你的账号 --all
  ```

无人值守运行：

```sh
export SRUN_USERNAME='你的账号'
export SRUN_PASSWORD='你的密码'
python3 srun_auth.py watch --no-prompt --auto-kick oldest --interval 30
```

`watch` 在线时只查询状态，检测到离线后才重新认证。若掉线重连时遇到设备超限，配置 `--auto-kick oldest` 可自动下线最早设备保证上线。长期运行建议由
systemd、OpenWrt procd 或其他服务管理器托管，并将凭据文件权限设为 `0600`。
基于代码进行修改时不要把密码直接写进脚本、命令行参数或提交到 Git。

## 登录过程

1. `GET /cgi-bin/rad_user_info` 判断当前 IP 是否已在线。
2. 访问普通 HTTP 地址，捕获认证网关重定向并刷新接入参数。
3. `GET /cgi-bin/get_challenge` 获取 60 秒有效的 challenge 和客户端 IP。
4. 用 challenge 作为密钥计算密码的 HMAC-MD5。
5. 将账号、明文密码、IP、`ac_id=1` 和 `srun_bx1` 编码为
   `{SRBX1}` 信息字段。编码过程为门户实现的 XXTEA 变体和自定义 Base64。
6. 将各字段按门户规定拼接后计算 SHA-1 `chksum`。
7. `GET /cgi-bin/srun_portal?action=login...` 提交认证。

门户要求图片验证码时，脚本会停止并提示先使用网页认证，避免反复失败导致账号锁定。
