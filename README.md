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
python3 srun_auth.py login -u 你的账号
```

无人值守运行：

```sh
export SRUN_USERNAME='你的账号'
export SRUN_PASSWORD='你的密码'
python3 srun_auth.py watch --no-prompt --interval 30
```

`watch` 在线时只查询状态，检测到离线后才重新认证。长期运行建议由
systemd、OpenWrt procd 或其他服务管理器托管，并将凭据文件权限设为 `0600`。
不要把密码直接写进脚本、命令行参数或提交到 Git。

## 登录过程

1. `GET /cgi-bin/rad_user_info` 判断当前 IP 是否已在线。
2. `GET /cgi-bin/get_challenge` 获取 60 秒有效的 challenge 和客户端 IP。
3. 用 challenge 作为密钥计算密码的 HMAC-MD5。
4. 将账号、明文密码、IP、`ac_id=1` 和 `srun_bx1` 编码为
   `{SRBX1}` 信息字段。编码过程为门户实现的 XXTEA 变体和自定义 Base64。
5. 将各字段按门户规定拼接后计算 SHA-1 `chksum`。
6. `GET /cgi-bin/srun_portal?action=login...` 提交认证。

门户要求图片验证码时，脚本会停止并提示先使用网页认证，避免反复失败导致账号锁定。
