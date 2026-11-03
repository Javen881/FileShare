# 部署与维护

## 1. 前置准备

准备 Ubuntu 主机和独立挂载的 `/data`。检查：

```bash
findmnt /data
df -h /data
```

磁盘挂载、swap、DNS 与路由器配置由管理员单独完成。仓库不包含绑定特定磁盘 UUID 的脚本。

## 2. 检查将要生成的配置

以下命令只输出文件，不安装系统服务：

```bash
python3 scripts/render_config.py \
  --public-origin https://files.example.com:22220 \
  --admin-origin https://192.168.1.10:8443 \
  --https-port 443 --output /tmp/fileshare-config
```

`PUBLIC_ORIGIN` 的端口是对外访问端口，`HTTPS_PORT` 是 Nginx 本机监听端口，两者可通过 NAT 映射。管理入口的端口直接由 `ADMIN_ORIGIN` 决定，且不得与共享端相同。

## 3. 首次安装

```bash
sudo env \
  PUBLIC_ORIGIN=https://files.example.com:22220 \
  ADMIN_ORIGIN=https://192.168.1.10:8443 \
  TLS_CERT=/path/to/fullchain.pem \
  TLS_KEY=/path/to/privkey.pem \
  bash scripts/install.sh
```

共享端和管理端默认使用同一份证书；证书应覆盖两个访问主机名。使用内网 IP 管理而证书只包含公网域名时，可为管理端另行配置证书或内部 DNS。省略证书参数会生成覆盖这两个主机的自签证书，浏览器仍会提示不受信任。

安装目录固定为 `/data/abshare`。系统盘仅安装系统依赖及少量服务配置。安装会为 `/data` 增加其他用户的目录遍历权限，但不会更改其中现有文件的访问权限。

安装脚本使用系统当前配置的软件源；下载失败时先检查网络或由管理员修改镜像。它不会覆盖已有 FileShare 安装，也不会删除现有 Nginx 站点。若 Nginx 已有相同监听地址/域名，需先由管理员协调配置。

## 4. 配置与日常管理

编辑 `/data/abshare/config.json` 后重启两个应用服务：

```bash
sudo systemctl restart abshare abshare-admin
sudo systemctl status abshare abshare-admin nginx
sudo nginx -t
```

配置字段见 [示例](../config/config.example.json)。`origin` 是共享端基础 HTTPS 地址；`admin_origin` 是独立管理端地址。页面保存的公网前缀位于 SQLite `settings` 表中，优先用于生成新链接；共享端接受基础地址及当前公网前缀，写操作要求严格匹配当前请求的 Origin。

更换前缀不会自动修改 DNS、NAT、Nginx 或证书。旧前缀生成的链接可能无法继续使用，应重新生成链接。旧版 `/#token` 链接不受支持。

管理密码重置（输出新的随机密码并撤销全部管理会话）：

```bash
cd /data/abshare/current
sudo env ABSHARE_ROOT=/data/abshare /data/abshare/venv/bin/python -m app.manage_admin --reset
sudo chown root:abshare /data/abshare/admin-auth.json
sudo chmod 640 /data/abshare/admin-auth.json
```

## 5. 更新

从独立 checkout 拉取新版本后运行：

```bash
git pull --ff-only
sudo bash scripts/update.sh
```

更新会暂停两个应用服务，备份代码、数据库和凭证配置，安装依赖、运行测试、迁移数据库后启动。现有配置、证书、Nginx 和 systemd 设置保持不变。若失败，服务保持停止，终端会显示备份目录；排查后恢复代码/数据库或重跑更新。不会自动回滚跨版本依赖及数据库。

如发布包含新的 Nginx/systemd 配置要求，应先比较模板与现有文件，再应用相应变更。

## 6. 备份

停止应用服务后，备份 `/data/abshare/state`、`files`、`config.json`、`admin-auth.json`、`tls`，再启动服务。SQLite WAL 文件可能包含尚未合并的数据，不能只复制正在运行的 `.sqlite3` 文件。

备份和恢复数据库及文件内容必须对应同一时间点；逻辑文件夹与回收站都保存在数据库中。备份包含私有文件和认证信息，应限制访问。

## 7. 部署验收

服务启动后，在服务器执行（访问地址必须能从服务器正常解析和连接）：

```bash
cd /data/abshare/current
sudo -u abshare env ABSHARE_ROOT=/data/abshare PYTHONDONTWRITEBYTECODE=1 \
  /data/abshare/venv/bin/python -m tests.check_live /data/abshare/public-certificate.crt
sudo -u abshare env ABSHARE_ROOT=/data/abshare PYTHONDONTWRITEBYTECODE=1 \
  /data/abshare/venv/bin/python -m tests.check_admin_live
```

验收创建专用测试记录和文件并在结束时清理，仅保留审计记录。管理员验收直接建立临时测试管理会话，不需要导出管理员密码。正常登录与密码校验由单元测试覆盖。

更换服务器证书时，同步更新 `/data/abshare/public-certificate.crt` 并验证证书链。域名使用公网 NAT 时，服务器若不支持 NAT 回环，需从外网设备补充检查。

## 常见情况

- **首页 403**：预期行为，请在后台生成新的 `/enter/<token>` 链接。
- **链接 403**：链接无效、已使用、过期或 PIN 错误次数达到上限。
- **登录后 401**：会话已超时、被撤销或被同用户的新登录替换。
- **上传中断**：检查会话绝对上限、网络停顿、大小配额和剩余空间。
- **外网无响应**：检查 DNS、公网地址、防火墙、TCP 端口映射和 TLS；修改页面前缀不等于完成网络配置。
- **管理端 403**：检查来源地址是否位于 Nginx 管理端配置允许的内网范围。
