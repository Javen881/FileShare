# FileShare

轻量文件共享平台，面向 Ubuntu 部署，使用 Python / aiohttp、SQLite、Nginx 和 systemd，无需 Docker。

管理员生成一次性随机 URL，访客输入独立 PIN 后上传、下载共享文件；管理员通过独立 HTTPS 端口管理文件、文件夹和访问权限。

## 功能

| 访客共享端 | 管理后台 |
| --- | --- |
| 随机链接 + 独立 8 位 PIN | 独立管理员账户及登录会话 |
| 文件夹浏览、上传、下载 | 新建文件夹、批量上传、搜索和下载 |
| 同名文件分别保存，不覆盖 | 文件移入回收站、恢复 |
| 链接只能成功兑换一次 | 添加用户、生成链接、即时撤销权限 |
| 空闲自动失效，文件继续保留 | 自定义 HTTPS 链接前缀、查看操作日志 |

### 默认授权规则

- 随机链接 **5 分钟有效**，成功登录后立即作废；错误 PIN 累计 5 次锁定链接。
- 每位访客最多一个有效会话；新的成功登录替换旧会话。
- **15 分钟无有效传输**后失效；刷新页面、浏览目录不会续期。
- 最长会话 **2 小时**；达到上限会中断传输。
- 传输连续 **60 秒无进展**即超时；未完成的上传不进入文件列表。
- 单文件最大 **10 GiB**；默认总配额 **1500 GiB**，至少保留 **5 GiB** 空闲磁盘。
- 文件和授权生命周期独立：链接、会话过期不会删除已上传文件。

直接访问共享端 `/` 返回 **403**。只有有效的 `/enter/<随机令牌>` 链接可打开 PIN 登录页；已登录会话通过 `/session` 使用共享空间。未授权用户不能读取文件列表或文件内容。

## 快速部署

需要 Ubuntu、sudo 权限，以及已挂载的数据盘 `/data`。安装脚本**不会分区、格式化磁盘或修改软件源**。

```bash
git clone https://github.com/Javen881/FileShare.git
cd FileShare

sudo env \
  PUBLIC_ORIGIN=https://files.example.com:22220 \
  ADMIN_ORIGIN=https://192.168.1.10:8443 \
  bash scripts/install.sh
```

请将示例域名、IP 替换为实际地址：

- `PUBLIC_ORIGIN`：用户收到的访问链接前缀，可包含公网端口。
- `ADMIN_ORIGIN`：管理后台地址，建议内网 IP + `8443`。
- `HTTPS_PORT`：共享端本机 HTTPS 监听端口，默认 `443`。例如公网 `22220` 应通过路由器转发到服务器 `443`。
- `TLS_CERT` / `TLS_KEY`：可选的现有证书和私钥路径，必须同时提供。未提供时生成 90 天自签证书，仅用于内网测试。

首次安装会输出管理员账户 `admin` 和随机密码。请保存密码。管理员密码、证书、数据库和文件均保存在服务器，**不在此仓库中**。

正式公网使用需要正确的 DNS、端口映射及受信任且匹配域名的 HTTPS 证书。管理端 Nginx 默认只允许环回和 RFC1918 内网地址，勿将管理端口开放到公网。

完整步骤和维护方法见 [部署文档](docs/deployment.md)，授权与数据处理见 [安全设计](docs/security.md)。

## 使用

1. 打开 `ADMIN_ORIGIN`，以 `admin` 登录。
2. 在“共享文件”中新建文件夹、进入目录并上传文件。
3. 在“访问权限”中选择用户，生成随机链接及 PIN；链接前缀可修改并保存。
4. 将链接与 PIN 分开发送。访客打开链接、输入 PIN 后即可操作共享目录。
5. 随时撤销用户权限；删除文件先进入回收站，需要时可恢复。

服务器命令行同样可管理授权：

```bash
sudo abshare add-user C
sudo abshare invite A
sudo abshare revoke A
sudo abshare status
sudo abshare audit --limit 50
```

## 数据与服务

```text
/data/abshare/
├── current/                  # 程序代码
├── venv/                     # Python 虚拟环境
├── config.json               # 服务配置
├── admin-auth.json           # 管理员密码哈希，非明文密码
├── state/database.sqlite3    # 元数据、授权、回收站和审计
├── files/                    # 文件内容，使用随机 ID 命名
├── tmp/                      # 未完成上传
├── logs/                     # Nginx 与应用日志
├── tls/                      # HTTPS 证书和私钥
└── backups/                  # 升级备份
```

文件名、逻辑文件夹及文件内容通过数据库关联，不能直接在 `files/` 手工增删文件。备份时应同时备份数据库与文件内容。

| 服务 | 默认监听 |
| --- | --- |
| `abshare` | `127.0.0.1:8765`，Nginx 代理到 HTTPS 443 |
| `abshare-admin` | `127.0.0.1:8766`，Nginx 代理到内网 HTTPS 8443 |

## 开发与测试

Python **3.11+**：

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
bash -n scripts/install.sh scripts/update.sh
```

自动测试使用隔离的临时目录、数据库及测试凭证，不依赖真实服务器。覆盖一次性登录、PIN 锁定、CSRF、权限隔离、过期与撤销、上传中断、文件留存、回收站恢复、文件夹、管理上传和公网前缀。

`tests/check_live.py` 和 `tests/check_admin_live.py` 是**显式执行的部署验收脚本**，会创建并清理专用测试数据，不属于默认单元测试。用法见部署文档。

## 当前边界

- 暂不支持断点续传、在线预览、病毒扫描或按文件夹划分用户权限；所有访客共享同一个逻辑目录树。
- 回收站没有网页永久清空按钮，仍占用存储空间。
- 此仓库整理自实际部署版本，测试通过不代表经过独立安全审计。
- 没有微信账号身份认证；微信仅作为打开访问链接的浏览器。
