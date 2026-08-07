# 🛡️ ScanGuard

[English](README.md) | **简体中文**

ScanGuard 是一个自托管的**开源扫描器检测与威胁情报平台**。它实时监控你的
Web/认证日志，识别扫描器与暴力破解行为，在防火墙层自动封禁，并可选地将每个
攻击者上报到一个**公开 GitHub 仓库**，由该仓库把恶意 IP 聚合成一份通过 GitHub
Pages 分发的社区黑名单——无需中心服务器。

## 架构

```
┌─────────────┐    commits events     ┌──────────────────────┐
│ Agent (VPS) │ ─────────────────────▶│ GitHub repo          │
│  - scan logs│   Contents API + PAT  │  reports/<node>.jsonl│
│  - block IP │                       │                      │
└─────────────┘                       │  GitHub Actions:     │
┌─────────────┐    commits events     │   aggregate.py       │
│ Agent (VPS) │ ─────────────────────▶│         ↓            │
└─────────────┘                       │  blocklist.{txt,     │
                                      │    iptables,nft}     │
                                      │  stats.json          │
                                      │  threats.json        │
                                      └──────────┬───────────┘
                                                 │ GitHub Pages
                                                 ▼
                          https://hezhidong.github.io/scanguard/
                          ├─ /             (仪表盘)
                          ├─ /blocklist.txt
                          ├─ /blocklist.iptables
                          └─ /blocklist.nftables
```

任何机器都可以订阅这份黑名单：
```bash
curl -s https://hezhidong.github.io/scanguard/blocklist.iptables | sudo iptables-restore
```

## 仓库结构

```
scanguard/
├── agent/        # ScanGuard Agent — 日志检测 + 自动封禁（部署在每台主机上）
├── intake/       # Cloudflare Worker — 公共社区上报入口
├── api/          # 可选的自托管 FastAPI 中心服务（旧方案）
├── web/          # 静态仪表盘（由 Actions 构建到仓库根目录，通过 Pages 提供服务）
├── scripts/      # aggregate.py（CI：reports/* → blocklist + stats）
├── reports/      # 各节点 + 社区 jsonl 事件文件
├── docs/         # 运营文档（intake 部署等）
├── install.sh    # 一键安装脚本
└── .github/workflows/aggregate.yml
```

---

## 1. ScanGuard Agent

一个独立的 Python 包（`scanguard`），具备以下能力：

- 实时跟踪**本地或远程（SSH）**的 nginx/apache/auth 日志（支持纯文本和 `.gz`）
- 采用可配置的正则**检测规则**，支持阈值与滑动时间窗口
- 通过可插拔的防火墙后端封禁攻击者：
  **iptables · nftables · ufw · firewalld**（支持本地或通过 SSH 远程执行）
- 使用 **IP 归属地（geolocation）** 丰富 IP 信息（ip-api，带缓存）
- 持久化状态（绝不会重复封禁），并写入供聊天机器人读取的通知文件
- 可选地把**每次封禁上报到公开 GitHub 仓库**（新的默认方案），
  或上报到自托管的 HTTP API

### 快速开始（一条命令）

安装脚本会自动完成：下载 agent、安装 Python 依赖、生成
`/etc/scanguard/config.yaml`、保存 GitHub token、安装每 30 分钟执行一次的
systemd timer。全部一步搞定：

```bash
github_pat=your…_XX  # fine-grained PAT，创建方法见下

curl -fsSL https://raw.githubusercontent.com/hezhidong/scanguard/master/install.sh \
  | sudo SG_GITHUB_TOKEN=*** bash
```

就这些。timer 已经立即启动。验证：

```bash
systemctl status scanguard.timer
sudo journalctl -u scanguard.service -n 50
```

**自定义节点名 / 防火墙后端 / 日志路径：**

```bash
curl -fsSL https://raw.githubusercontent.com/hezhidong/scanguard/master/install.sh \
  | sudo SG_GITHUB_TOKEN=*** \
       SG_NODE_ID=web-01 SG_NODE_NAME="Web Server 01" \
       SG_FIREWALL=nftables \
       SG_WHITELIST=127.0.0.1,::1,203.0.113.10 \
       bash
```

| 变量 | 默认值 | 用途 |
|---|---|---|
| `SG_GITHUB_TOKEN` | _交互式提示_ | 针对该仓库开通 Contents: Read&write 的 fine-grained PAT |
| `SG_NODE_ID` | `$(hostname)` | 节点唯一 ID → `reports/<node_id>.jsonl` |
| `SG_NODE_NAME` | 与 node id 相同 | 仪表盘上显示的节点名称 |
| `SG_FIREWALL` | `iptables` | `iptables` / `nftables` / `ufw` / `firewalld` |
| `SG_LOG_PATHS` | `/var/log/nginx/access.log,/var/log/nginx/access.log.1` | 逗号分隔的 nginx access 日志路径 |
| `SG_WHITELIST` | `127.0.0.1,::1` | 逗号分隔的、永远不应被封禁的 IP/CIDR |
| `SG_INSTALL_DIR` | `/opt/scanguard` | agent 代码安装位置 |
| `SG_SKIP_SYSTEMD` | `0` | 容器/无 systemd 环境下设为 `1` |

> **不想把 token 放在命令行？** 直接运行 `sudo bash install.sh`，脚本会在终端
> 交互式提示你粘贴 token（输入不可见）。

#### 如何创建 GitHub Token

1. GitHub → **Settings → Developer settings → Personal access tokens → Fine-grained tokens**
2. **Only select repositories（仅选择仓库）** → `scanguard`
3. Repository permissions（仓库权限） → **Contents: Read and write**
4. Expiration（有效期）：90 天（请定期轮换）

> **隐私说明：** 上报内容只包含 IP / 规则 / 严重级别 / 命中次数 / 归属地 /
> 节点元数据，不会发送完整 URL、查询字符串或请求证据。

### 社区上报（默认开启）

Agent 每次封禁 IP 时，会同时把一条**脱敏后的事件**发送到 ScanGuard 公共入口
（一个 Cloudflare Worker）：

```
POST https://scanguard-intake.hezhidong.workers.dev/report
```

Worker 会做校验、限流，然后把事件追加到本仓库的
`reports/community.jsonl`。**不需要任何账号或 token。**

**上报内容：** IP、规则名、严重级别、命中次数、国家/城市/ISP，以及你的
`node_id` / `node_name`。**不会**上传 URL、查询字符串、User-Agent 或请求体。

**防投毒机制：** 来自社区节点的 IP，必须被**至少 2 个不同的 node_id** 上报后，
才会进入公共黑名单。单节点上报的 IP 会在仪表盘中标记为"待确认（pending）"，
但不会通过 `blocklist.*` 分发。来自运营方自有节点（通过 `central:` 直接推送到
GitHub）的上报不受此限制。

如需关闭，在 `config.yaml` 中设置：

```yaml
community:
  enabled: false
```

或者安装时加上 `SG_COMMUNITY_ENABLED=0`。

### 运行自己的仪表盘（可选）

如果你想在贡献社区的同时，也拥有自己的私有仪表盘：

1. Fork 本仓库
2. 在 fork 上启用 GitHub Pages（Settings → Pages → master / root）
3. 创建一个仅对你 fork 有 Contents: Read&write 权限的 fine-grained PAT
4. 安装时这样运行：

```bash
curl -fsSL https://raw.githubusercontent.com/hezhidong/scanguard/master/install.sh \
  | sudo SG_REPO=yourname/scanguard \
       SG_GITHUB_TOKEN=*** bash
```

你的 agent 会同时推送到社区 feed（默认开）和你自己的 fork（提供了 token 时）。
设置 `community.enabled: false` 可完全私有化。

如果你想**自建 intake 入口**而不是使用公共服务，参见
[`docs/INTAKE_DEPLOY.md`](docs/INTAKE_DEPLOY.md)。

### 手动安装（如果你希望自己一步步来）

```bash
cd agent
pip install -r requirements.txt
sudo mkdir -p /etc/scanguard /var/lib/scanguard
sudo cp ../examples/config.example.yaml /etc/scanguard/config.yaml
sudo $EDITOR /etc/scanguard/config.yaml
```

把 token 保存到 `/etc/scanguard/github_token`（权限 600），然后启用 timer：

```bash
sudo cp agent/packaging/scanguard.service agent/packaging/scanguard.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now scanguard.timer
```

### 防火墙后端

| 后端       | 持久化方式                | 说明                                        |
|------------|---------------------------|---------------------------------------------|
| iptables   | netfilter-persistent      | 默认；在大多数 Linux 主机上可用             |
| nftables   | /etc/nftables.conf        | 使用 `scanguard_blocklist` inet 集合        |
| ufw        | —                         | `ufw deny/reject from <ip>`                 |
| firewalld  | permanent ipset           | `firewall-cmd --ipset` + reload             |

每个后端都可以**在本地执行**，也可以**通过 SSH 在远程主机执行**
（设置 `firewall.host/user/key`），因此一台 agent 就可以在边界/网关机器上
完成封禁。

---

## 2. 中心聚合（GitHub Actions）

Workflow `.github/workflows/aggregate.yml` 每 10 分钟运行一次（同时在
每次推送到 `reports/` 时触发）。它调用 `scripts/aggregate.py`，完成：

1. 读取所有 `reports/*.jsonl`
2. 按 IP 聚合事件（取最高严重级别、累加命中次数、汇总节点与规则）
3. 写出：
   - `blocklist.txt` / `blocklist.iptables` / `blocklist.nftables`
   - `stats.json`（仪表盘用的关键计数）
   - `threats.json`（完整的聚合后 IP 列表）
   - 把 `web/index.html` 复制到仓库根目录
4. 把结果提交回仓库

黑名单中只包含严重级别为 **high 或 critical** 的 IP。

### 启用 GitHub Pages

第一次 Actions 运行完成后：

1. 仓库 **Settings → Pages**
2. Source：**Deploy from a branch**
3. Branch：**master** / **/ (root)**
4. Save。约 1 分钟后仪表盘就会在
   `https://hezhidong.github.io/scanguard/` 上线。

---

## 3. Web 仪表盘

一个单文件静态 HTML 页面（`web/index.html`），加载 `stats.json` +
`threats.json` 并渲染：

- 全局计数（IP 总数、严重级别分布、上报节点数、事件数）
- Top 国家 / 规则的柱状图
- 可搜索、可排序的表格
- 每个 IP 的详情弹窗，含最近活动时间线
- 一键复制 `iptables` 封禁命令

无后端、无 JS 框架，可直接在 GitHub Pages 上运行。

---

## 4. 订阅黑名单

```bash
# 纯列表（每行一个 IP）
curl https://hezhidong.github.io/scanguard/blocklist.txt

# iptables-restore 格式
curl https://hezhidong.github.io/scanguard/blocklist.iptables | sudo iptables-restore

# nftables 格式
curl https://hezhidong.github.io/scanguard/blocklist.nftables | sudo nft -f -
```

加一个每几小时一次的 cron，你就拥有了一道社区驱动的防火墙。

---

## 检测规则（示例）

```yaml
rules:
  - name: php-scanner
    pattern: '\.(php|asp|aspx|env|git|jsp|cgi)(\?|$| )'
    threshold: 20
    window_minutes: 30
    severity: high
  - name: path-traversal
    pattern: '(\.\./|/etc/passwd|phpMyAdmin|/\.aws/credentials)'
    threshold: 5
    window_minutes: 30
    severity: critical
  - name: ssh-bruteforce
    pattern: 'Failed password|Invalid user|authentication failure'
    threshold: 5
    window_minutes: 10
    severity: high
```

---

## 可选：自托管中心 API（旧方案）

如果你不想使用 GitHub，`api/` 下有一个 FastAPI 服务可接收上报并下发黑名单，
具体搭建方式见源码中的 `api/README`。Agent 通过 `backend: http` 即可使用。

---

## 安全说明

- **请把你自己的 IP 和监控网段加入白名单。** 配置错误的规则可能把你自己封掉。
- Agent 需要以 root 运行（需要防火墙权限）；API 不需要 root。
- 远程日志/防火墙目标推荐使用 SSH 密钥；密码认证需要安装 `sshpass`。
- GitHub PAT 只需要针对单一仓库的 **Contents: Read and write** 权限。
  请定期轮换；如果某台主机失陷，立即吊销该 token。
- `ip-api` 免费版仅供非商用且有速率限制；大规模使用请替换为付费的 `geo` 供应商。

## 许可协议

MIT — 详见 [LICENSE](LICENSE)。
