# Tunnel Control

面向团队的 Windows 到 Linux 公网服务器内网穿透。管理面板独立使用 HTTPS 端口；管理员分配 TCP/HTTP/UDP 公网端口，Windows 后台代理通过控制通道注册并持续发送心跳，数据流量在独立的 K 条数据通道上多路复用。

当前发布版本：V4.3（客户端安装包 `release\V4.3\Tunnel-Agent-Setup-V4.3.exe`）。

## 项目结构

- `crates/protocol`：版本化控制协议及其编解码测试。
- `crates/server`：Axum 管理 API、设备注册、令牌验证、隧道配置及内存状态机。
- `crates/agent`：可作为 Windows 后台服务运行的控制信道代理与自动重连循环。
- `apps/admin`：管理控制台前端。
- `deploy`：Docker Compose、Caddy TLS 代理和 PostgreSQL 初始表结构。

客户端没有独立 GUI：`tunnel-agent.exe` 是唯一的设备端程序，通过命令行安装和查看日志，全部运行参数由管理端下发。

## 本地开发

```powershell
cargo test
cargo run -p tunnel-server

cd apps/admin
npm.cmd install
npm.cmd run dev

```

管理 API 默认是 `http://127.0.0.1:18080`；本地演示代理直接以前台模式运行：

```powershell
$env:TUNNEL_SERVER_URL = "ws://127.0.0.1:18080/control"
cargo run -p tunnel-agent -- --agent
```

不带令牌启动时，代理进入设备码注册模式：控制台打印一次性注册码，管理员在管理端「设备注册」页批准后，服务器生成令牌并直接下发。

## Linux Docker 部署

1. 在 Linux 服务器复制 `.env.example` 为 `deploy/.env`，设置高强度 `BOOTSTRAP_AGENT_TOKEN` 与 `POSTGRES_PASSWORD`。
2. 准备 PEM 证书和私钥，填入 `TLS_CERT_PATH` 和 `TLS_KEY_PATH`；管理面板由 `MANAGEMENT_HTTPS_PORT`（默认 `8443`）提供服务。
3. 从仓库根目录运行：`docker compose --env-file deploy/.env -f deploy/compose.yaml up -d --build`。
4. 防火墙只开放管理 HTTPS 端口、控制信道端口，以及管理员规划的公网映射范围（默认 `10000-60000`）。不要把 PostgreSQL 或 Redis 暴露到公网。

备份：使用 `docker compose -f deploy/compose.yaml exec postgres pg_dump -U tunnel tunnel > tunnel.sql`；恢复时将备份送入 `psql -U tunnel tunnel`。Redis 是在线状态缓存，可以在恢复时清空。

## 当前首版边界

控制面已经可运行：令牌注册、心跳、设备在线状态、端口冲突检查、隧道创建/启停与审计事件接口都可使用。PostgreSQL/Redis 以及 Docker 部署物已准备好，但当前服务端状态仍在内存中，重启后不会恢复；将 SQLx repository 接入 API 是下一生产化迭代。

## 数据面与稳定性语义

协议 v3 起数据面与控制面分离：1 条控制 WebSocket 只承载注册、心跳、`StreamOpen/Close` 等小消息；注册成功后代理额外打开 `DATA_CHANNELS`（默认 2，服务端上限 `DATA_CHANNELS_MAX` 默认 4）条数据 WebSocket，每条先以 `DataBind` 绑定再以 `DataBound` 获得通道号。每条公网连接/每个 UDP 会话由服务端分配到一个数据通道（`StreamOpen` 携带通道号），该通道上的二进制帧只走对应的数据套接字。

- 任一数据通道抖动只关闭它承载的流（约 1/K），其他通道不受影响；控制通道不会被数据突发饿死。
- 可探测故障（RST、正常关闭）下，代理按 1s 起、×2、上限 10s 的退避重连，新连接约 1–3s 恢复；静默黑洞最坏受 `AGENT_PONG_TIMEOUT_SECS`（默认 25s）约束，可通过环境变量调小。
- 整链路断网时，在途 TCP 连接会被切断（裸 TCP 字节流无法透明续传），恢复语义为"新连接快速可用"；数据库连接池、HTTP 客户端等长连接应用应自行重试。UDP 会话在重连后由下一个客户端报文自动重建。
- UDP 隧道把每个公网客户端视为一个会话，空闲超过 `UDP_SESSION_IDLE_SECS`（默认 120 秒）后自动回收；零长度 UDP 报文也会被正常转发。
- 带宽限速每个方向只记一次账：agent → server 由 agent 源端限速，服务端不二次计费；public → agent 由服务端收包处限速。服务端按设备分桶，设备之间不争抢同一把全局锁，配置值按设备生效。

当前不支持 TLS 透传、自动 HTTPS 或自定义域名。协议 v4 与旧版代理/服务端不兼容，升级时需要同时发布两侧。

### 可调环境变量

服务端：`DATA_CHANNELS_MAX`（1–16）、`SHUTDOWN_DRAIN_SECS`（优雅停机排水秒数，默认 10）、`BANDWIDTH_LIMIT_MBPS`、`UDP_SESSION_IDLE_SECS`。

代理端运行参数（数据通道数、心跳、超时、重连退避、日志级别、服务器地址）由管理端在「系统设置」或「Windows 设备」页统一控制，改动即时推送到在线代理；重连类参数由代理自动重连生效。本地环境变量与 `agent.env` 仅作首次连接引导（`DATA_CHANNELS`、`AGENT_HEARTBEAT_SECS`、`AGENT_PONG_TIMEOUT_SECS`、`AGENT_RECONNECT_MIN_SECS`、`AGENT_RECONNECT_MAX_SECS` 等仍可作为兜底）。

Windows 安装与日志：

```powershell
tunnel-agent.exe --install --server ws://公网IP:18080/control   # 管理员权限：安装并启动服务
tunnel-agent.exe logs -f                                        # 跟踪服务日志（首次会显示注册码）
tunnel-agent.exe reset                                          # 停止并清除全部本地数据（令牌/注册码/日志/引导配置），下次启动重新注册
tunnel-agent.exe --uninstall
```

设备端凭据（服务器下发的令牌）保存在 `%PROGRAMDATA%\TunnelControl\credentials`，仅 SYSTEM/管理员可读写，用户全程不接触令牌。

### 客户端控制台（单文件，无需管理员）

客户端就是单个 `tunnel-agent.exe`。无参数运行（或双击）即进入客户端控制台：首次启动会询问服务器（`1. LineWeb 官方（ws://123.207.8.77:18080/control）` 或 `2. 自定义`），然后自动后台启动代理并进入交互命令行。非管理员运行时控制台、安装、卸载和重置操作会自动弹出 UAC 请求管理员权限（`--agent`、`--service`、`logs` 不弹窗；可用 `TUNNEL_SKIP_ELEVATION=1` 跳过）：

```text
start      启动代理（未运行时）
stop       终止代理
restart    终止并重新启动
reset      停止并清除全部本地数据（重新注册）
status     查看进程、服务与凭据状态
settings   查看服务器下发的有效设置
traffic    查看每条数据通道的实时流量（上行/下行与合计）
logs       查看最近日志（首次可看到注册码）
exit       退出脚本（代理保持后台运行）
help       显示命令帮助
```

控制台模式使用 `%LOCALAPPDATA%\TunnelControl` 下的独立凭据与日志，不触碰 Windows 服务的 `%PROGRAMDATA%` 文件，普通用户即可运行；若检测到 TunnelAgent 服务正在运行，控制台会提示先停止服务，避免两个代理抢占同一设备会话。
