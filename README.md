# Tunnel Control

面向团队的 Windows 到 Linux 公网服务器内网穿透首版。管理面板独立使用 HTTPS 端口；管理员分配 TCP/HTTP 公网端口，Windows 后台代理通过控制信道注册并持续发送心跳。

## 项目结构

- `crates/protocol`：版本化控制协议及其编解码测试。
- `crates/server`：Axum 管理 API、设备注册、令牌验证、隧道配置及内存状态机。
- `crates/agent`：可作为 Windows 后台服务运行的控制信道代理与自动重连循环。
- `apps/admin`：管理控制台前端。
- `apps/client`：Windows Tauri 壳内使用的客户端界面。
- `deploy`：Docker Compose、Caddy TLS 代理和 PostgreSQL 初始表结构。

## 本地开发

```powershell
cargo test
cargo run -p tunnel-server

cd apps/admin
npm.cmd install
npm.cmd run dev

cd ../client
npm.cmd install
npm.cmd run dev
```

管理 API 默认是 `http://127.0.0.1:8080`；演示代理使用默认令牌 `change-me-agent-token`：

```powershell
$env:TUNNEL_SERVER_URL = "ws://127.0.0.1:8080/control"
$env:TUNNEL_TOKEN = "change-me-agent-token"
cargo run -p tunnel-agent
```

## Linux Docker 部署

1. 在 Linux 服务器复制 `.env.example` 为 `deploy/.env`，设置高强度 `BOOTSTRAP_AGENT_TOKEN` 与 `POSTGRES_PASSWORD`。
2. 准备 PEM 证书和私钥，填入 `TLS_CERT_PATH` 和 `TLS_KEY_PATH`；管理面板由 `MANAGEMENT_HTTPS_PORT`（默认 `8443`）提供服务。
3. 从仓库根目录运行：`docker compose --env-file deploy/.env -f deploy/compose.yaml up -d --build`。
4. 防火墙只开放管理 HTTPS 端口、控制信道端口，以及管理员规划的公网映射范围（默认 `10000-60000`）。不要把 PostgreSQL 或 Redis 暴露到公网。

备份：使用 `docker compose -f deploy/compose.yaml exec postgres pg_dump -U tunnel tunnel > tunnel.sql`；恢复时将备份送入 `psql -U tunnel tunnel`。Redis 是在线状态缓存，可以在恢复时清空。

## 当前首版边界

控制面已经可运行：令牌注册、心跳、设备在线状态、端口冲突检查、隧道创建/启停与审计事件接口都可使用。PostgreSQL/Redis 以及 Docker 部署物已准备好，但当前服务端状态仍在内存中，重启后不会恢复；将 SQLx repository 接入 API 是下一生产化迭代。

同样，代理目前实现控制信道而不是公网数据面的连接多路复用。生产数据面将为每条公网连接增加受限的 `OpenStream/Data/CloseStream` 帧，并在代理端连接对应的本地 `host:port`。首版明确不支持 UDP、TLS 透传、自动 HTTPS 或自定义域名。

Windows 打包接入建议使用 Tauri v2：将 `tunnel-agent` 编译为 Windows Service，GUI 通过命名管道调用服务，而不要把访问令牌交给 WebView 或写入配置文件。
