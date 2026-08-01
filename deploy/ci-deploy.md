# 自动部署（GitHub Actions）

仓库推送到 `main` 后，GitHub Actions 会自动把代码同步到 Linux 服务器并重新部署，整个过程**不会清空服务器上已有的数据**。

## 工作流程做什么

```text
git push (本地 main)
        |
        v
GitHub Actions: 校验密钥配置
        |
        v
rsync 同步代码到服务器（不删除服务器上任何现有文件）
        |
        v
（可选）pg_dump 备份 PostgreSQL 到 deploy/backups/
        |
        v
docker compose up -d --build（重建有变化的容器）
        |
        v
健康检查 /healthz，失败时输出容器日志
```

## 为什么不会丢数据

- 数据库和 Redis 使用**命名外部数据卷** `tunnel-control_tunnel-control-postgres-data`、`tunnel-control_tunnel-control-redis-data`，`docker compose up -d` 只会重建容器，不会删除卷。
- 部署脚本**从不执行** `docker compose down -v` 或 `docker volume rm`。
- `rsync` 刻意**不加 `--delete`**，并排除 `.env` 和 `deploy/backups/`，所以服务器上的 `deploy/.env`、备份文件（1Panel 场景下还有 `deploy/bin/tunnel-server`）不会被覆盖或删除。
- 每次部署前默认先做一次 `pg_dump` 备份（保留 14 天），即使部署出问题也可以恢复。

## 首次初始化（只需一次）

在服务器上把代码放到部署目录并准备好 `.env`：

```bash
sudo mkdir -p /opt/tunnel-control
sudo chown "$USER" /opt/tunnel-control
git clone https://github.com/LinePixel2025/tunnel-control.git /opt/tunnel-control
cp /opt/tunnel-control/deploy/.env.example /opt/tunnel-control/deploy/.env
# 编辑 deploy/.env，填入随机密钥（openssl rand -hex 32）
cd /opt/tunnel-control
docker compose --env-file deploy/.env -f deploy/compose.yaml up -d --build
```

确认服务正常后，后续每次 `git push` 都会自动同步并部署，不再需要手动上服务器执行命令。

## 服务器准备

- 已安装 Docker Engine 和 Docker Compose plugin（与现有部署一致）。
- 已安装 `rsync`：

  ```bash
  sudo apt-get update && sudo apt-get install -y rsync
  ```

## 配置 GitHub Secrets

在仓库页面 **Settings → Secrets and variables → Actions** 中添加以下密钥：

| Secret | 必填 | 说明 |
| --- | --- | --- |
| `SSH_HOST` | 是 | 服务器公网 IP 或域名 |
| `SSH_USER` | 是 | SSH 登录用户，例如 `root` 或 `ubuntu` |
| `SSH_PRIVATE_KEY` | 是 | GitHub Actions 使用的 SSH 私钥（见下） |
| `SSH_PORT` | 否 | SSH 端口，默认 `22` |
| `SSH_KNOWN_HOSTS` | 建议 | 服务器公钥，防止中间人攻击 |
| `DEPLOY_DIR` | 否 | 服务器上代码所在目录，默认 `/opt/tunnel-control` |

生成专用 SSH 密钥并授权：

```bash
# 在本机或任意地方生成
ssh-keygen -t ed25519 -C "github-actions" -f ~/.ssh/github_actions
ssh-copy-id -i ~/.ssh/github_actions.pub <SSH_USER>@<SSH_HOST>
```

把 `~/.ssh/github_actions` 的完整内容粘贴到 `SSH_PRIVATE_KEY`。

获取 `SSH_KNOWN_HOSTS`：

```bash
ssh-keyscan -p <端口> -H <SSH_HOST> >> known_hosts
```

把 `known_hosts` 文件内容粘贴到 `SSH_KNOWN_HOSTS`。

## 手动触发

仓库 **Actions → Deploy to Server → Run workflow** 可以手动部署，并提供两个可选参数：

- `deploy_subdir`：代码在 `DEPLOY_DIR` 下的子目录。1Panel 部署填 `source`。
- `compose_file`：Compose 文件路径，1Panel 填 `deploy/compose.1panel.yaml`。
- `run_db_backup`：是否在部署前备份数据库，默认开启。

## 1Panel 变体

如果服务器使用 1Panel 部署：

- `DEPLOY_DIR` 填 1Panel 应用目录。
- `deploy_subdir` 填 `source`。
- `compose_file` 填 `deploy/compose.1panel.yaml`。
- 预编译二进制 `deploy/bin/tunnel-server` 需要手动放到服务器的 `deploy/bin/` 下，CI 不会删除它，但也不会替你更新它。

## 数据备份与恢复

CI 生成的备份位于服务器 `deploy/backups/tunnel-YYYYMMDD-HHMMSS.sql.gz`，保留最近 14 天。

手动恢复：

```bash
cd /opt/tunnel-control
gunzip -c deploy/backups/tunnel-<时间戳>.sql.gz \
  | docker compose --env-file deploy/.env -f deploy/compose.yaml exec -T postgres psql -U tunnel -d tunnel
```
