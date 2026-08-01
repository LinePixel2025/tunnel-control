# 自动部署（GitHub Actions）

仓库推送到 `main` 后，GitHub Actions 会自动把代码同步到服务器并重新部署，整个过程**不会清空服务器上已有的数据**，也不会影响服务器上的其他容器（如 `lineweb-server-1`、1Panel 自带的 PostgreSQL）。

## 这台服务器的实际情况

服务器 `123.207.8.77` 使用 1Panel 部署 Tunnel Control：

- 部署根目录：`/opt/1panel/docker/compose/tunnel-control`
- 代码检出目录：`/opt/1panel/docker/compose/tunnel-control/source`
- 环境变量文件：`/opt/1panel/docker/compose/tunnel-control/1panel.env`
- 项目名：`tunnel-control`（容器 `tunnel-control-server-1` 等）
- CI 同步代码到 `source/`，并把编译好的 `tunnel-server` 放到 `source/deploy/bin/`，然后执行 `docker compose up -d --build`

## 工作流程做什么

```text
git push (本地 main)
        |
        v
GitHub Actions: 校验密钥配置
        |
        v
编译 tunnel-server（rust:1.97-bookworm，与服务器 Dockerfile 一致）
        |
        v
rsync 同步代码到服务器 source/（不删除服务器上任何现有文件）
        |
        v
上传新的 tunnel-server 二进制到 source/deploy/bin/
        |
        v
（可选）pg_dump 备份 PostgreSQL 到 source/deploy/backups/
        |
        v
docker compose -p tunnel-control up -d --build（重建有变化的容器）
        |
        v
健康检查 /healthz，失败时输出容器日志
```

## 为什么不会丢数据、不影响其他容器

- 数据库和 Redis 使用**命名外部数据卷** `tunnel-control_tunnel-control-postgres-data`、`tunnel-control_tunnel-control-redis-data`，`docker compose up -d` 只重建容器，不删卷。
- 部署脚本**从不执行** `docker compose down -v` 或 `docker volume rm`。
- `rsync` 刻意**不加 `--delete`**，并排除 `.git`、`.env` 和 `deploy/backups/`；1Panel 的 `1panel.env`、已有备份、`deploy/bin/tunnel-server` 都不会被覆盖或删除。
- CI 使用 `-p tunnel-control` 和 `docker-compose.ci.yml`（从仓库复制），只操作 Tunnel Control 项目自己的容器，不碰其他容器。
- 每次部署前默认先做一次 `pg_dump` 备份（保留 14 天）。

## 服务器准备（已完成）

以下步骤已经在这台服务器上完成，无需重复操作：

- GitHub Actions 的 SSH 公钥已加入 `ubuntu` 用户的 `~/.ssh/authorized_keys`。
- `ubuntu` 用户已加入 `docker` 组（新 SSH 会话生效），CI 可直接执行 `docker compose`。
- `rsync`、`git`、`curl`、`gzip` 均已安装。

## 配置 GitHub Secrets（待你完成）

在仓库页面 **Settings → Secrets and variables → Actions** 中添加以下密钥：

| Secret | 值 |
| --- | --- |
| `SSH_HOST` | `123.207.8.77` |
| `SSH_USER` | `ubuntu` |
| `SSH_PRIVATE_KEY` | 部署私钥（见下） |
| `SSH_PORT` | `22` |
| `SSH_KNOWN_HOSTS` | `ssh-keyscan -H 123.207.8.77` 的输出 |
| `DEPLOY_DIR` | `/opt/1panel/docker/compose/tunnel-control` |

`DEPLOY_SUBDIR`、`COMPOSE_FILE`、`ENV_FILE`、`PROJECT_NAME` 已有适合本服务器的默认值（`source`、`deploy/compose.1panel.yaml`、`1panel.env`、`tunnel-control`），不填也可以。

部署私钥由本次配置生成，位于本机临时目录：

```text
C:\Users\22798\AppData\Local\Temp\tunnel-control-sshkey\id_ed25519
```

把该文件的**完整内容**粘贴到 `SSH_PRIVATE_KEY`。私钥仅供 GitHub Actions 登录服务器使用，请勿提交到仓库。

## 验证与手动触发

配置完 Secrets 后，在仓库 **Actions → Deploy to Server → Run workflow** 手动触发一次，或直接推送代码到 `main`。

手动触发可选参数：

- `deploy_subdir`：代码在 `DEPLOY_DIR` 下的子目录，默认 `source`。
- `compose_file`：Compose 文件，默认 `deploy/compose.1panel.yaml`。
- `run_db_backup`：是否部署前备份数据库，默认开启。

## 数据备份与恢复

CI 生成的备份位于服务器 `source/deploy/backups/tunnel-YYYYMMDD-HHMMSS.sql.gz`，保留最近 14 天。

手动恢复：

```bash
cd /opt/1panel/docker/compose/tunnel-control
gunzip -c source/deploy/backups/tunnel-<时间戳>.sql.gz \
  | docker compose -p tunnel-control --env-file 1panel.env -f docker-compose.ci.yml exec -T postgres psql -U tunnel -d tunnel
```
