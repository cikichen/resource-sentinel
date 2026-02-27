# Resource Sentinel

一个可 Docker 部署的系统资源监控服务。定期采集 CPU / 内存 / 磁盘占用，当连续多次超过阈值时触发告警，并支持发送到 Telegram、企业微信机器人、IYUU、PushPlus 以及通用 Webhook 三方平台。

## 仓库地址

- GitHub: https://github.com/cikichen/resource-sentinel
- Docker Hub: https://hub.docker.com/r/cikichen/resource-sentinel

## 功能

- 支持 CPU、内存、磁盘占用率阈值监控
- 支持连续 N 次超限才告警，减少抖动误报
- 支持恢复通知（从异常恢复到正常）
- 支持 Telegram、企业微信、IYUU、PushPlus、通用 Webhook 多通道通知
- 支持内置 Web 配置页面（在线编辑 `config.yaml`）
- 支持 `docker build` / `docker-compose` 部署
- 支持 YAML 配置 + 环境变量覆盖

## 项目结构

- `cmd/monitor/main.go`：入口
- `internal/monitor`：指标采集与阈值评估
- `internal/notify`：通知通道实现
- `internal/config`：配置加载与校验
- `internal/service`：监控主循环
- `configs/config.yaml`：默认配置

## 本地运行

```bash
go mod tidy
go run ./cmd/monitor -config configs/config.yaml
```

## Docker 部署

### 1. 构建镜像

```bash
docker build -t resource-sentinel:latest .
```

### 2. 启动容器

```bash
docker run -d \
  --name resource-sentinel \
  --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  -e CONFIG_PATH=/app/configs/config.yaml \
  -e APP_TG_ENABLED=true \
  -e APP_TG_TOKEN=你的TG机器人Token \
  -e APP_TG_CHAT_ID=你的ChatID \
  -e APP_WEB_ENABLED=true \
  -e APP_WEB_LISTEN=:8080 \
  -e APP_WEB_AUTH_TOKEN=替换成强口令 \
  -v $(pwd)/configs/config.yaml:/app/configs/config.yaml \
  resource-sentinel:latest
```

### 3. 使用 docker-compose

```bash
docker compose up -d --build
```

## 配置说明

`configs/config.yaml`:

```yaml
monitor:
  interval: 10m
  cpu_window: 1s
  disk_path: "/"
  consecutive: 3
  thresholds:
    cpu: 85
    memory: 80
    disk: 90

notify:
  telegram:
    enabled: false
    token: ""
    chat_id: ""
  wechat:
    enabled: false
    webhook: ""
  iyuu:
    enabled: false
    token: ""
  webhook:
    enabled: false
    url: ""
  pushplus:
    enabled: false
    token: ""
    template: "txt"
    topic: ""

web:
  enabled: true
  listen: ":8080"
  auth_token: "CHANGE_ME_STRONG_TOKEN" # 首次启动占位值，进入控制台后需先设置新口令
  allowed_cidrs: []
  rate_limit_per_minute: 120
```

### 环境变量覆盖

- `APP_MONITOR_INTERVAL` 例如 `10m`
- `APP_MONITOR_CPU_WINDOW` 例如 `1s`
- `APP_MONITOR_DISK_PATH` 例如 `/`
- `APP_MONITOR_CONSECUTIVE` 例如 `3`
- `APP_THRESHOLD_CPU` 例如 `85`
- `APP_THRESHOLD_MEMORY` 例如 `80`
- `APP_THRESHOLD_DISK` 例如 `90`
- `APP_TG_ENABLED` 例如 `true`
- `APP_TG_TOKEN`
- `APP_TG_CHAT_ID`
- `APP_WECHAT_ENABLED` 例如 `true`
- `APP_WECHAT_WEBHOOK` 企业微信机器人 webhook 地址
- `APP_IYUU_ENABLED` 例如 `true`
- `APP_IYUU_TOKEN` IYUU token
- `APP_WEBHOOK_ENABLED` 例如 `true`
- `APP_WEBHOOK_URL` 三方平台 webhook 地址
- `APP_PUSHPLUS_ENABLED` 例如 `true`
- `APP_PUSHPLUS_TOKEN` PushPlus token
- `APP_PUSHPLUS_TEMPLATE` 推送模板（`txt`/`html`/`json`/`markdown`）
- `APP_PUSHPLUS_TOPIC` 群组编码（可选）
- `APP_WEB_ENABLED` 例如 `true`
- `APP_WEB_LISTEN` 例如 `:8080`
- `APP_WEB_AUTH_TOKEN` 配置台访问口令（公网监听时必填）
- `APP_WEB_ALLOWED_CIDRS` 允许访问配置台的 IP/CIDR（逗号分隔，可选）
- `APP_WEB_RATE_LIMIT_PER_MINUTE` 配置台单 IP 每分钟请求上限（默认 `120`）

## Web 配置页

- 默认地址：`http://<host>:8080/`
- API：
  - `GET /api/config` 读取结构化配置
  - `POST /api/config` 保存结构化配置
  - `GET /api/config/raw` 读取配置
  - `POST /api/config/raw` 保存配置
- 页面支持直接输入访问口令，口令会自动附加到 API 请求头
- 当 `auth_token` 为默认占位值 `CHANGE_ME_STRONG_TOKEN` 时，控制台会进入首次初始化流程，需先设置新口令
- 登录后基于 HttpOnly 会话 Cookie 访问 API，不再支持请求头携带口令
- 保存配置后访问口令会立即生效，其他配置仍需重启进程/容器生效

## 公网安全建议

1. 配置 `APP_WEB_AUTH_TOKEN`，使用长度 >= 16 的随机口令并定期轮换。
2. 使用 `APP_WEB_ALLOWED_CIDRS` 做来源 IP 白名单，仅允许办公网或堡垒机访问。
3. 保持 `APP_WEB_RATE_LIMIT_PER_MINUTE` 启用，减少暴力尝试风险。
4. 对外暴露时建议放在 Nginx/Caddy 之后并开启 HTTPS；容器端口默认仅绑定本机 `127.0.0.1`。

## Telegram 准备

1. 用 `@BotFather` 创建机器人，拿到 token。
2. 将机器人拉进目标群或私聊，拿到 `chat_id`。

## 企业微信机器人准备

1. 在群机器人里创建自定义机器人。
2. 复制 webhook URL，配置到 `APP_WECHAT_WEBHOOK`。

## IYUU 准备

1. 在 IYUU 平台获取 token。
2. 配置 `APP_IYUU_TOKEN`，并将 `APP_IYUU_ENABLED` 设为 `true`。
3. 当前实现使用 IYUU 官方接口：`https://iyuu.cn/<token>.send`（发送 `text/desp`）。

## 通用 Webhook 准备

1. 将目标平台的 webhook 地址配置到 `APP_WEBHOOK_URL`。
2. 将 `APP_WEBHOOK_ENABLED` 设为 `true`。
3. 发送 payload 为 JSON：`{\"title\":\"...\",\"body\":\"...\"}`。

## PushPlus 准备

1. 在 PushPlus 平台获取 token。
2. 配置 `APP_PUSHPLUS_TOKEN`，并将 `APP_PUSHPLUS_ENABLED` 设为 `true`。
3. 可选配置 `APP_PUSHPLUS_TEMPLATE` 和 `APP_PUSHPLUS_TOPIC`。
4. 当前实现默认调用 `https://www.pushplus.plus/send`。

## 告警策略

默认策略：

- CPU >= 85% 连续 3 次触发告警
- 内存 >= 80% 连续 3 次触发告警
- 磁盘 >= 90% 连续 3 次触发告警
- 指标回落到阈值以下发送恢复通知
