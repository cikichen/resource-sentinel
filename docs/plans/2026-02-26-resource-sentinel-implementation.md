# Resource Sentinel Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 构建一个可 Docker 部署的系统资源监控服务，支持 CPU/内存/磁盘阈值告警，并通过微信机器人和 Telegram 发送通知。

**Architecture:** 使用 Go 单进程服务，按固定间隔采集系统资源数据，通过阈值评估器输出告警/恢复事件，再由通知聚合器分发到多个通道。配置使用 YAML + 环境变量覆盖，便于容器化部署。

**Tech Stack:** Go、gopsutil、YAML、Docker、docker-compose

---

### Task 1: 阈值评估核心（TDD）

**Files:**
- Create: `internal/monitor/evaluator_test.go`
- Create: `internal/monitor/evaluator.go`

**Step 1:** 写失败测试，覆盖连续触发告警与恢复通知。

**Step 2:** 运行 `go test ./internal/monitor -v` 确认失败。

**Step 3:** 实现最小评估逻辑让测试通过。

**Step 4:** 再次运行 `go test ./internal/monitor -v` 确认通过。

### Task 2: 采集与通知通道

**Files:**
- Create: `internal/monitor/collector.go`
- Create: `internal/notify/notifier.go`
- Create: `internal/notify/telegram.go`
- Create: `internal/notify/wechat.go`

**Step 1:** 定义采样结构与采集器接口。

**Step 2:** 实现 Telegram/WeChat Webhook 通知。

**Step 3:** 实现多通道聚合发送与错误汇总。

### Task 3: 配置加载与运行编排

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/service/service.go`
- Create: `cmd/monitor/main.go`

**Step 1:** 实现 YAML 配置解析和环境变量覆盖。

**Step 2:** 实现定时采样 -> 阈值评估 -> 发送通知主循环。

**Step 3:** 支持信号优雅退出。

### Task 4: Docker 与交付文档

**Files:**
- Create: `Dockerfile`
- Create: `docker-compose.yml`
- Create: `configs/config.example.yaml`
- Create: `README.md`

**Step 1:** 提供多阶段 Docker 构建。

**Step 2:** 提供 docker-compose 运行模板。

**Step 3:** 补充配置说明、启动步骤和告警示例。

### Task 5: 收口验证

**Files:**
- Modify: `go.mod` / `go.sum`

**Step 1:** 执行 `go test ./...`。

**Step 2:** 执行 `go build ./cmd/monitor`。

**Step 3:** 记录验证结果并输出使用说明。
