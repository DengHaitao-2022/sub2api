# sub2api 项目开发指南

> 本文档记录项目环境配置、常见坑点和注意事项，供 Claude Code 和团队成员参考。

## 一、项目基本信息

| 项目 | 说明 |
|------|------|
| **上游仓库** | Wei-Shaw/sub2api |
| **Fork 仓库** | bayma888/sub2api-bmai |
| **技术栈** | Go 后端 (Ent ORM + Gin) + Vue3 前端 (pnpm) |
| **数据库** | PostgreSQL 16 + Redis |
| **包管理** | 后端: go modules, 前端: **pnpm**（不是 npm） |

## 二、本地环境配置

### PostgreSQL 16 (Windows 服务)

| 配置项 | 值 |
|--------|-----|
| 端口 | 5432 |
| psql 路径 | `C:\Program Files\PostgreSQL\16\bin\psql.exe` |
| pg_hba.conf | `C:\Program Files\PostgreSQL\16\data\pg_hba.conf` |
| 数据库凭据 | user=`sub2api`, password=`sub2api`, dbname=`sub2api` |
| 超级用户 | user=`postgres`, password=`postgres` |

### Redis

| 配置项 | 值 |
|--------|-----|
| 端口 | 6379 |
| 密码 | 无 |

### 开发工具

```bash
# golangci-lint v2.7
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.7

# pnpm (前端包管理)
npm install -g pnpm
```

## 三、CI/CD 流水线

### GitHub Actions Workflows

| Workflow | 触发条件 | 检查内容 |
|----------|----------|----------|
| **backend-ci.yml** | push, pull_request | 单元测试 + 集成测试 + golangci-lint v2.7 |
| **security-scan.yml** | push, pull_request, 每周一 | govulncheck + gosec + pnpm audit |
| **release.yml** | tag `v*` | 构建发布（PR 不触发） |

### CI 要求

- Go 版本必须是 **1.25.7**
- 前端使用 `pnpm install --frozen-lockfile`，必须提交 `pnpm-lock.yaml`

### 本地测试命令

```bash
# 后端单元测试
cd backend && go test -tags=unit ./...

# 后端集成测试
cd backend && go test -tags=integration ./...

# 代码质量检查
cd backend && golangci-lint run ./...

# 前端依赖安装（必须用 pnpm）
cd frontend && pnpm install
```

## 四、常见坑点 & 解决方案

### 坑 1：pnpm-lock.yaml 必须同步提交

**问题**：`package.json` 新增依赖后，CI 的 `pnpm install --frozen-lockfile` 失败。

**原因**：上游 CI 使用 pnpm，lock 文件不同步会报错。

**解决**：
```bash
cd frontend
pnpm install  # 更新 pnpm-lock.yaml
git add pnpm-lock.yaml
git commit -m "chore: update pnpm-lock.yaml"
```

---

### 坑 2：npm 和 pnpm 的 node_modules 冲突

**问题**：之前用 npm 装过 `node_modules`，pnpm install 报 `EPERM` 错误。

**解决**：
```bash
cd frontend
rm -rf node_modules  # 或 PowerShell: Remove-Item -Recurse -Force node_modules
pnpm install
```

---

### 坑 3：PowerShell 中 bcrypt hash 的 `$` 被转义

**问题**：bcrypt hash 格式如 `$2a$10$xxx...`，PowerShell 把 `$2a` 当变量解析，导致数据丢失。

**解决**：将 SQL 写入文件，用 `psql -f` 执行：
```bash
# 错误示范（PowerShell 会吃掉 $）
psql -c "INSERT INTO users ... VALUES ('$2a$10$...')"

# 正确做法
echo "INSERT INTO users ... VALUES ('\$2a\$10\$...')" > temp.sql
psql -U sub2api -h 127.0.0.1 -d sub2api -f temp.sql
```

---

### 坑 4：psql 不支持中文路径

**问题**：`psql -f "D:\中文路径\file.sql"` 报错找不到文件。

**解决**：复制到纯英文路径再执行：
```bash
cp "D:\中文路径\file.sql" "C:\temp.sql"
psql -f "C:\temp.sql"
```

---

### 坑 5：PostgreSQL 密码重置流程

**场景**：忘记 PostgreSQL 密码。

**步骤**：
1. 修改 `C:\Program Files\PostgreSQL\16\data\pg_hba.conf`
   ```
   # 将 scram-sha-256 改为 trust
   host    all    all    127.0.0.1/32    trust
   ```
2. 重启 PostgreSQL 服务
   ```powershell
   Restart-Service postgresql-x64-16
   ```
3. 无密码登录并重置
   ```bash
   psql -U postgres -h 127.0.0.1
   ALTER USER sub2api WITH PASSWORD 'sub2api';
   ALTER USER postgres WITH PASSWORD 'postgres';
   ```
4. 改回 `scram-sha-256` 并重启

---

### 坑 6：Go interface 新增方法后 test stub 必须补全

**问题**：给 interface 新增方法后，编译报错 `does not implement interface (missing method XXX)`。

**原因**：所有测试文件中实现该 interface 的 stub/mock 都必须补上新方法。

**解决**：
```bash
# 搜索所有实现该 interface 的 struct
cd backend
grep -r "type.*Stub.*struct" internal/
grep -r "type.*Mock.*struct" internal/

# 逐一补全新方法
```

---

### 坑 7：Windows 上 psql 连 localhost 的 IPv6 问题

**问题**：psql 连 `localhost` 先尝试 IPv6 (::1)，可能报错后再回退 IPv4。

**建议**：直接用 `127.0.0.1` 代替 `localhost`。

---

### 坑 8：Windows 没有 make 命令

**问题**：CI 里用 `make test-unit`，本地 Windows 没有 make。

**解决**：直接用 Makefile 里的原始命令：
```bash
# 代替 make test-unit
go test -tags=unit ./...

# 代替 make test-integration
go test -tags=integration ./...
```

---

### 坑 9：Ent Schema 修改后必须重新生成

**问题**：修改 `ent/schema/*.go` 后，代码不生效。

**解决**：
```bash
cd backend
go generate ./ent  # 重新生成 ent 代码
git add ent/       # 生成的文件也要提交
```

---

### 坑 10：前端测试看似正常，但后端调用失败（模型映射被批量误改）

**典型现象**：
- 前端按钮点测看起来正常；
- 实际通过 API/客户端调用时返回 `Service temporarily unavailable` 或提示无可用账号；
- 常见于 OpenAI 账号（例如 Codex 模型）在批量修改后突然不可用。

**根因**：
- OpenAI 账号编辑页默认不显式展示映射规则，容易让人误以为“没映射也没关系”；
- 但在**批量修改同时选中不同平台账号**（OpenAI + Antigravity/Gemini）时，模型白名单/映射可能被跨平台策略覆盖；
- 结果是 OpenAI 账号的关键模型映射丢失或被改坏，后端选不到可用账号。

**修复方案（按优先级）**：
1. **快速修复（推荐）**：在批量修改中补回正确的透传映射（例如 `gpt-5.3-codex -> gpt-5.3-codex-spark`）。
2. **彻底重建**：删除并重新添加全部相关账号（最稳但成本高）。

**关键经验**：
- 如果某模型已被软件内置默认映射覆盖，通常不需要额外再加透传；
- 但当上游模型更新快于本仓库默认映射时，**手动批量添加透传映射**是最简单、最低风险的临时兜底方案；
- 批量操作前尽量按平台分组，不要混选不同平台账号。

---

### 坑 11：PR 提交前检查清单

提交 PR 前务必本地验证：

- [ ] `go test -tags=unit ./...` 通过
- [ ] `go test -tags=integration ./...` 通过
- [ ] `golangci-lint run ./...` 无新增问题
- [ ] `pnpm-lock.yaml` 已同步（如果改了 package.json）
- [ ] 所有 test stub 补全新接口方法（如果改了 interface）
- [ ] Ent 生成的代码已提交（如果改了 schema）

---

### 坑 12：网关审计日志实现与防遗忘清单

> 这是长期维护记忆。修改 `/admin/settings`、网关路由、Usage 审计详情或任何 `gateway_audit_*` 字段前必须先读本节。

#### 1. 核心数据流

```text
config.gateway.audit（部署默认值）
        +
settings 表 gateway_audit_*（管理员覆盖值，优先级更高）
        |
SettingService.GetGatewayAuditConfig（合并 + 60 秒缓存，保存时立即失效/回填）
        |
GatewayAuditMiddlewareWithConfigProvider（每个请求取得有效配置）
        |
handler 显式 CaptureInput / MarkAccount / MarkAttemptResult
        +
ResponseWriter 捕获状态码、响应摘要、TTFT、usage
        |
WriteEvent
   |-- JSONL：完整事件/WAL，按日期分片
   |-- Ops index：运维日志索引
   `-- PostgreSQL：可检索元数据 + JSONL 文件路径/offset
          |-- 同步写入，或 Dispatcher -> IndexWorkerPool 异步写入
          |-- BackfillScanner 从 JSONL 补漏
          `-- RetentionScheduler 清理过期索引
        |
/api/v1/admin/audit 查询索引，详情按 offset 读取完整 JSONL
        |
UsageView + AuditDetailDrawer 展示
```

设计原则：**JSONL 保存完整审计事件，PostgreSQL 主要作为查询索引**。不能把二者误认为重复存储后随意删除其中一条链路；异步索引失败时还依赖 JSONL backfill 恢复。

#### 2. 关键代码位置

| 层 | 文件 | 职责 |
|---|---|---|
| 静态配置 | `backend/internal/config/config.go` | `GatewayAuditConfig`、默认/最大正文限制 |
| Setting key | `backend/internal/service/domain_constants.go` | 全部 `SettingKeyGatewayAudit*` 常量 |
| 默认值与读取 | `backend/internal/service/setting_parse.go`、`settings_view.go` | config 默认值转 settings、数据库值转 `SystemSettings` |
| 实时配置 | `backend/internal/service/setting_gateway_runtime.go` | DB 覆盖 config、校验、缓存和 singleflight |
| 保存 | `backend/internal/service/setting_update.go` | 序列化入库、正文限制归一化、缓存失效/回填 |
| Admin 请求 | `backend/internal/handler/admin/setting_handler_update.go` | PUT 指针字段、保留未提交旧值、输入归一化 |
| Admin 响应 | `backend/internal/handler/admin/setting_handler.go` | `applyGatewayAuditSettingsDTO`，GET/PUT 必须共用 |
| DTO | `backend/internal/handler/dto/settings.go` | admin settings JSON 字段 |
| 路由挂载 | `backend/internal/server/routes/gateway.go` | 在各网关路由挂载 audit middleware 和实时 config provider |
| 输入/账号/尝试 | `backend/internal/handler/gateway_audit_helper.go` | `captureGatewayInput*`、账号快照、上游尝试结果 |
| 请求生命周期 | `backend/internal/audit/middleware.go` | enable、路径过滤、稳定采样、响应捕获、最终事件组装 |
| 上下文/事件 | `backend/internal/audit/context.go`、`event.go` | 请求内快照及最终事件结构 |
| 脱敏 | `backend/internal/audit/redact.go` | preview/full 正文结构化裁剪和敏感键脱敏 |
| 写入 | `backend/internal/audit/sink.go` | JSONL、Ops、同步/异步 PostgreSQL index |
| 异步管线 | `dispatcher.go`、`index_worker.go` | 有界队列、批量 index worker、队列满指标 |
| 恢复/保留 | `backfill_scanner.go`、`retention_scheduler.go` | JSONL 补索引、索引保留清理 |
| Runtime 启动 | `backend/internal/audit/runtime.go`、`backend/internal/service/wire.go` | worker/backfill/retention 的启动时拓扑 |
| Repository | `backend/internal/repository/gateway_audit_*.go` | 索引、批量写入及 offset 持久化 |
| Admin 查询 | `backend/internal/handler/admin/audit_handler.go`、`backend/internal/service/gateway_audit.go` | list/stats/detail/export/health/access-log/by-request |
| 前端设置 | `frontend/src/api/admin/settings.ts`、`views/admin/SettingsView.vue` | 类型、默认值、回显、保存和旧响应保护 |
| 前端查询 | `frontend/src/api/admin/audit.ts`、`components/admin/audit/*`、`views/admin/UsageView.vue` | 查询、详情抽屉、健康状态和 Usage 关联 |

#### 3. 采集模式语义

- `none`：不保留该方向正文，也不要求正文 hash。
- `hash`：只保留 SHA-256、大小、截断等元数据，不保留正文。
- `preview`：在限制内保留经过裁剪和脱敏的预览。
- `full`：保留更大范围正文，但仍受硬上限、脱敏规则和二进制内容保护约束。
- 非法或空 capture mode 必须归一化到 `preview`。
- `full` 输入硬上限为 1 MiB，输出硬上限为 2 MiB；修改限制时必须继续调用 `normalizeGatewayAuditBodyLimit`。

特别注意：middleware 可以包装响应 writer，但请求 body 往往已被 handler 消费，因此每条新网关处理链必须在解析原始 body 后调用 `captureGatewayInput` 或 `captureGatewayInputHash`。新增协议/别名路由时只挂 middleware 不等于输入审计已经完整。

#### 4. 实时生效与重启边界

`RegisterGatewayRoutes` 把 `SettingService.GetGatewayAuditConfig` 作为 provider 传给 middleware，所以以下配置按请求读取，可实时生效：

- 总开关、输入/输出 capture mode；
- sample rate、include/exclude paths、redact keys；
- 正文和 preview 限制；
- sink 开关在 `WriteEvent` 层的判断。

`ProvideGatewayAuditRuntime` 只在进程启动时依据配置创建 Dispatcher、worker、backfill、retention，因此以下拓扑/调度设置按当前实现需要重启：

- 文件路径；
- index queue size、worker count、batch size、flush interval、write timeout；
- backfill enabled/interval/batch size；
- retention cleanup interval；
- 任何决定 runtime 组件是否被创建的组合开关。

如果未来要让这些配置热更新，必须实现安全的 runtime stop/rebuild/start，而不是只修改设置页上的“实时生效”文案。

#### 5. `/admin/settings` 防覆盖约束

2026-07 曾发生一次真实回归：审计 DTO、保存和运行时逻辑都存在，但 Handler 拆分/合并时丢失了响应 struct literal 中的字段映射。Go 自动输出零值，前端因此把当前配置覆盖为 `false`、`0` 和空 capture mode，看起来像“配置未保存/输入策略消失”。

当前防线：

1. 所有审计响应字段集中在 `applyGatewayAuditSettingsDTO`。
2. `GetSettings` 和 `UpdateSettings` 成功响应都必须调用该 helper。
3. 前端统一通过 `applySettingsResponseToForm` 回填；若输入/输出 capture mode 无效，则把整组响应视为旧版不完整响应，不用零值覆盖可用默认值。
4. GET 和 PUT 均有回归测试，Handler 重构或解决 merge conflict 时不得删除。

#### 6. 新增/修改 `gateway_audit_*` 字段的强制同步清单

一个字段至少需要同步以下位置，少一处都视为未完成：

- [ ] `config.GatewayAuditConfig` 和配置默认值/校验；
- [ ] `SettingKeyGatewayAudit*`；
- [ ] `SystemSettings` service view；
- [ ] `setting_parse.go` 默认值和 DB 解析；
- [ ] `setting_gateway_runtime.go` merge、GetMultiple key 列表和缓存结果；
- [ ] `setting_update.go` 持久化及保存后的缓存回填；
- [ ] `dto.SystemSettings` JSON 字段；
- [ ] `UpdateSettingsRequest` 指针字段及“未提交则保留旧值”逻辑；
- [ ] `applyGatewayAuditSettingsDTO`；
- [ ] `setting_handler_audit.go` 设置变更审计；
- [ ] `frontend/src/api/admin/settings.ts` 的响应和更新类型；
- [ ] `SettingsView.vue` 表单默认值、UI、load/save payload；
- [ ] 中英文 i18n；
- [ ] GET/PUT 回显测试、service parse/update/runtime 测试；
- [ ] 若影响 runtime 拓扑，更新重启提示和本节说明。

#### 7. 安全与可靠性约束

- 默认脱敏列表必须覆盖 Authorization、API key、Cookie、token、password、client secret、session/conversation 标识等敏感键。
- 二进制、图片/音视频和 base64 图片响应不可写入正文预览，只记录 hash/大小等元数据。
- 采样使用 request ID/path 的稳定 hash，不能改为每次随机，否则同一请求的行为不可复现。
- include/exclude 按规范化 path 前缀匹配，exclude 优先。
- 异步队列必须有界；队列满应记录指标/告警，不能阻塞网关主链路。
- 查看详情和导出必须写 access log，保留 operator、IP、User-Agent。
- JSONL 写失败当前会返回 error 并记录告警；修改 sink 容错策略前必须明确 WAL 与 index 一致性后果。

#### 8. 最小验证命令

```bash
# Handler GET/PUT 回显与 admin 审计 API
cd backend
GOCACHE=/tmp/sub2api-go-build go test ./internal/handler/admin -count=1

# 审计中间件、脱敏、sink、worker、backfill
GOCACHE=/tmp/sub2api-go-build go test ./internal/audit -count=1

# Setting 解析、保存和实时配置
GOCACHE=/tmp/sub2api-go-build go test ./internal/service -run 'GatewayAudit|SettingService' -count=1

# 前端设置与详情类型
cd ../frontend
pnpm typecheck
pnpm exec eslint src/views/admin/SettingsView.vue src/views/admin/UsageView.vue src/api/admin/audit.ts
```

## 五、常用命令速查

### 数据库操作

```bash
# 连接数据库
psql -U sub2api -h 127.0.0.1 -d sub2api

# 查看所有用户
psql -U postgres -h 127.0.0.1 -c "\du"

# 查看所有数据库
psql -U postgres -h 127.0.0.1 -c "\l"

# 执行 SQL 文件
psql -U sub2api -h 127.0.0.1 -d sub2api -f migration.sql
```

### Git 操作

```bash
# 同步上游
git fetch upstream
git checkout main
git merge upstream/main
git push origin main

# 创建功能分支
git checkout -b feature/xxx

# Rebase 到最新 main
git fetch upstream
git rebase upstream/main
```

### 前端操作

```bash
# 安装依赖（必须用 pnpm）
cd frontend
pnpm install

# 开发服务器
pnpm dev

# 构建
pnpm build
```

### 后端操作

```bash
# 运行服务器
cd backend
go run ./cmd/server/

# 生成 Ent 代码
go generate ./ent

# 运行测试
go test -tags=unit ./...
go test -tags=integration ./...

# Lint 检查
golangci-lint run ./...
```

## 六、项目结构速览

```
sub2api-bmai/
├── backend/
│   ├── cmd/server/          # 主程序入口
│   ├── ent/                 # Ent ORM 生成代码
│   │   └── schema/          # 数据库 Schema 定义
│   ├── internal/
│   │   ├── handler/         # HTTP 处理器
│   │   ├── service/         # 业务逻辑
│   │   ├── repository/      # 数据访问层
│   │   └── server/          # 服务器配置
│   ├── migrations/          # 数据库迁移脚本
│   └── config.yaml          # 配置文件
├── frontend/
│   ├── src/
│   │   ├── api/             # API 调用
│   │   ├── components/      # Vue 组件
│   │   ├── views/           # 页面视图
│   │   ├── types/           # TypeScript 类型
│   │   └── i18n/            # 国际化
│   ├── package.json         # 依赖配置
│   └── pnpm-lock.yaml       # pnpm 锁文件（必须提交）
└── .claude/
    └── CLAUDE.md            # 本文档
```

## 七、参考资源

- [上游仓库](https://github.com/Wei-Shaw/sub2api)
- [Ent 文档](https://entgo.io/docs/getting-started)
- [Vue3 文档](https://vuejs.org/)
- [pnpm 文档](https://pnpm.io/)
