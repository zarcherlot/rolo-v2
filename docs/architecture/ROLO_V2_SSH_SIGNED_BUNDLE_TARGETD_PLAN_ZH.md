<!-- status: draft; authority: plan; owner: rolo maintainers; last_reviewed: 2026-09-04 -->

# Rolo v2 优雅 SSH Bundle 与 rolo-targetd 开发计划

本文定义最终执行层：普通 SSH 登录和目标机已有软件栈是基础；Probe/Harness 直接执行已绑定
操作；Codex 通过 `rolo skill` 默认安装 `rolo-targetd`。一次真实用户旅程建立一个跨
Probe→Trace→Certify 的 `journey_session`；targetd 就绪后，连续执行的三个阶段共用一条
SSH stdio 通道，在 session 内复用多次 Tool 调用、事件流和取消。全程不引入额外 collector。

## 1. 基线和目标

| 项目 | 基线/目标 |
|---|---|
| 传输 | 普通 SSH、固定 host key/identity、无 PTY/转发 |
| 执行环境 | 目标机已有 Python、ROS/Middleware 和应用软件栈 |
| Probe | 可直接通过普通 SSH 探测目标软件栈；不写入业务工作区 |
| targetd | `rolo skill` 在 journey session bootstrap 阶段默认安装并验证；进入 Probe/Trace/Certify 前要求 healthy |
| Bundle | 签名、按 digest 寻址、不可变；通过 journey session 级 SSH stdio 传输，目标端缓存 |
| 工作区 | 不写入机器人业务工作区；只使用 targetd 专用缓存/run 目录 |

当前 main 已有 `SshTargetExecutor.run_transient_code`（stdin → `python3 -`）和
`HarnessCodeBundle.source_sha256`。本计划将其升级为 manifest 签名、调用与 bundle 分离、
分帧协议、目标端缓存和断线恢复；不引入 collector 抽象。

## 2. 调用方向和安装策略

```text
Codex / Agent harness
  → rolo skill
  → rolo CLI/API
  → 普通 SSH bootstrap
  → rolo-targetd
  → 目标机已有软件栈
```

Rolo 不调用 Codex，Codex 不直接拼 SSH/scp/rsync。Codex 只需加载并调用 `rolo skill`；skill
负责发现本地 Rolo 版本、创建 journey session、检查目标机状态，并在该 session 的
bootstrap 阶段自动调用：

```bash
rolo targetd status --profile landerpi
rolo targetd install --profile landerpi
rolo targetd health --profile landerpi
```

profile 创建和 SSH 可达性检查完成后，skill 立即创建 `journey_session`，然后在该 session
内执行 targetd bootstrap。targetd 未安装时，bootstrap 阶段通过普通 SSH 安装并启动
targetd；targetd healthy 后，协议桥接把同一条 SSH stdio 通道交给 targetd。随后 Probe、
Trace、Tool Invoke 和 Certify 均通过该 session 执行。用户不需要再单独下发一次
`rolo targetd install` 指令。

## 3. 组件架构

```text
Codex + rolo skill
        │ typed CLI/API request
Rolo controller
  profile / policy / signer / session / artifact
        │ one pinned SSH stdio channel per journey_session
SSH forced entrypoint / protocol bridge
        │ local IPC
rolo-targetd
  verify → cache → lease → isolated worker
        │
目标机已有软件栈（Probe/Harness/ROS/Middleware/Application）
```

targetd 不暴露公网端口。SSH key 使用 fixed command/无 PTY/无转发策略，业务用户不能用同一
凭据绕过 Rolo。

## 4. Bundle 和调用模型

### 4.1 签名 Bundle manifest

```json
{
  "schema_version": "rolo-execution-bundle/v1",
  "bundle_digest": "sha256:...",
  "signer_key_id": "rolo-release-2026-09",
  "signature": "base64url(...)",
  "tool_id": "app.mapping.start",
  "runtime": "python3",
  "entrypoint": "execute",
  "source_digest": "sha256:...",
  "binding_digest": "sha256:...",
  "dependencies": [],
  "observation_contract": {},
  "limits": {"max_duration_s": 60, "max_output_bytes": 65536}
}
```

签名覆盖 canonical manifest、文件 digest、Tool binding 和 release version。source digest
只证明内容完整，不单独授予执行权。

### 4.2 每次调用 envelope

```json
{
  "schema_version": "rolo-execution-request/v1",
  "run_id": "trace-001",
  "session_id": "session-001",
  "target_id": "landerpi",
  "bundle_digest": "sha256:...",
  "binding_digest": "sha256:...",
  "surface_digest": "sha256:...",
  "arguments": {"output_path": "/opt/rolo/maps/run-001"},
  "mode": "SUPERVISED_FIELD_DEBUG",
  "deadline": "2026-09-04T12:00:00Z"
}
```

参数变化只产生新 request，不重新上传不可变 bundle。targetd 必须再次验证 target、Tool、
binding、surface、session、参数边界和执行模式。

## 5. Journey session 级 SSH stdio 协议

每个 Probe→Trace→Certify 用户旅程只建立一个 `journey_session`。skill 建立 session 后，
先打开一条 SSH stdio 通道执行 bootstrap；targetd healthy 后由远端 `exec`/协议交接把该
通道转为 targetd 通道。控制、事件和结果继续在同一 session 的 SSH stdio 上复用：

```text
OPEN_JOURNEY → session_id/target_id/profile/protocol/phase=BOOTSTRAP
BOOTSTRAP    → targetd status/install/health
HANDOFF      → targetd capability digest/phase=PROBE
HAS          → bundle_digest（可重复多次）
PUT          → cache miss 时发送 manifest 和 bundle
CALL         → call_id/idempotency_key/bundle/binding/arguments/deadline
EVENT        ← call_id/sequence/accepted/started/observation/stopped
RESULT       ← call_id/idempotency_key/status/result/evidence/artifacts
CANCEL       → session_id/call_id
PHASE_CHANGE → session_id/from/to/user_confirmation_ref
CLOSE_SESSION→ session_id

RESUME_SESSION → session_id + resume token
QUERY_CALL     → idempotency_key（查询断线前是否已执行）
```

约束：

- 每帧有大小上限、序号、run_id 和 digest；`CANCEL` 优先于普通输出；
- 一条通道只属于一个 `journey_session`；Probe、Trace、Certify 以及其中的多个 Tool
  `CALL` 在同一旅程内复用该 SSH 连接；不同用户旅程不共享 SSH 连接；
- 阶段切换由 Rolo 控制器发出 `PHASE_CHANGE`，例如 `PROBE → WAITING_CONFIRMATION → TRACE`
  或 `TRACE → CERTIFY`；用户确认是状态门，不是新建 session 的理由；
- session 内的多个 `CALL` 复用同一 SSH 连接，不为每次 Tool 调用重新认证；
- 不传自由 shell 字符串，不依赖完整 stdout；
- SSH 断开不自动重发写/运动请求；重新连接先以 `session_id + resume token` 恢复，再用每个
  `idempotency_key` 查询调用状态；只有明确为 `NOT_ACCEPTED` 的调用才允许重发；
- targetd 必须持久化 session lease、call receipt 和最终 result，保证同一 idempotency key
  不会执行两次；
- targetd 使用本地 deadline/lease 收尾，结果区分 `SUCCEEDED/FAILED/STOPPED/CANCELLED/UNKNOWN`；
- bundle 缓存与业务工作区隔离，例如 `/var/lib/rolo-targetd/bundles/<digest>`。

## 6. 生命周期

```text
PROFILE_READY → SSH_REACHABLE → TARGETD_INSTALL_REQUESTED
             → TARGETD_HEALTHY → EXECUTION_READY
```

```text
LOCAL_SIGNED → HAS(digest)
                 ├─ hit  → EXEC
                 └─ miss → PUT → VERIFY → COMMIT → EXEC
```

运行状态：

```text
REQUESTED → ACCEPTED → STARTED → OBSERVING → SUCCEEDED
                                  ├─ FAILED / STOPPED / CANCELLED / UNKNOWN
```

### 5.1 逻辑 session 与物理连接

`journey_session` 是跨阶段的逻辑边界，绑定 target、surface digest、用户意图、证据和
审计上下文。SSH stdio 是该逻辑 session 的当前物理通道：

- 连续执行时 Probe、Trace、Certify 共用同一条通道；
- 用户确认等待、网络抖动或本地进程重启导致通道关闭时，不创建新的
  `journey_session`，而是在 lease TTL 内用 `session_id + resume token` 恢复；
- 恢复后先同步 phase、事件序号和未决调用，再由 `idempotency_key` 查询结果；只对明确
  `NOT_ACCEPTED` 的调用重发；
- 只有用户开启新的目标、独立意图或结束当前旅程时，才创建新的 session。

SSH 通道状态与 journey session 绑定：`OPEN_BOOTSTRAP → HANDOFF → ACTIVE → RESUMING? → CLOSED`；
阶段状态为 `BOOTSTRAP → PROBE → WAITING_CONFIRMATION → TRACE → CERTIFY → COMPLETE`，其中
后续阶段可按用户意图跳过。session 结束时先发送 `CLOSE_SESSION`，targetd 固化未决调用状态；连接异常时保留
lease，允许在 TTL 内使用 `session_id + resume token` 恢复。`idempotency_key` 是调用级
去重键，不能被新的参数复用。

## 7. 最大并行开发计划

| 工作流 | 开发内容 | 主要产物 | 依赖 |
|---|---|---|---|
| B0 | manifest/request/frame/schema、错误码和版本规则 | JSON Schema、协议文档 | 无 |
| B1 | targetd service、IPC、worker、health、lease、cancel | targetd package/service | B0 |
| B2 | bundle builder、canonical digest、签名和缓存 | builder、签名工具、fixture | B0 |
| B3 | journey session 级 SSH stdio、OPEN_JOURNEY/BOOTSTRAP/HANDOFF/CALL/EVENT/CANCEL、PHASE_CHANGE、HAS/PUT、分帧、超时、重连查询 | Rolo session client、bridge | B0、B1 |
| B4 | skill 安装/升级 targetd、health、意图路由 | `skills/rolo/SKILL.md`、runbook | B0、B1 |
| B5 | Probe/Trace/Tool/Certify 统一调用 envelope | CLI/API adapter、contract tests | B0、B2、B3 |
| B6 | LanderPi 目标栈、建图 Tool、现场操作、10 条用例 | 真机 canary、报告 | B1～B5 |
| B7 | 签名失败、cache hit、断线、回滚、版本矩阵 | CI、replay、release checklist | B0～B6 |

B1、B2、B4 可并行；B3 使用 targetd mock；B5 使用 fake target；B6 在集成门后进行；B7
从第一天开始编写 replay 和 contract 测试。

## 8. 里程碑和验收

| 门 | 验收条件 |
|---|---|
| G0 | schema、签名覆盖、frame 和错误码冻结 |
| G1 | Codex 按 skill 触发安装；普通 SSH bootstrap 成功；targetd health/capability 通过 |
| G2 | 首次 bundle PUT 成功；同 digest 第二次命中缓存；同一 journey session 内 Probe/Trace/Certify 多次 CALL 复用 SSH；业务工作区无新文件 |
| G3 | Probe/Harness 直接调用目标已有软件栈；Tool/绑定/证据完整回传 |
| G4 | Probe→Trace→Certify 连续旅程的成功、超时、取消、断线恢复和不可恢复错误均不重复执行；通过 session_id + idempotency_key 核验 |
| G5 | Certify 用户明确触发后 10 条用例逐条执行，报告与 digest 一致 |
| G6 | LanderPi 完成一次 Codex→skill→Rolo→targetd→建图 Trace，可选执行 Certify |

## 9. LanderPi MVP 走查

1. Codex 加载 `rolo skill`，安装本地 Rolo 并完成 profile/preflight。
2. Rolo 通过普通 SSH 检查目标机已有软件栈；只使用目标已有软件，不写业务工作区。
3. Codex 触发 `rolo targetd install`；Rolo 通过同一普通 SSH bootstrap 安装并验证 targetd。
4. `rolo skill` 创建一个 `journey_session`，在同一 session 内完成 targetd bootstrap；随后
   调用 `probe`，读取证据并在 UI 中等待用户确认，再按用户意图继续 `trace`，需要时执行
   `certify`。
5. Bootstrap→Probe→Trace→Certify 共用一条 SSH stdio；session 内多次调用、事件流和取消复用该通道；
   cache hit 时不重复传源码；若确认等待或断线导致连接关闭，则按同一 session 恢复。
6. targetd 在专用目录保存 bundle/run 状态，目标业务工作区不被修改。
7. Codex 读取结构化结果，自行决定诊断、恢复或结束；Rolo 记录证据和审计。

## 10. 非目标

- 不引入额外 SSH collector；
- 不允许 Codex 直接操作 SSH、scp、rsync 或目标 shell；
- 不把 bundle 签名当成物理安全或功能安全证明；
- 不把 Certify 设为每次用例的必经步骤；
- 不在本阶段承诺无人值守写入。
