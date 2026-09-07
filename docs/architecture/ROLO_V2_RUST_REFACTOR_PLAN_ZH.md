<!-- status: draft; authority: plan; owner: rolo maintainers; last_reviewed: 2026-09-06; prerequisite: ROLO_V2_POST_COMPILER_PRODUCT_ROADMAP_ZH.md + ROLO_V2_SSH_SIGNED_BUNDLE_TARGETD_PLAN_ZH.md -->

# Rolo v2 Rust 重构方案：Journey 执行平面

## 1. 目标和结论

本方案把 Rust 重构边界放在可信执行平面：Controller 与目标机之间的 session transport、
SSH fixed entrypoint、Unix socket、`rolo-targetd`、Bundle cache、worker supervisor、
取消/恢复和资源隔离。Agent Harness、Probe/RKB/MHS 业务语义和 ROS/Python/C++ provider
暂时继续复用既有实现。

路线图完成后的产品闭环保持不变：

```text
Probe
  → Compile Context
  → Coding Agent 生成 DSL
  → Compiler 生成 Canonical IR / Bundle Plan
  → targetd 绑定目标机已有 runtime
  → C1～C4 + T1～T4 Conformance
  → immutable Tool Release
  → Trace / Certify 消费 Release
```

Rust 重构不改变这个用户旅程，也不把 Agent 变成 SSH 客户端。它只替换执行链路的实现，
使每个 `journey_session` 拥有一条可复用、可恢复、可审计的目标执行通道。

## 2. 产品边界

```text
Codex / 其他 Agent
  │ rolo skill → rolo CLI / loopback API
  ▼
Rolo Controller
  │ profile / policy / signer / session / artifact
  │ one pinned SSH stdio channel per journey_session
  ▼
SSH fixed entrypoint / protocol bridge
  │ stdio → local Unix socket
  ▼
rolo-targetd
  ├─ manifest / digest / signature verification
  ├─ session lease / phase / idempotency
  ├─ bundle cache and immutable run directory
  ├─ target runtime / provider resolver
  ├─ isolated worker supervisor
  ├─ cancel / stop / timeout
  └─ receipts / events / result / audit
  ▼
目标机已有 Python、ROS、Middleware、MHS 和应用软件栈
```

以下规则是不可变的产品约束：

- Agent 只提交意图、DSL、typed arguments 和结构化 follow-up request；不得直接操作 SSH、
  shell、`scp`、`rsync`、targetd 或 Tool Catalog。
- Compiler 只负责 DSL、Context、IR、Bundle Plan 和 diagnostics；不连接目标机，不执行 DSL。
- targetd 只解析和执行目标机已经存在且被 Probe 观察到的软件能力。
- 目标业务 workspace 不写入。Bundle 和运行状态存放在 targetd 专用目录。
- Trace 只消费 `PUBLISHED` 且 digest 仍然匹配的 Release；Certify 只有用户明确要求时才运行。

## 3. 为什么 Rust 只重构执行平面

Rust 在以下方面收益明确：

- 目标机可部署单一静态 binary，减少 Python 版本、依赖和启动环境差异；
- Tokio 和 typed framing 适合长连接、事件流、超时、取消、重连和并发 session；
- Bundle cache、lease、receipt、idempotency 和 worker 生命周期更容易集中管理；
- `serde`、签名、digest 和 schema 结构可以做成显式类型，减少边界隐式转换；
- targetd 可以低内存运行，并通过 cgroup、seccomp、bubblewrap 或 systemd scope 管理 worker。

全量 Rust 化的代价也很高：

- ROS2、MHS 和 vendor provider 仍有大量 Python/C++ 生态依赖；
- Agent Harness 和 skill 的模型调用并不因 Rust 获得明显收益；
- Rust SSH library 可能改变现有 host-key、ssh-agent、known_hosts 和 Windows 行为；
- Python 与 Rust 双实现期间需要维持相同 schema、digest、错误码和 artifact 行为；
- Rust targetd 本身不能让 Agent 生成的任意代码变安全，仍需要 WASM 或 OS sandbox。

因此，Rust 的第一目标是“可靠地承载已验证执行”，不是重写整个 Rolo 领域模型。

## 4. 组件拆分

建议新增 Rust workspace，crate 边界与现有产品契约对应：

```text
rust/
  crates/rolo-contracts
    DSL/Context/IR/Bundle/Release/Session/Frame 的 serde 类型
  crates/rolo-crypto
    canonical bytes、SHA-256、Ed25519 manifest 签名
  crates/rolo-policy
    target/session/phase/TTL/allowlist/idempotency 校验
  crates/rolo-transport
    OpenSSH process、length-delimited frame、重连和事件流
  crates/rolo-targetd
    Unix socket service、cache、lease、worker supervisor、health
  crates/rolo-runtime
    provider resolver、Python/WASM loader、sandbox adapter
  crates/rolo-controller-client
    Python/CLI/API 可调用的 Controller adapter
  crates/rolo-targetd-cli
    install、health、status、diagnostics 和版本输出
```

第一阶段保留 Python 入口：`rolo`、`robotctl`、Probe、Compiler、Release Publisher、Trace
和 Certify 继续对外提供现有 JSON contract；它们通过 `rolo-controller-client` 或兼容协议
调用 Rust 执行平面。

## 5. Journey session 和物理连接

逻辑边界是 `journey_session`，物理通道是它当前持有的一条 SSH stdio 连接：

```text
OPEN_JOURNEY
  → targetd bootstrap/status/health
  → HANDOFF
  → PROBE
  → WAITING_CONFIRMATION
  → TRACE
  → CERTIFY（可选）
  → CLOSE_SESSION
```

约束如下：

- 一条 SSH 通道只属于一个 `journey_session`；Probe、Trace、Certify 内的多个 `CALL` 复用它。
- 用户确认等待、网络抖动或 Controller 重启不创建新 session；在 lease TTL 内通过
  `session_id + resume_token` 恢复。
- 恢复后先同步 phase、最后事件序号和未决调用，再用 `idempotency_key` 查询调用状态。
- 只有明确返回 `NOT_ACCEPTED` 的调用允许重发；写入或运动调用不得因断线自动重发。
- 一个 session 结束后 targetd 固化未决调用状态，不再接受新的 CALL。

SSH 仍由系统 OpenSSH 负责，以保留已验证的安全参数：

```text
BatchMode=yes
StrictHostKeyChecking=yes
UserKnownHostsFile=<pinned file>
GlobalKnownHostsFile=none
IdentitiesOnly=yes（使用 pinned identity 时）
ForwardAgent=no
ClearAllForwardings=yes
No PTY
```

Rust 初期通过 `std::process::Command` 启动 OpenSSH。只有在 contract、负向测试和跨平台
凭据行为稳定后，才评估切换到 native SSH library。

## 6. Fixed entrypoint 和 Unix socket

目标机的 SSH key 使用 forced command，例如：

```text
command="/usr/local/libexec/rolo-ssh-gateway",no-pty,no-agent-forwarding,no-port-forwarding,no-X11-forwarding
```

`rolo-ssh-gateway` 不解析用户提供的 shell 命令，也不接受目标路径参数，只完成：

1. 检查 stdin/stdout 是非交互模式；
2. 连接 root-owned 或受控 group-owned 的 Unix socket；
3. 双向转发受限 framed protocol；
4. 在协议结束或 socket 断开时清理连接。

最终授权仍由 targetd 完成，不能把“能连上 Unix socket”当成执行授权。targetd 要再次
检查 signer、target、session、phase、release/bundle digest、参数和 mode。

## 7. Bundle、缓存和执行模型

### 7.1 Manifest

沿用现有 `rolo-execution-bundle/v1` 方向，签名覆盖 canonical manifest、所有文件 digest、
Tool binding、Release version 和执行限制：

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
  "limits": {"max_duration_s": 60, "max_output_bytes": 65536}
}
```

`source_digest` 只证明完整性，不单独授予执行权。执行权来自已发布 Release、targetd policy、
session 和 target conformance。

### 7.2 HAS/PUT/COMMIT

```text
Controller: HAS(bundle_digest)
targetd:    HIT / MISS
Controller: PUT(manifest, framed chunks)       # 仅 MISS
targetd:    VERIFY(signature, size, file digests)
targetd:    COMMIT(atomic rename into cache)
Controller: CALL(bundle_digest, typed arguments)
```

缓存目录与业务 workspace 分离：

```text
/var/lib/rolo-targetd/bundles/<bundle_digest>/
/var/lib/rolo-targetd/runs/<session_id>/<call_id>/
```

Bundle 不覆盖，运行目录按 call 隔离。重复请求必须幂等，缓存命中时不重新传输源码。

### 7.3 Runtime 策略

执行 runtime 分三层：

1. `OBSERVE`、`COMPOSE`、`INVOKE` 优先使用 targetd 已注册 provider，不运行 Agent 源码；
2. `EXECUTE` 只加载 manifest 声明、签名、版本和 implementation contract 匹配的 bundle；
3. 长期优先编译为 WASM/WASI，通过有限 host API 访问 ROS/MHS；Python bundle 作为兼容模式，
   由 targetd 负责 `-I`、依赖、环境、隔离和停止。

Rust targetd 负责监督 worker，实际 ROS provider 可以继续是 Python/C++：

```text
targetd
  → sandbox worker
  → local ROS/Python provider
  → bounded result/event
```

targetd 不给 worker 任意 shell、网络、未声明文件或未绑定目标地址。

## 8. Protocol frames

建议先用 JSON envelope 作为契约格式，用 length-delimited framing 解决边界问题；后续可在同一
schema 上增加 CBOR 编码。每帧至少包含：

```text
schema_version
frame_type
session_id
run_id / call_id
sequence
payload_digest
```

核心帧：

```text
OPEN_JOURNEY
BOOTSTRAP
HANDOFF
HAS
PUT
DSL_PUT
DSL_CHECK
PLAN_RESOLVE
TARGET_COMPILE
TARGET_CONFORMANCE
CALL
EVENT
RESULT
CANCEL
QUERY_CALL
RESUME_SESSION
PHASE_CHANGE
CLOSE_SESSION
```

`DSL_PUT → DSL_CHECK → PLAN_RESOLVE → TARGET_COMPILE → TARGET_CONFORMANCE` 直接复用现有
Compiler/targetd 交接，不再定义 Rust 私有 DSL 或 IR。

## 9. Controller 兼容层

Rust 迁移期间，Python Controller 保留现有业务 API，并增加一个执行后端适配器：

```python
class ExecutionPlane(Protocol):
    def open_journey(self, request: JourneyRequest) -> JourneyHandle: ...
    def put_bundle(self, bundle: SignedBundle) -> PutReceipt: ...
    def call(self, request: ExecutionRequest) -> CallHandle: ...
    def cancel(self, call_id: str) -> CancelReceipt: ...
    def resume(self, session_id: str, resume_token: str) -> JourneyHandle: ...
```

原有 Probe、Trace、Certify 只依赖这个抽象，不直接依赖 OpenSSH、Unix socket 或 Rust binary。
这样可以同时运行：

```text
legacy Python executor  ← feature flag →  Rust targetd executor
```

两条后端必须输出同一个 `rolo-post-compiler-journey-result/v1` 和相同 artifact index 结构。

## 10. 迁移阶段

### R0 — 现状契约和基线

- 固定 DSL、Context、IR、Bundle Plan、Release Binding、Journey Result 和 frame schema；
- 为 transient execution、bundle digest、stdout/event、cancel 和 resume 添加行为测试；
- 修复当前 Python transient path 的 entrypoint、request 传递和 ROS setup 契约；
- 定义 Python executor 与 Rust executor 的等价结果矩阵。

完成条件：旧路径测试通过，Rust 还未进入生产执行。

### R1 — Rust targetd skeleton

- 实现 Unix socket service、health、version、lease 和 worker 生命周期；
- 实现 fixed SSH gateway；
- 用 fake provider 完成 `OPEN_JOURNEY → CALL → EVENT → RESULT`；
- 增加 frame size、sequence、timeout、cancel 和 malformed input 负向测试。

完成条件：fake target 可离线重放成功、失败、取消和过期 session。

### R2 — Signed Bundle 和 cache

- 实现 canonical bytes、Ed25519 manifest、HAS/PUT/VERIFY/COMMIT；
- 实现 cache hit、重复 PUT、digest mismatch、签名失败和原子提交；
- 确认目标业务 workspace 没有新文件。

完成条件：相同 bundle digest 在重复旅程中只传输一次，失败不会产生可执行缓存。

### R3 — Python Controller 双后端

- Python 通过 `ExecutionPlane` 调用 Rust targetd；
- 保留 legacy executor feature flag；
- Probe、Trace、Certify 共用 journey session 连接；
- 实现断线恢复、`QUERY_CALL` 和 idempotency receipt。

完成条件：同一 fake journey 用两种后端产生等价 phase、status、evidence 和 artifact index。

### R4 — Target runtime 和 Conformance

- 接入真实 ROS/Middleware provider resolver；
- 目标绑定 Bundle 生成与 T1～T4 Conformance；
- Python/C++ provider 由 Rust worker supervisor 托管；
- 首个只读 Tool 通过真实目标验收。

完成条件：targetd 只执行 Probe 观察到的已有能力，缺依赖明确返回 `BLOCKED` 或 `UNKNOWN`。

### R5 — Release、Trace、Certify 集成

- Release Publisher 消费 Rust targetd conformance；
- Trace/Certify 只消费 `PUBLISHED` Release Binding；
- 实现 stale、rollback、cancel、resume 和事件回放；
- 完成 LanderPi `Probe → DSL → Compile → Conformance → Release → Trace`，Certify 作为显式第二路径。

完成条件：真实 journey 的全部 digest 可从 artifact index 复核。

### R6 — WASM 和现场发布

- 为稳定的 EXECUTE contract 增加 WASM/WASI runtime；
- 将 Python source bundle 限制为兼容模式；
- 完成 targetd 安装、升级、卸载、health、回滚和版本窗口；
- 默认切换 Rust execution plane，legacy backend 仅保留回滚窗口。

完成条件：CI、offline replay、fake target 和 LanderPi canary 全部通过，才进入 field release。

## 11. 测试和门禁

每个门都必须同时覆盖：

- schema/version mismatch；
- target、session、phase、surface、Context、binding 和 release digest mismatch；
- signature failure、cache miss/hit、partial upload 和 atomic commit；
- timeout、cancel、stop、disconnect、resume 和 duplicate idempotency key；
- provider/runtime 缺失、输出超限和 worker 崩溃；
- 业务 workspace 无写入；
- Trace/Certify 的结果与旧 Python executor 的兼容矩阵；
- artifact index 能串起 Context、DSL、IR、Bundle、Conformance、Release、Trace 和 Certify。

关键验收门：

| 门 | 条件 |
|---|---|
| R0 | 契约冻结，旧执行路径有 characterization tests |
| R1 | Rust targetd fake journey 可重放 |
| R2 | 签名 Bundle、cache 和原子提交通过负向矩阵 |
| R3 | Python/Rust 双后端结果等价，断线不重复执行 |
| R4 | 真实 target runtime 和 T1～T4 通过 |
| R5 | Tool Release、Trace、Certify 和 stale/rollback 完成 |
| R6 | LanderPi 真机 journey、CI、回放和 field runbook 通过 |

## 12. 完成后的运行形态

用户看到的调用方式保持稳定：

```text
“发现/注册建图能力”
  → Probe
  → Agent 生成 DSL
  → Compiler
  → targetd compile/conformance
  → Tool Release

“完成建图”
  → Trace session
  → 已发布 Tool CALL
  → targetd worker
  → 事件、诊断、结果和 Episode evidence

“执行建图验收”
  → Certify
  → 同一 Release 的逐用例调用
  → expected/actual/status/evidence 报告
```

Rust 只改变内部执行方式：

```text
Agent → Rolo API → Rust execution plane → fixed SSH → Unix socket → targetd → provider/worker
```

它不改变 Agent 的权限、不改变 DSL/IR/Release 语义，也不把目标机业务 workspace 变成部署目录。

## 13. 推荐决策

建议批准以下工程决策：

1. Rust 以 `rolo-targetd`、SSH gateway、transport、cache、policy 和 worker supervisor 为第一交付目标；
2. Python Controller 通过兼容层调用 Rust，至少保留一个完整 release window 的 legacy backend；
3. 系统 OpenSSH 继续作为第一阶段的 SSH 实现，native SSH library 延后；
4. `OBSERVE/COMPOSE/INVOKE` 优先使用 provider，`EXECUTE` 采用签名 bundle，长期迁移到 WASM；
5. 不同步到业务 workspace，所有 bundle 使用 HAS/PUT/cache/COMMIT；
6. Rust backend 必须先通过与 Python backend 的等价 contract tests，才能成为默认执行路径。
