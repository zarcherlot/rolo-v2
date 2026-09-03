<!-- status: draft; authority: plan; owner: rolo maintainers; last_reviewed: 2026-09-02; reviewed_commit: decb3b7fe5f2d5685b3998880f103ab301728880; source_of_truth: ROBOT_KNOWLEDGE_BASE_FOR_AGENT_DEBUGGING_ZH.md -->

# Rolo v2 Robot Knowledge Base 可执行开发计划（修订版）

本计划依据 [开发计划评审](../review/ROLO_V2_RKB_DEVELOPMENT_PLAN_REVIEW_ZH.md) 重排，目标是
在不改变当前 v2 只读产品承诺的前提下，交付一个可安装、可测试、可回滚的 RKB 最小闭环。
旧计划已合并并从工作树移除；本文是 RKB 唯一的排期入口。

## 1. 基线、目标与边界

### 1.1 基线事实

- 基线提交：`decb3b7`，分支：`rolo-v2`；
- canonical Probe 实现：`src/rolo/stages/probe/`；
- 当前权威链路：`TargetProfile → TargetEvidenceBundle → NativeToolSession → ToolPlan → Conformance`；
- `ProbeResult` 尚未携带强类型 identity/freshness envelope；Bundle 校验有目标绑定和 replay
  window，但没有事实级 `fresh_until`；
- 当前仓库没有 `src/rolo/rkb/`、RKB schema 或 `rolo.capabilities` 包；
- 当前 v2 明确是只读产品，不包含 reset、calibrate、actuator、power、firmware 或物理安全闭环。

### 1.2 本计划目标

1. 为每个 Probe snapshot 和重要 fact 提供目标身份、来源、digest、观测时间、freshness、
   置信度和限制；
2. 在 `DECLARED`、`OBSERVED`、`VERIFIED`、`INFERRED`、`DECISION` 之间保持不可混淆的层级；
3. 将硬件、OS/runtime、middleware、application 和 capability 逐步转换为严格 read model；
4. 提供 identity/freshness-checked 的只读 query，同时保持现有 bundle/report 可读；
5. 把 MHS 作为只读硬件证据适配层验证，暂不引入物理写操作。

本计划中的“RKB artifact 写入”仅指持久化 snapshot、Episode、latest 指针等证据制品，不是向
机器人或 MHS 设备发出写命令。RKB 始终是事实/证据层；Probe 保持只读，设备写入须另行通过
Probe 后的 Rolo Write Execution 计划批准。

### 1.3 非目标与硬约束

- 不实现运动控制、急停、碰撞检测或物理安全闭环；
- 不把 Wiki、Agent 输出、源码声明或 `--help` 结果升级为目标运行事实；
- 不在本计划中开放 MHS reset/calibrate、执行器 setpoint、power-cycle 或固件更新；
- 不要求一次性支持所有 ROS 发行版、厂商驱动和非 ROS 协议；
- 新 RKB artifact 写入失败不得覆盖既有 EvidenceBundle、DiscoveryReport 或 latest index；
- 未满足依赖、测试或真机门槛时，阶段状态只能是 `BLOCKED`，不能标记 `DONE`。

## 2. 交付策略与阶段门

采用“每阶段一个纵向闭环”的方式，而不是先铺开九层模型。每个阶段都必须同时交付：

- 版本化 schema；
- 最小实现和兼容读取；
- 成功、失败、边界测试；
- 可执行验收命令；
- artifact 写入/回滚规则；
- 更新工程状态台账的证据记录。

| 阶段 | 主题 | 预计迭代 | 默认状态 | 通过后才允许 |
|---|---|---:|---|---|
| RKB-0 | 基线清点、契约冻结、依赖准备 | 1 | BLOCKED 直至清点完成 | 创建 RKB 实现分支 |
| RKB-1 | Evidence Envelope 与兼容读取 | 1–2 | OFF | 生成 RKB snapshot，不改变旧 CLI |
| RKB-2 | 分层只读模型与 typed query | 2–3 | OFF | Agent 读取摘要和受校验详情 |
| RKB-3 | MHS 只读兼容层 | 1–2 | OFF | 固定目标机只读 canary |
| RKB-4 | Episode 元数据、双读一写与灰度 | 1–2 | OFF | 进入有限发布评估 |

任何阶段若 gate 失败，保留上一阶段 artifact 和代码路径，只撤销新阶段的 latest 指针或入口。

## 3. RKB-0：基线清点、契约冻结、依赖准备

### 输入

- `src/rolo/core/models.py` 的 `ProbeResult`、`DiscoveryReport`；
- `src/rolo/stages/probe/target_evidence.py` 的 Bundle 校验；
- `src/rolo/stages/probe/discovery.py`、`routes.py`、现有 Probe contract tests；
- RKB 架构说明、审计报告和本计划。

### 输出

- `docs/architecture/RKB_CONTRACT_DECISIONS_ZH.md`：冻结 vocabulary、状态、route 和 TTL；
- `docs/reference/RKB_IMPLEMENTATION_MAP_ZH.md`：每个模型的唯一代码所有权；
- `schemas/RobotEvidenceEnvelope.schema.json` 初稿；
- `tests/test_rkb_contract_baseline.py`：基线字段与迁移样例；
- 依赖清单：本地 Python、pytest、ruff、CI matrix 和真机 canary 前置条件。

### 必须冻结的决策

1. canonical Probe 路径只使用 `src/rolo/stages/probe/`；
2. MHS canonical route 使用 `mhs://<device_id>/<capability_id>`；原型中的
   `mhs://sensor/<device_id>/<capability_id>` 只作为兼容输入，不作为新输出；
3. MHS Provider SPI 由 Rolo 自己拥有，原型不得依赖基线不存在的 `rolo.capabilities`；
4. canonical JSON 使用 UTF-8、排序 key、无多余空白和明确的 `exclude_none` 规则；
5. schema 采用显式版本号，旧 bundle 只读迁移，不回写旧 artifact；
6. 初始 freshness policy 为：middleware graph 30 秒、进程/状态 30 秒、hardware topology
   10 分钟、thermal 10 秒、executable identity 24 小时。策略必须写入 snapshot，且不能超过
   Bundle 的整体有效窗口；静态声明不伪造 freshness。

### 验收与回滚

- 验收：`python scripts/check_docs.py`、`python -m compileall src tests`、基线测试命令可执行；
- 依赖缺失时记录为 `BLOCKED`，不得以静态检查替代测试通过；
- 回滚：仅回滚新增文档/契约，不触碰现有 v2 artifact。

## 4. RKB-1：Evidence Envelope 与兼容读取

### 实现范围

新增 `src/rolo/rkb/`，首版只包含：

- `models.py`：`SnapshotIdentity`、`EvidenceEnvelope`、`Fact`、`Snapshot`；
- `canonical.py`：canonical JSON、payload digest 和 JSON Pointer；
- `migration.py`：`TargetEvidenceBundle`/`ProbeResult` 到 RKB snapshot 的只读迁移；
- `validation.py`：identity、digest、freshness、source kind 和 access 校验；
- `schemas/RobotEvidenceEnvelope.schema.json` 与 `schemas/RobotKnowledgeBase.schema.json`。

`ProbeResult` 先增加可选、版本化的 envelope 读取入口，不立即删除 `data`。所有新 query 只读
envelope；旧调用继续读取旧字段，直到 RKB-4 完成迁移。

### 最小字段

```text
SnapshotIdentity:
  robot_id, target_host_fingerprint, collector_id, deployment_mode,
  access, request_nonce, observed_at, fresh_until

EvidenceEnvelope:
  fact_id, identity, source_kind, source_ref, sha256,
  confidence, limitations, value
```

### 测试

- 正向：合法 Bundle 生成 snapshot，digest 可重复，JSON Pointer 可定位原始事实；
- 负向：robot/fingerprint/collector/nonce 不一致、未来时间、过期 freshness、payload digest
  或 HMAC 错误全部拒绝；
- 边界：旧 v2/v3 Bundle、缺 optional 字段、`UNKNOWN`/`UNAVAILABLE` Probe 保留原状态；
- 安全：secret 不进入 envelope、原始大 payload 不进入 startup context。

### Exit Gate

单个 snapshot 不依赖外层上下文即可回答“属于哪个目标、由谁采集、何时观测、何时失效、来自
哪个 artifact”；旧 EvidenceBundle 和 DiscoveryReport 仍可读取，且没有新增成功语义。

## 5. RKB-2：分层只读模型与 typed query

### 5.1 分层顺序

按风险和当前证据成熟度实施：

1. `identity`：直接投影 RKB-1 envelope；
2. `os_runtime`、`hardware`：复用现有 Probe 输出，补充稳定 resource identity 和来源；
3. `middleware`：先做 endpoint/relationship schema，缺 QoS/GUID 时保留 limitation；
4. `application`：区分 source/static、target observed 和 Rolo verified；
5. `capabilities`：只读状态投影，不增加新的写 Operation；
6. `state_safety`：只记录目标已观察字段，未采集字段为 `UNKNOWN`，不推断安全停止。

### 5.2 必须实现的规则

- hardware resource 优先使用 serial、USB topology、I2C/CAN 地址、udev by-id 或 Provider ID；
  只有路径时标记 `UNSTABLE`，不得绑定长期能力；
- ROS Domain ID/RMW 未观察时输出结构化 `UNKNOWN`，不填充隐含默认值；
- ROS route 分离 endpoint 与 relationship，至少保留 role、node、interface、schema、provider、
  runtime revision、observed_at、fresh_until 和 stability；
- source/static 只能产生 `DISCOVERED_UNVERIFIED`，不能单独产生 `ELIGIBLE` 或 `VERIFIED`；
- capability 状态唯一来源为 `CapabilityRecord`：
  `DISCOVERED_UNVERIFIED → ELIGIBLE → VERIFIED`，失败为 `UNAVAILABLE`，TTL/fingerprint 变化为
  `STALE`；
- 每个 query 返回 `evidence_ids`、`observed_at`、`fresh_until`、`limitations` 和状态原因。

### 5.3 Query 首批接口

```text
robot.identity()
os.runtime.status()
hw.inventory.scan()
middleware.graph.snapshot(selector)
middleware.route.inspect(route_id)
app.executable.inspect(executable_id)
capability.get(operation_id)
state_safety.snapshot()
```

所有接口只接受已验证的 snapshot reference，并在 fingerprint 不匹配、freshness 过期或请求
未授权时拒绝读取。startup context 只包含 identity、runtime/graph 摘要、capability blockers 和
显式 UNKNOWN，不返回原始 bundle。

### 测试与 Exit Gate

- 同名不同 executable hash、不同 shebang/interpreter、source-only 和 help-only 场景；
- 多 publisher/subscriber、缺 QoS/schema/provider、graph 不稳定和 CLI 受限场景；
- stale、fingerprint mismatch、UNKNOWN safety、缺 route 不得被转换为成功；
- query 分页/排序稳定，所有派生字段保留输入 evidence IDs。

Exit Gate：离线 fixture 能完成“Bundle → RKB → typed query → 兼容 DiscoveryReport”闭环，且
所有拒绝路径有测试。

## 6. RKB-3：MHS 只读兼容层

### 设计边界

MHS 首版只交付 manifest、inspect、status、read 四类只读能力。设备统一描述
`device_id/device_class/vendor/model/serial/transport/resources/state/limits/driver`；
sensor、controller、actuator 等只是 capability 组合，不为每类设备复制 RKB identity。

原型代码保留在 `examples/mhs-sensor/`，先改造成只依赖 Rolo-owned adapter interface 的
示例；它不进入生产包，直到 Provider SPI、RKB envelope 和测试被纳入基线。

### 证据与限制

- manifest 属于 `DECLARED/PROVIDER`；driver probe/status/read 属于目标 `OBSERVED`；
- 每次结果必须带 target identity、manifest/driver digest、canonical route、时间、freshness、
  fact IDs 和 limitations；
- channel 的 measurement validity 不等同于 actuator operating limit、hard stop 或
  authorization limit；本阶段只保存读数约束，不授予物理安全结论；
- Provider 注册、manifest 解析或单次 read 成功都不能直接进入 `VERIFIED` 或 release。

### 测试与灰度

1. fake backend：未知 channel、类型错误、NaN/Infinity、越界、异常和超时；
2. contract：manifest digest 漂移、driver digest 漂移、canonical route、重复 device ID；
3. policy：无 authorizer 的任何写入口必须不存在或明确拒绝；
4. 迁移：旧 sensor route 可读但新输出只使用 canonical route；
5. canary：固定目标机只读 inspect/status/read，失败自动撤销 MHS read-model latest 指针。

### Exit Gate

Provider SPI、RKB provenance 和测试均进入 CI；示例测试迁入 `tests/` 或由独立 CI job 显式
收集；目标机只读 canary 有完整 artifact 和回滚记录。写能力不因本阶段通过而开放。

## 7. RKB-4：Episode 元数据、双读一写与灰度迁移

### 实施内容

- 每次 Probe run 创建 metadata-only Episode，记录 bundle/report/snapshot/digest 引用；
- 仅记录 baseline、observation、hypothesis、change、smoke_test、decision/rollback 的事件
  元数据，不实现完整 Diagnose/Certify 业务；
- 采用“双读一写”：旧 bundle/report 可读，新 RKB artifact 为唯一新写入格式；
- latest index 只原子指向完整、校验通过的新 snapshot；失败保留上一版本；
- 将 native tool、application route 和现有 fingerprint 读取逐步切换到 typed query；
- 用一台固定目标机执行 identity → runtime → graph → app CLI 的只读 smoke，再决定扩大平台。

### Exit Gate

旧 fixture/bundle/release 可读；新旧路径的 robot identity 和 fingerprint 一致；Episode 能从
Probe run 定位到 evidence 和 rollback；startup context 不包含 secret 或大 payload；工程状态台账
记录证据等级，没有把设计状态改成 STABLE。

## 8. 测试、CI 与验收命令

### 依赖前提

开发机必须按仓库 Quickstart 安装 Python 3.10–3.13、uv 和 dev dependencies。当前环境缺少
`pytest`/`uv` 时，只能运行静态检查并记录 `BLOCKED`，不能宣称测试通过。

### 每个 PR 的最小命令

```bash
uv sync --locked --dev
uv run pytest
uv run ruff check .
python scripts/check_docs.py
```

新增 RKB 测试必须使用 `tests/test_rkb_*.py` 命名，以纳入当前 pytest 配置；MHS 示例测试
不得只放在 `examples/` 而不被 CI 收集。

### 统一测试矩阵

| 类别 | 最少覆盖 |
|---|---|
| 身份/完整性 | robot、fingerprint、collector、nonce、payload digest、HMAC |
| 时间 | future、replay window、事实 TTL、snapshot TTL、clock skew |
| 来源 | declared、observed、verified、inferred、decision 的隔离 |
| 运行时 | 目标 PATH、executable hash、interpreter/shebang、Domain/RMW UNKNOWN |
| 图与资源 | ROS 关系、QoS/schema 缺失、设备重排、UNSTABLE resource |
| 能力 | 状态转换、缺证据、STALE、缺 provider 不得 VERIFIED |
| MHS | manifest/driver digest、读数类型/范围、异常、断线、route 迁移 |
| 迁移 | 旧 bundle/report 读取、latest 原子更新、失败回滚 |

## 9. 责任边界、依赖与回滚

| 工作包 | 责任角色 | 前置依赖 | 主要回滚 |
|---|---|---|---|
| RKB-0 | 架构/维护者 | 基线清点、契约决策 | 删除未采用的契约草案 |
| RKB-1 | Core/证据维护者 | RKB-0 schema 与 canonicalization | 停止生成 RKB snapshot，保留旧 Bundle |
| RKB-2 | Probe/Query 维护者 | RKB-1 identity/freshness | 关闭 query 入口，继续旧 report 投影 |
| RKB-3 | Adapter/硬件维护者 | RKB-1 provenance、RKB-2 route | 撤销 MHS latest，仅保留示例原型 |
| RKB-4 | Release/QA 维护者 | 前三阶段 artifact 与 canary | latest 指回上一完整 snapshot |

禁止跨阶段隐式依赖：任何阶段不能直接读取未验证原始 bundle、控制器本地环境或 Agent/Wiki
文本作为事实。所有新 artifact 使用临时文件、fsync（适用时）和原子 replace；写失败不得
破坏既有版本。

## 10. 完成定义（Definition of Done）

阶段只有同时满足以下条件才可标记 `DONE`：

- 有版本化 schema、代码所有权和兼容策略；
- 有一条本地可运行命令，并在 CI 中执行同一入口；
- 有成功、失败和边界测试，拒绝路径优先于成功数量；
- artifact 有 source ref、digest、时间、freshness、限制和回滚记录；
- 文档路径与当前 `src/rolo/stages/probe/` 实现一致；
- 不把静态声明、route 存在、Provider 注册或一次 read 成功升级为物理安全/行为正确；
- 真机能力仍保持只读，所有写能力另有批准的 RFC、授权、取消和补偿方案；
- 结果回写 `docs/reference/ENGINEERING_STATUS.md`，证据等级没有提升不得提升成熟度。

本计划当前状态为 `DRAFT`。在 RKB-0 的契约决策、依赖准备和负向测试入口完成前，不进入
RKB-1 以上的实现排期。
