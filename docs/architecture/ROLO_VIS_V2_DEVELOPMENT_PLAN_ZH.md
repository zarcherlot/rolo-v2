<!-- status: active; authority: guide; owner: rolo-vis-v2 team; last_reviewed: 2026-09-06 -->

# rolo-vis-v2 开发交接计划

本文供 rolo-vis-v2 团队直接实施。目标是为 Rolo v2 的 Bootstrap Probe、Candidate、Mapping、
Tool Release、Trace 和 Certify 提供只读观测面，当前 MVP 场景为 LanderPi 底盘旋转。UI 展示
状态、事件、证据和报告，不拥有写权限，也不绕过 Rolo API 调用目标机。

## 修订版实施基线

本计划采用垂直切片推进，先冻结契约，再逐步开放信息路径。rolo-vis-v2 的一级体验以用户
能否使用能力、查看方案、跟踪任务和追溯证据为中心；Agent Harness 仍是任务交互和所有有
影响动作的入口，rolo-vis-v2 是独立打开的全局只读视图。

实施顺序固定为：

1. 冻结 Bootstrap、Candidate、Probe run、Mapping、Release、Evidence 的 schema、fixture、
   错误模型和 digest 身份规则；
2. 完成 Capabilities、Tools、Evidence、Tasks、Certify、Artifact 主路径；
3. 接入 Bootstrap / Candidate / bounded Probe 的只读详情；
4. 接入 Mapping / Release lineage 以及 DIRTY / STALE 生命周期；
5. 通过离线 LanderPi journey replay 后，再进行真机联调。

九类信息视图仍然保留，但 Bootstrap、Candidate、bounded Probe、Mapping 和 Release 以详情
或上下文入口出现，不作为一级导航。技术 contract ID、operation ID、schema、digest 保持
canonical；用户文案支持中文和英文切换。所有能力、方案、Trace event 和 Certify case 都
必须提供可点击的 Evidence 引用；引用指向清理后的公共 read model，不打开原始文件或主机路径。

fixture 只允许在显式 `artifact` 或 `demo` 模式出现。真实 API 失败时不得静默伪装成成功；
artifact 必须显示来源批次、时间、digest 和 provisional 状态，demo 必须明确标注为演示数据。

## 产品边界

调用方向固定为：

```text
用户 / Agent Harness → Rolo API → rolo-vis-v2 只读视图
```

rolo-vis-v2 不执行 Shell、SSH、ROS topic、任意 argv 或未注册 Tool。所有执行动作由 Rolo 的
Trace session、Tool registration、binding、参数边界、超时、停止/取消和审计机制决定。

产品主链为：

```text
安装 Rolo / 绑定目标
  → Bootstrap Probe
  → Capability Candidate Index
  → 用户提出意图
  → Agent 查询候选
  ├─ 证据充分 → Mapping Proposal
  └─ 证据不足 → bounded Probe → 更新 Candidate/Context
  → Compiler / targetd / Conformance
  → immutable Tool Release
  → Trace / Certify 消费
```

rolo-vis-v2 必须区分三类对象：

| 对象 | UI 含义 | 是否可执行 |
|---|---|---|
| `CapabilityCandidate` | Probe 发现目标机可能支持的能力 | 不可执行 |
| `MappingProposal` | Agent 根据证据生成的 DSL 映射建议 | 不可执行 |
| `ToolRelease` | 编译、目标绑定和 Conformance 通过后的正式 Tool | 仅可被 Agent 的 Trace/Certify 消费 |

当前产品口径：

- Bootstrap Probe 负责目标身份、证据、Tool Surface 和 Capability Candidate Index；
- bounded Probe 只补采集当前用户意图所缺少的证据；
- Agent Harness 负责查询 Candidate、生成 Mapping Proposal 和消费 diagnostics；
- Trace 负责已注册 Tool 的任务执行、事件流、诊断和结果 artifact。
- Certify 负责固定测试套件、逐例 expected/actual、报告和 artifact digest。
- 当前真机 MVP 是旋转；10 条真机 Certify、真机恢复和非 ROS 实机 provider 暂延期。
- MHS 只是可选上下文来源，不是 UI 执行入口，也不定义 `app.base.rotate` 语义。
- 目标连接使用普通 SSH profile；UI 不显示、不管理 SSH key 或 Probe runner credential。
- 新软件安装后，UI 展示 runtime/surface/evidence digest 变化及受影响 namespace 的 `DIRTY`/
  `STALE` 状态，不把变化直接伪装成新 Tool。

## 已有后端接口

Rolo loopback API 的基础目录接口：

```http
GET /v1/features
GET /v1/robots
GET /v1/robots/{robot_id}/tools
GET /v1/robots/{robot_id}/rkb
GET /v1/robots/{robot_id}/mhs
GET /v1/robots/{robot_id}/episodes
GET /v1/robots/{robot_id}/bootstrap
GET /v1/robots/{robot_id}/discovery-sessions
GET /v1/robots/{robot_id}/candidates
GET /v1/robots/{robot_id}/candidates/{candidate_id}
GET /v1/robots/{robot_id}/probe-runs
GET /v1/robots/{robot_id}/mappings
GET /v1/robots/{robot_id}/mappings/{mapping_id}
GET /v1/robots/{robot_id}/releases
GET /v1/robots/{robot_id}/lifecycle
```

新增 read model 的统一响应至少包含：

```json
{
  "schema_version": "rolo-vis-read-model/v1",
  "target_id": "landerpi",
  "snapshot_digest": "0123456789abcdef...",
  "items": [],
  "next_cursor": null,
  "limitations": []
}
```

统一响应不能替代各对象的具体 schema。Bootstrap、CapabilityCandidate、ProbeRun、MappingProposal、
ToolRelease 和 EvidenceRecord 必须分别冻结字段、状态枚举、终态、producer、revision、
evidence_ids、limitations、target fingerprint 和 digest 引用。所有对象必须能回指上游对象及
其 digest，缺失 lineage 时只能显示为 UNKNOWN 或 BLOCKED。

错误响应统一为 `error_code`、`message`、`status`、`target_id`、`session_id`、`snapshot_digest`、
`reference_hint` 和 `limitations`，并规定 404、409、`*_BLOCKED`、`*_STALE`、`*_UNAVAILABLE`
的映射。分页必须规定 cursor、上限、排序字段和重复读取行为；未知字段保留，未知状态降级为
`UNKNOWN`。

接口必须支持分页、状态过滤、target/session/digest 隔离和未知字段保留。rolo-vis-v2 不新增
执行类 API；所有 Probe、Mapping、Compile、Release、Trace 和 Certify 动作仍由 Agent/Rolo
调用方发起。

当前 MVP Trace 接口：

```http
POST /v1/mvp/trace/sessions
POST /v1/mvp/trace/sessions/{session_id}/execute?target_id={target_id}
GET  /v1/mvp/trace/sessions/{session_id}?target_id={target_id}
GET  /v1/mvp/trace/sessions/{session_id}/events?target_id={target_id}
POST /v1/mvp/trace/sessions/{session_id}/cancel?target_id={target_id}
POST /v1/mvp/trace/sessions/{session_id}/stop?target_id={target_id}
GET  /v1/mvp/runs/{run_id}?target_id={target_id}
```

Trace 创建请求必须携带 `target_id`、`catalog_digest`、`task`、`mode`、`ttl_s` 和 `max_calls`。
`SUPERVISED_FIELD_DEBUG` 还必须有 `safety_confirmed=true`。UI 只提交用户已经明确提供的值，
不得自行补全安全确认或扩大 TTL/预算。

## 页面与组件

页面按信息优先级组织，而不是按后端对象数量平铺。一级导航只承载 Capabilities、Plan、Tasks、
Tools、Evidence、Certify 和 Artifact；Bootstrap、Candidate、bounded Probe、Mapping、Release
以详情页、侧栏或上下文入口出现。页面必须面向用户目标解释状态，技术字段只作为可展开的证据和
契约详情，不能复制 Agent Harness 的任务时间线和控制入口。

### 1. Target overview

展示：

- `robot_id`、目标 fingerprint、Probe snapshot digest；
- `discovery_session_id`、Bootstrap Probe 状态和最近一次 Bootstrap 时间；
- `target_identity_digest`、`runtime_snapshot_digest`、`surface_digest`、`evidence_digest`；
- Candidate 数量及 `FRESH`、`DIRTY`、`STALE`、`UNKNOWN` 数量；
- catalog freshness：`fresh`、`stale`、`unknown`；
- 最近一次 Probe 时间和限制说明；
- Tool、RKB、MHS 数量及各自 evidence 状态。

交互：点击 Candidate、Tool 或 evidence 进入详情；不提供执行按钮。

### 2. Bootstrap / Discovery view

展示安装 Rolo 或绑定目标后自动创建的 discovery session：

- Bootstrap Probe 当前阶段和已完成采集项；
- warning、UNKNOWN、limitation 和失败原因；
- Candidate Index 构建状态；
- Bootstrap artifact、Context digest 和 snapshot digest；
- 是否已经可以进入用户意图驱动的增量流程。

Bootstrap 页面只展示只读状态，不执行 SSH、Shell 或 ROS 查询。

### 3. Capability Explorer

每个 `CapabilityCandidate` 展示：

- `candidate_id`、intent tags 和可能的 normalized operations；
- observed route/resource、MHS refs、evidence refs；
- confidence、freshness 和 Candidate 状态；
- missing evidence；
- 可用的 bounded Probe templates；
- 关联 Mapping Proposal 和 Tool Release。

Candidate 卡片必须明确显示“可能支持”或“证据不足”，不能显示“执行”“调用”按钮。

### 4. Bounded Probe view

展示 Agent 针对用户意图提出的结构化补探测请求：

- 原始用户意图和命中的 Candidate；
- 已有证据、缺失证据和 Probe scope；
- Probe template、最大轮数、时间上限和 artifact 上限；
- 状态：`PROPOSED`、`APPROVED`、`RUNNING`、`COMPLETED`、`BLOCKED`、`FAILED`；
- 新增 evidence、Context revision 和更新后的 Candidate 状态。

UI 不扩大 Probe scope、不编辑 Probe 命令、不执行自由 shell。

### 5. Tool catalog

每个 Tool 卡片展示：

- `tool_id`、family、access、risk、state；
- descriptor digest、evidence IDs、参数 schema；
- binding provider kind、command endpoint 的脱敏显示；
- 是否 `experimental_write`；
- Candidate ID、Mapping ID、Release ID 及 lineage；
- DSL、IR、Bundle、Context、target fingerprint digest；
- `CURRENT`、`STALE`、`PINNED`、`ROLLED_BACK` 状态和 stale 原因；
- limitations。

写 Tool 只能显示“需要 Trace supervised field debug”，不得在 Tool 卡片直接触发动作。

### 6. Mapping proposal view

展示从 Candidate 到 Tool Release 的映射链路：

- 用户意图和命中的 Candidate；
- evidence sufficiency 结果及 bounded Probe 记录；
- target/tool/evidence identity；
- DSL、Context、IR、Bundle digest；
- Compiler diagnostics 和 targetd Conformance 状态；
- proposal 当前状态：`PROPOSED`、`COMPILING`、`CONFORMANCE_FAILED`、`READY_TO_PUBLISH`、
  `PUBLISHED` 或 `BLOCKED`；
- 关联 Release、stale 原因和 Rolo 返回的拒绝原因。

UI 不重新编辑 proposal、不创建未观测 route、不直接发布。需要修改时，由 Agent Harness
重新生成并提交。

### 7. Trace timeline

使用 `/events` 接口按 `sequence` 展示：

- `SESSION_CREATED`、`PLAN_ACCEPTED`；
- `TOOL_CALL` 和经过脱敏的 arguments；
- `TOOL_RESULT`、evidence IDs、错误码；
- 使用的 Tool Release、release digest 和 Candidate/Mapping 来源；
- 是否执行过 bounded Probe 及其 Context revision；
- `DIAGNOSING`、`RECOVERY_ATTEMPT`、`RECOVERY_FAILED`；
- `SESSION_COMPLETED`、`SESSION_CANCELLED`、`SESSION_STOPPED`、`BLOCKED`、`UNKNOWN`。

事件流必须保留原始 sequence，不按前端时间重新排序。敏感字段由后端脱敏后再显示。

### 8. Certify report

当前后端已有离线 `CertificationRunner` 和报告模型。UI 先实现报告读取和展示：

- suite digest、snapshot digest；
- Tool Release、release/context/target digest 和 journey session；
- 每个 case 的 expected、actual、status、failure class；
- operation IDs、evidence IDs、artifact digests；
- 总结论：`PASS`、`CONDITIONAL` 或 `BLOCKED`。

Certify 真机执行入口属于后续后端工作，UI 不得伪造“运行完成”。未找到报告时显示明确的
`CERTIFY_UNAVAILABLE`。

### 9. Artifact detail

展示 artifact index、文件名、sha256、生成时间和关联 run/session。支持复制 artifact ref 和
打开 JSON 内容；不支持前端修改、删除或覆盖 artifact。签名字段存在但无法验证时，状态显示
`SIGNATURE_UNVERIFIED`，不能显示为可信。

## 前端状态模型

前端只允许渲染后端返回的状态，不自行推导成功：

| 后端状态 | UI 颜色/标签 | 可用动作 |
|---|---|---|
| `OBSERVED` / `POSSIBLE` | 候选能力 | 查看 Candidate/evidence |
| `DIRTY` | 环境变化待增量 Probe | 查看受影响 namespace 和限制 |
| `READY` / `CALLABLE` | 可用 | 查看详情 |
| `PROPOSED` / `COMPILING` | 映射处理中 | 查看 Candidate、diagnostics 和进度 |
| `REGISTERED` / `PUBLISHED` / `CURRENT` | 已发布 | 查看 Tool/Trace |
| `STALE` / `UNKNOWN` | 数据不可用 | 查看限制和 stale 原因 |
| `BLOCKED` / `CONFORMANCE_FAILED` | 已阻塞 | 查看错误和证据 |
| `COMPLETED` | 已完成 | 查看 timeline/artifact |
| `CANCELLED` / `STOPPED` | 已停止 | 查看停止事件 |

刷新和断线重连后必须重新读取后端状态。浏览器本地状态不能作为事实来源。

### 状态来源和降级规则

- `live` 只表示当前读取到了目标绑定的真实 Rolo read model；
- `artifact` 表示明确加载的离线、不可变、只读产物快照，必须展示批次、观测时间、digest
  和 provisional 状态；
- `demo` 只用于测试、评审或无目标数据的显式演示入口；
- 网络错误不会自动生成 demo 成功状态。错误、artifact 和 demo 都必须在页面上区分显示；
- 页面切换、刷新和断线重连后，必须重新读取后端并重新校验 target/session/digest 身份。

### 语言和引文

用户主路径默认使用配置语言，并支持中文和英文切换。用户文案可以翻译，operation ID、
schema、状态原文、digest 和 contract ID 保持 canonical。Capabilities、Tools、Evidence、
Plan、Tasks、Certify、Artifact 及其详情弹层必须响应语言切换。

Candidate、Mapping、Tool Release、Trace event 和 Certify case 必须提供 `evidence_ids` 或
明确的无证据状态。Evidence 引用至少展示 authority、observed_at、freshness、reference digest
和 limitations；原始 artifact、主机路径、凭据和未脱敏参数不得由浏览器打开。

## rolo-vis-v2 适配工作流

| 工作流 | 内容 | 依赖 | 主要产物 |
|---|---|---|---|
| V0 | 契约冻结 | Bootstrap、Candidate、Probe run、Mapping、Release、Evidence schema | parser、错误模型、fixture、身份与 digest 规则 |
| V1 | 用户主路径 | 已有 RKB、MHS、Tool、Evidence、MVP Trace/Certify API | Capabilities、Tools、Evidence、Tasks、Certify、Artifact |
| V2 | Bootstrap / Candidate / bounded Probe | Bootstrap、Candidate、Probe run API | 目标准备、候选、缺口和补探测只读详情 |
| V3 | Mapping / Release lineage | Mapping、Compile、Release、lifecycle API | Candidate→DSL→IR→Bundle→Conformance→Release |
| V4 | DIRTY / STALE 生命周期 | digest diff、Release lifecycle API | 受影响 namespace、增量 Probe、pin、rollback 状态 |
| V5 | Trace / Certify 加固 | `/v1/mvp` API 和报告 API | sequence、诊断、终态、脱敏、引文、artifact |
| V6 | LanderPi journey replay | V0～V5 fixture | 离线端到端 acceptance pack |
| V7 | 真机联调 | 真机 Bootstrap、Probe、Release、Trace | 仅在离线 replay 和错误矩阵通过后进行 |

V1～V5 可以使用 fixture 并行；V6 依赖 Release read model；V7 可在 V6 稳定后并行接入；
V8 只在离线 journey replay 通过后进行真机联调。

## 必须实现的交付项

1. Workbench plugin package，复用现有 `/workbench/` host 和 `/rolo-api/*` 同源适配。
2. Target overview、Bootstrap/Discovery、Capability Explorer、Bounded Probe、Mapping proposal、
   Tool catalog、Trace timeline、Certify report、Artifact detail 九个只读视图。
3. API client 对所有响应执行 schema/version 校验；未知字段保留，未知状态降级为 `UNKNOWN`。
4. Candidate、Mapping Proposal、Tool Release 的 lineage 可从 read model 追溯展示。
5. Trace timeline 支持轮询和手动刷新，按 session digest/target ID/release digest 隔离数据。
6. 所有网络错误、404、409、`*_BLOCKED`、`*_STALE` 和 `*_UNAVAILABLE` 都显示结构化 error code、
   limitation 和关联 artifact。
7. 前端测试覆盖 Bootstrap 失败、Candidate 证据不足、bounded Probe、mapping blocked、stale/dirty
   release、Trace failure/recovery、cancel/stop 和空报告。
8. 截图验收覆盖“安装 → Bootstrap → Candidate → bounded Probe（如需要）→ Mapping → Release →
   Trace timeline → Artifact detail”，Certify 作为同一 Release 的显式第二路径。
9. 每个 read model 都有独立 schema parser、版本兼容测试、未知状态降级测试和 target/session/digest
   隔离测试；每个错误码都有 fixture 和结构化错误验收。
10. `live`、`artifact`、`demo` 三类数据源在页面上可区分；网络失败不会被渲染为 demo 成功状态。
11. 语言切换覆盖用户主路径和详情弹层；所有可见结论都能打开对应 Evidence，或明确显示无证据。

## 明确不做

- 不实现 SSH、Probe runner、Rolo runtime 或 ROS 客户端。
- 不在浏览器执行 Harness source，不在浏览器拼接 transport payload。
- 不把 Candidate 当作 Tool，不在 Candidate 卡片提供调用或执行入口。
- 不在 UI 直接启动 Bootstrap、bounded Probe、Compile、Publish、Trace 或 Certify；这些动作由
  Agent/Rolo 调用方发起，UI 只读取状态和结果。
- 不提供“确认后直接旋转”的 UI 按钮；执行仍由 Agent Harness 调用 Rolo。
- 不把 route presence、MHS manifest、Candidate confidence 或 UI 状态升级成 VERIFIED capability。
- 不实现延期的 10-case 真机 Certify、真机恢复和非 ROS 实机 provider。

## 验收标准

- 新目标绑定后，Bootstrap/Discovery 页面能显示一次只读探测的阶段、限制、snapshot digest 和
  Candidate Index 结果。
- Candidate 页面能明确区分 `POSSIBLE`、`OBSERVED`、`DIRTY`、`STALE` 和 `BLOCKED`，候选能力
  不出现执行控件。
- 用户意图命中候选且证据充分时，UI 显示“无需额外 Probe”，并能追踪到 Mapping Proposal。
- 用户意图证据不足时，UI 能展示 bounded Probe 的 scope、模板、上限、状态和新增证据；不能出现
  自由 Shell 或未声明采集项。
- 新软件导致 runtime/surface digest 变化时，UI 只标记受影响 namespace 为 `DIRTY`，不把所有
  Release 误标为 stale；下一次相关意图的增量 Probe 可被追踪。
- Mapping Proposal 能展示 Candidate → DSL → IR → Bundle → Conformance → Release 的完整 lineage。
- 未注册 `app.base.rotate` 时，Tool catalog 显示 `BLOCKED` 或未注册状态，不出现执行控件。
- Trace session 创建后，timeline 能显示完整事件序列和 evidence IDs。
- Trace 被 cancel/stop 后，刷新页面仍显示最终状态和对应事件。
- catalog digest 或 target ID 不匹配时，UI 显示后端 `TRACE_BLOCKED`，不展示旧 session 的数据。
- artifact index 中任一 sha256 不匹配时，UI 显示校验失败，不显示“可信”。
- 所有页面在后端不可用时仍能显示结构化错误，不显示假数据或成功状态。

## 后端依赖与联调顺序

1. 先冻结各 read model schema、错误响应、fixture 和身份/digest 隔离规则，完成 parser 与契约测试。
2. 用已有 RKB、MHS、Tool、Evidence、MVP Trace/Certify fixture 完成用户主路径和语言/引文验收。
3. 接入 Bootstrap、Candidate、bounded Probe read model，完成证据缺口、限制和失败矩阵。
4. 接入 Mapping、Compile、Release、lifecycle read model，验证完整 lineage 和拒绝原因。
5. 接入 runtime/surface digest diff，验证 DIRTY、STALE、增量 Probe、pin 和 rollback 状态。
6. 使用旋转 MVP 的离线旅程 fixture 做“Bootstrap → Candidate → Mapping → Release → Trace”截图验收，
   Certify 作为同一 Release 的显式第二路径。
7. 等离线 replay、错误矩阵和 artifact 签名规则通过后，再进行真机联调；真机 Certify、恢复和非 ROS
   provider 继续保持延期状态。

rolo-vis-v2 的完成只代表 Bootstrap、候选、映射、Release、Trace/Certify 的观测链路可用，不代表
旋转真机 release gate 自动通过，也不代表 UI 获得任何执行权限。
