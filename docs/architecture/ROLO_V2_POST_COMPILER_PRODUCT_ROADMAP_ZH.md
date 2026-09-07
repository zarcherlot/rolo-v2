<!-- status: draft; authority: plan; owner: rolo maintainers; last_reviewed: 2026-09-06; prerequisite: ROLO_V2_DSL_COMPILER_DEVELOPMENT_PLAN_ZH.md G7 -->

# Rolo v2 Compiler 后续产品路线与任务拆解

## 1. 用途和边界

本文是[Rolo DSL Compiler 完成后的互补开发计划](ROLO_V2_DSL_POST_COMPILER_REMAINING_DEVELOPMENT_PLAN_ZH.md)的产品化执行视图：
先定义用户可感知的产品节点，再拆成可并行开发、可单独验收的工程任务。

产品目标不是开发新的机器人能力，而是：

```text
安装 Rolo 后自动执行只读 Bootstrap Probe
  → 建立 Capability Candidate Index
用户提出具体意图
  → Agent 优先查询候选索引
  → 仅在证据不足时执行 bounded Probe
  → Coding Agent 生成 Rolo DSL 映射
  → Compiler 生成 Canonical IR / Bundle Plan
  → targetd 在目标机绑定并验证已有软件能力
  → Conformance 通过后发布 Tool Release
  → Trace 按用户意图消费 Tool
  → Certify 按用户明确指定的测试用例消费同一 Tool
```

Rolo DSL 是已有应用能力的诊断映射和有限组合语言。`EXECUTE` 可以携带专用运行时，但
仍必须映射到目标机已经存在的软件入口；不允许借此创建未经目标软件支持的新机器人功能。

Bootstrap Probe 建立的是“可能支持什么”的候选索引，不是已注册 Tool。只有 Mapping、目标侧
Conformance 和发布门全部通过，能力才进入 `PUBLISHED` Tool Release。

## 2. 当前基线与待办边界

### 2.1 已进入主线的基线

- Compiler standalone 契约、Canonical IR、Bundle Plan、fake backend 和离线 Conformance 已合入主线；
- targetd 的协议、session、DSL stdio、Bundle/Release 和 Trace/Certify 消费代码已有实现切片；
- LanderPi 离线 MVP、release gate、journey session 和单通道 SSH 设计已有实现切片；
- Compiler 与互补层的交接兼容矩阵已开始落地；
- Probe evidence → Compile Context adapter 已启动，覆盖 routes、message schemas、MHS 引用、runtime revision、published tools、freshness 和 limitation，并可写入带 digest/index 的 `compile-context.json`。
- Bootstrap Probe、Capability Candidate Index 和按用户意图触发的增量 Probe 正在纳入产品闭环；

### 2.2 本轮已落地的互补切片

- `AdapterMappingRequest`、`DslRepairLoop` 和 bounded Probe follow-up 已提供 Agent 映射边界；
- `CapabilityCandidateIndex` 已从 observed Context 构建候选、证据引用、freshness、缺口和 Probe 模板，并提供确定性的意图 token 查询；
- `MappingProposal` 已固化候选、证据引用、风险、未知项和显式确认状态，作为发布/执行前的只读展示产物；
- `ContextLayerDigests` 和 `ContextChangeReport` 已固定 target/runtime/surface/evidence 分层变化判定，支持只标记受影响 namespace；
- targetd DSL service 已支持 `PLAN_RESOLVE`、`TARGET_COMPILE`、`TARGET_CONFORMANCE`，并在 PUT/compile 阶段校验 DSL、Context 和 target digest；
- ROS2 runtime snapshot/resolver 只解析运行时观测到的 topic，并提供稳定 runtime digest；
- Release Publisher 已提供 T1～T4 门禁、stale 原因、immutable load/current 和原子 rollback；
- 发布绑定旅程层已把 targetd conformance、immutable Release、Trace、Certify 和 artifact index 串成同一条可回放离线链路；
- JourneyMetric、脱敏 JSONL recorder 和显式 artifact retention policy 已落地，覆盖旅程生命周期、敏感字段保护及 bounded 留存清理；
- MVP HTTP API 已暴露 Release current read model，供 rolo-vis 只读显示状态、digest 和 callable flag；
- `rolo-dsl` CLI、兼容矩阵和 LanderPi ROS2 运行时证据已纳入文档入口。

### 2.3 本路线不重复开发

- 不重新设计 DSL、IR、Bundle Plan、diagnostics 或 Backend SPI；
- 不让 Agent 直接操作 SSH、target shell、targetd 或 Tool Catalog；
- 不把 vendor MHS 改写成 Rolo 自有权威定义；
- 不把 Certify 隐式插入普通 Trace；用户未明确要求测试时，不启动 Certify；
- 不把 Probe 的未知证据填充成已观测事实。

### 2.4 当前尚未形成产品闭环的部分

- 真实 Probe 证据到完整 `rolo-compile-context/v1` 的稳定构建与回放；
- 安装后的 Bootstrap Probe、Capability Candidate Index 的 rolo-vis 展示和现场候选验收；
- 用户意图驱动的证据充分性判断与 bounded Probe 增量闭环，以及现场 proposal 展示；
- Bootstrap Probe 到候选索引的真实目标采集和现场 proposal 展示；
- Agent 通过 `rolo skill` 生成、修复 DSL 并消费 diagnostics 的闭环；
- 真实目标机 runtime/backend 的绑定和 T1～T4 Conformance；
- Trace 的自然语言意图到 Tool 调用、诊断、事件和 Episode evidence 的现场闭环；
- Certify 的显式测试请求到逐用例报告的现场闭环；
- LanderPi 真机上的一次完整 Probe → DSL → Compile → Release → Trace/Certify 旅程。

## 3. 产品大里程碑

| 产品节点 | 用户可感知结果 | 完成门 | 依赖 |
|---|---|---|---|
| P0 Contract Handoff | 所有组件使用同一套 Compiler 资产和版本规则 | 兼容矩阵、schema、digest、diagnostics 契约测试通过 | Compiler G7 |
| P1 Bootstrap/Candidate Ready | 安装 Rolo 后立即看到目标机可能支持的能力 | Bootstrap 只读完成；候选有证据、freshness、置信度和缺口；未观测能力不会进入 observed 集合 | P0 |
| P2 Intent-driven Mapping Ready | Codex 优先消费候选索引，仅在必要时补探测并生成 DSL | 证据充分时零额外 Probe；不足时 bounded Probe 可回放；达到上限会 BLOCKED | P0、P1 |
| P3 Target Compile Ready | targetd 能把 Bundle Plan 绑定为目标机可执行 Tool | 真实目标 runtime 解析、T1～T4 通过，业务工作区无写入 | P0、P2 |
| P4 Tool Release Ready | 通过门禁的映射自动成为可消费的 Tool Release | immutable release、原子 current、stale、rollback 完成 | P3 |
| P5 Trace Ready | 用户用一句意图完成一个已有能力任务并获得诊断证据 | Trace 只消费 PUBLISHED release，支持事件流、取消、有限重试 | P4 |
| P6 Certify Ready | 用户明确指定测试套件后得到逐用例报告 | expected/actual/status/evidence 全量可追溯 | P4 |
| P7 LanderPi MVP | 现场完成一次完整 Agent 用户旅程 | 真机完成 Probe→Trace；同一 release 可选执行 Certify | P1～P6 |
| P8 Field Release | 可重复安装、升级、回放和故障恢复 | CI、targetd 安装、观测、文档和现场 runbook 完整 | P7 |

P1、P2 的契约和离线任务可以并行；P3 需要 P2 的 Bundle Plan；P5、P6 在 P4 后并行；
P7 是首次端到端集成门；P8 不得提前承诺为真机能力已完成。

### 3.1 Bootstrap 与增量探测模型

安装 Rolo 并绑定目标机后，系统创建逻辑上的 `discovery_session`（可在用户提出意图时
升级为 `journey_session`），执行一次受限、只读的 Bootstrap Probe。Bootstrap 的目标是
建立候选索引，不是穷举所有应用，也不直接生成 DSL。

Bootstrap 至少采集：

- 目标 identity、OS/架构、runtime 和软件包/服务快照；
- ROS/Middleware 的 topic、service、action、参数和消息类型；
- vendor MHS manifest 或 MHS ID 的原始引用和 digest；
- 已存在的 CLI/API/socket/RPC 入口；
- route、schema、来源、采集时间、freshness、warning、UNKNOWN 和 limitation。

候选索引条目必须至少包含：

```text
candidate_id
intent_tags / possible_operations
observed_resources / mhs_refs
evidence_refs / context_digest
confidence
freshness
missing_evidence
bounded_probe_templates
```

用户提出意图时，Agent 先执行 `Candidate Index → evidence sufficiency` 判断：

```text
证据充分 → 直接生成 Mapping DSL
证据不足 → 生成结构化 bounded Probe Request → Rolo 执行 → 更新 Context/Index → 生成 DSL
```

Agent 只能引用已注册 Probe 模板，不能自由 SSH、自由 shell 或自行扩展采集范围。Probe
请求受轮数、时间、artifact 数量和目标 scope 限制。

### 3.2 新软件安装后的增量失效

不要只用单一 target fingerprint 判断环境变化，至少维护：

| 指纹 | 含义 |
|---|---|
| `target_identity_digest` | 目标身份，通常稳定 |
| `runtime_snapshot_digest` | OS、软件包、服务和运行时版本 |
| `surface_digest` | route、topic、service、action、MHS、schema |
| `evidence_digest` | 当前 Probe 证据集合 |

新软件安装后，先比较 snapshot/surface digest 并标记受影响的 capability namespace 为
`DIRTY`，不立即重探所有能力。下次用户提出相关意图时，仅执行该 namespace 的增量 Probe。
旧 Release 仍保留：无关能力继续 `current`，受影响能力标记 `STALE`，新 Mapping 通过
Conformance 后再原子切换 `current`。

## 4. 里程碑任务拆解

### P0 — Contract Handoff

| 任务 | 开发内容 | 产物 | 验收 |
|---|---|---|---|
| P0-T1 | 固定 DSL/Context/IR/Plan/Result schema 版本 | compatibility matrix、schema manifest | 版本不匹配统一返回 `BLOCKED` |
| P0-T2 | 统一 canonical bytes、digest 输入和排序 | digest fixture | YAML/JSON、字段重排产生相同 digest |
| P0-T3 | 固定 diagnostics catalog 与 Agent 可消费格式 | diagnostics fixture | code/path/severity 稳定且可回放 |
| P0-T4 | 固定 backend capability negotiation | capability matrix | 缺失 backend 不生成 COMPILED |
| P0-T5 | 建立跨组件 contract CI | contract test job | Compiler、adapter、targetd 共享同一 fixture |

### P1 — Bootstrap / Candidate Ready

| 任务 | 开发内容 | 产物 | 验收 |
|---|---|---|---|
| P1-T1 | 将 TargetEvidenceBundle 投影为 Compile Context | context builder/adapter | robot、target fingerprint、observed_at 正确绑定 |
| P1-T2 | 规范化 route、resource、message schema 和 schema digest | normalized resource model | 只复制 Probe 实际观测记录 |
| P1-T3 | 接入 vendor MHS manifest 引用与 digest | MHS reference projection | 只引用原始 manifest，不生成 vendor 定义 |
| P1-T4 | 保留 freshness、UNKNOWN、warning、error、limitation | limitation model | 信息不完整时可解释，不静默补全 |
| P1-T5 | 增加 context canonicalization、签名和 artifact index | `compile-context.json`、index | 同一证据重复构建得到同一 context digest |
| P1-T6 | 实现 Bootstrap Probe profile 和 discovery session | bootstrap evidence bundle | 安装/绑定目标后可自动执行一次只读探测 |
| P1-T7 | 建立 Capability Candidate Index | candidate index/read model | 每个候选含证据、置信度、freshness、缺口和 Probe 模板 |
| P1-T8 | 实现 runtime/surface/evidence 分层 digest | snapshot evaluator | 新软件变化只标记受影响 namespace 为 `DIRTY` |
| P1-T9 | 实现 bounded Probe follow-up 请求 | follow-up request/receipt | Agent 只能请求已定义采集项，不能自由扩展 shell |
| P1-T10 | 建立离线 replay 和真实 LanderPi fixture | replay bundle | 断网可重建 Context/Index 并复核全部 digest |

### P2 — Intent-driven Agent Mapping Ready

| 任务 | 开发内容 | 产物 | 验收 |
|---|---|---|---|
| P2-T1 | 完成 `rolo skill` 安装、profile/preflight、targetd bootstrap 规则 | skill/runbook | Codex 能按 skill 初始化本地 Rolo 和目标 targetd |
| P2-T2 | 建立用户意图 → Candidate Index 查询器 | intent/candidate resolver | “完成建图”优先命中候选，不默认全量 Probe |
| P2-T3 | 实现证据充分性判断和缺口解释 | sufficiency report | 明确可直接 Mapping、需要补证据或无法支持 |
| P2-T4 | 建立 Probe Context → Mapping Request context builder | request envelope | Agent 收到用户意图、Context digest、Tool candidates |
| P2-T5 | 设计四类 Operation 的 DSL 生成提示模板 | prompt fixtures | OBSERVE/COMPOSE/INVOKE/EXECUTE 均输出合法 DSL |
| P2-T6 | 实现 compile diagnostics 消费与修复循环 | repair loop | DSL 错误自动修复；Context 缺失转 bounded Probe 请求 |
| P2-T7 | 实现 proposal、证据引用和用户确认展示 | proposal artifact/UI payload | 用户能看到映射、证据、风险、未知项和待确认动作 |
| P2-T8 | 加入循环上限、时间上限、artifact 上限和 BLOCKED 状态 | harness policy | 超限不发布、不降级为未验证 Tool |
| P2-T9 | 固定 Agent 不可越权边界 | negative fixtures | Agent 不直接 SSH、不改 Context、不直接发布 |

### P3 — Target Compile Ready

| 任务 | 开发内容 | 产物 | 验收 |
|---|---|---|---|
| P3-T1 | session bootstrap 建立并复用一条 SSH stdio 通道 | session transport | Probe/Trace/Certify 在一个 journey session 内复用通道 |
| P3-T2 | targetd 接收 DSL/IR/Bundle Plan 并按 digest 缓存 | typed frames、cache | 重复请求幂等；断线可用 session_id + idempotency_key 恢复 |
| P3-T3 | 实现目标 runtime/provider resolver | target backend adapters | 只解析目标已有软件入口和 vendor MHS |
| P3-T4 | OBSERVE/COMPOSE/INVOKE 目标绑定 | runtime bundle | 生成目标绑定 Bundle，不写业务工作区 |
| P3-T5 | EXECUTE source bundle loader 和 implementation contract | runtime loader | 仅加载声明、签名、版本匹配的专用运行时 |
| P3-T6 | 实现 T1～T4 target conformance | conformance report | 任一失败不产生 PUBLISHED release |
| P3-T7 | 加入 cancel、stop、lease、UNKNOWN 和故障恢复 | receipts/events | 长任务可取消，结果状态可追溯 |

### P4 — Tool Release Ready

| 任务 | 开发内容 | 产物 | 验收 |
|---|---|---|---|
| P4-T1 | 生成 immutable Tool Release manifest | release manifest | 包含 DSL/Context/IR/Bundle/compiler/target digest |
| P4-T2 | 实现 Tool Catalog current 原子更新 | catalog API/read model | 发布成功才替换 current，失败保留旧版本 |
| P4-T3 | 实现 stale/dirty 判定 | stale evaluator | runtime/surface/evidence 变化标记受影响 Release stale，未受影响能力保持 current |
| P4-T4 | 实现 rollback 和 release pinning | rollback API | 可恢复到已知良好 release，禁止隐式跨 target 使用 |
| P4-T5 | 发布 rolo-vis 可消费 read model | release/read API | UI 可展示证据、编译、Conformance、Release 关联 |
| P4-T6 | 将 Candidate、Mapping、Release 关联到同一 artifact index | lifecycle read model | UI 可追溯候选→补探测→DSL→Release 的完整链路 |

### P5 — Trace Ready

| 任务 | 开发内容 | 产物 | 验收 |
|---|---|---|---|
| P5-T1 | 用户意图解析为 Trace plan | intent/plan schema | “调用已注册工具完成建图，遇到问题自行诊断”可落到已发布 Tool |
| P5-T2 | Tool invocation、事件流和结果模型 | invoke/event API | 每次调用带 release digest、session_id、idempotency_key |
| P5-T3 | Agent 自主诊断循环 | diagnosis evidence、retry plan | 只在已注册 Tool 和边界内重试/调整；不得创造新能力 |
| P5-T4 | 长任务取消、断线恢复和 UNKNOWN 处理 | resume/cancel flow | 连接断开后可恢复或明确返回 UNKNOWN |
| P5-T5 | Episode/evidence artifact 归档 | episode index | 用户可复核计划、调用、事件、诊断和最终结果 |

### P6 — Certify Ready

| 任务 | 开发内容 | 产物 | 验收 |
|---|---|---|---|
| P6-T1 | 测试套件 schema、路径输入和报告输出配置 | test suite contract | 支持用户指定 10 条用例和报告目录 |
| P6-T2 | 逐用例加载同一 Tool Release | certify runner | 每例记录 release、Context 和 target digest |
| P6-T3 | expected/actual/status/evidence 比较 | case result schema | PASS/FAIL/BLOCKED/NOT_RUN 语义固定 |
| P6-T4 | 事件流、取消、失败继续策略 | run control API | 用户可选择失败即停或继续，默认不隐式 Trace |
| P6-T5 | 生成报告、artifact index 和回归结论 | HTML/JSON/Markdown report | 报告可离线复核且不覆盖历史结果 |

### P7 — LanderPi MVP

| 任务 | 开发内容 | 产物 | 验收 |
|---|---|---|---|
| P7-T1 | Codex 加载 skill、安装本地 Rolo 和 targetd | bootstrap transcript | 全过程不让 Agent 直接操作 SSH |
| P7-T2 | 创建 discovery session 并执行 Bootstrap Probe | bootstrap evidence/index | 安装后 UI 立即展示目标机候选能力 |
| P7-T3 | 用户提出“完成建图”，Agent 查询 Candidate Index | intent/proposal artifact | 证据充分时不执行无关 Probe |
| P7-T4 | 证据不足时执行 mapping namespace 的 bounded Probe | delta evidence/Context revision | 只补采集缺口，不能全量重探或自由 shell |
| P7-T5 | Agent 生成建图 DSL，Compiler/targetd 生成 Bundle | mapping/release artifacts | 用户确认前不发布、不执行写操作 |
| P7-T6 | Conformance 通过后自动发布 mapping Tool | release/catalog | Tool 在 Catalog 中可读取、可 pin、可 stale |
| P7-T7 | Trace 执行建图并自行诊断 | trace episode | 现场完成一次建图或给出可解释失败 |
| P7-T8 | 用户明确要求时执行 Certify 十条用例 | certify report | 同一 session/release 可产生逐例报告 |
| P7-T9 | 端到端回放和人工验收 | journey acceptance pack | 可从 artifact index 复核 Bootstrap→Candidate→Probe→DSL→Release→Trace/Certify |

### P8 — Field Release

| 任务 | 开发内容 | 产物 | 验收 |
|---|---|---|---|
| P8-T1 | targetd 安装、升级、health、卸载和版本兼容 | installer/runbook | 新目标机可重复 bootstrap，失败可恢复 |
| P8-T2 | CI 矩阵、离线 replay、fake target、LanderPi canary | release gate | PR、夜间回放和真机门禁分层执行 |
| P8-T3 | 观测指标、日志脱敏、artifact retention | observability contract | 可定位 session、compile、release、trace、certify 故障 |
| P8-T4 | 现场 runbook 和故障分类 | operator guide | 工程师能区分 Context 缺失、映射失败、目标编译失败、运行失败 |
| P8-T5 | 版本发布和兼容窗口 | release notes、compatibility policy | 旧 Release 行为和升级/回滚策略明确 |

## 5. 最大并行开发组织

```text
P0 Contract
 ├─ W1 Bootstrap/Context/Candidate (P1)
 ├─ W2 Agent Skill/Intent/Mapping (P2，依赖 P0，可用 fixture 先行)
 ├─ W3 targetd Transport/Runtime (P3，依赖 P0)
 └─ W4 Release/Read Model (P4 skeleton，依赖 P0)

P1 Bootstrap + P2 Intent Mapping ──> P3 Target Compile ──> P4 Release
                                      ├─> P5 Trace
                                      └─> P6 Certify
P1～P6 ───────────────────────────────> P7 LanderPi MVP ──> P8 Field Release
```

并行规则：

- W1 先冻结 Bootstrap、Candidate、Context fixture，W2、W3 使用 fake Context/target 并行开发；
- W4 可以先实现 release/read model 和 stale/rollback 状态机，等待真实 Bundle；
- Candidate Index、Mapping Proposal 和 Tool Release 必须使用不同状态，不能把候选直接当作可调用 Tool；
- P5、P6 不修改 Compiler 或 targetd DSL 语义，只消费 P4 的 published release；
- P7 只在 P5 和 P6 的离线 replay 通过后占用 LanderPi；
- 真机失败不得通过修改 fixture 掩盖，必须回写真实 evidence 和 failure artifact。
- 观测指标和留存策略已有离线契约，但现场指标采集与 acceptance pack 仍待接入真实 LanderPi 旅程。

## 6. 统一完成定义

某个产品节点只有同时满足以下条件才算完成：

1. 代码、schema、CLI/API、artifact 和文档齐备；
2. 至少有成功、缺失证据、digest 漂移、目标不匹配和中断恢复用例；
3. 可在 fake target 离线重放，且结果 digest 稳定；
4. 用户可从 rolo-vis 或结构化 read model 看到该节点的输入、状态、证据和失败原因；
5. 不改变 Compiler 契约，不写机器人业务工作区，不允许 Agent 越权；
6. Candidate、Mapping Proposal、Tool Release 的状态和权限边界清晰可验证；
7. 完成门禁记录进入 CI 或 LanderPi acceptance pack。

## 7. 推荐交付顺序

当前最短可交付路径是：

```text
P0-T1～T5
  → P1-T1～T8 + P2-T1～T4 + P3-T1～T2 并行
  → P2-T5～T9
  → P3-T3～T6
  → P4-T1～T6
  → P5-T1～T5 与 P6-T1～T5 并行
  → P7-T1～T9
  → P8-T1～T5
```

第一产品演示应选择“安装 Rolo → Bootstrap Probe → UI 展示候选 → 用户提出完成建图 →
候选索引命中或只补一次 bounded Probe → Mapping → Conformance → Trace 建图”的旅程。
Certify 作为同一 Tool Release 的第二条显式用户路径验收，不应阻塞第一条 Trace 演示，但
必须在 P7 结束前完成。
