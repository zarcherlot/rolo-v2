<!-- status: draft; authority: plan; owner: rolo maintainers; last_reviewed: 2026-09-04; source_of_truth: ROLO_V2_PROBE_TRACE_CERTIFY_ZH.md -->

# Rolo v2：LanderPi Agent 用户旅程 MVP 开发计划

本文只补充 LanderPi 的目标特化验收，不重新定义阶段职责或通用用户旅程；后两者以[阶段规范](ROLO_V2_PROBE_TRACE_CERTIFY_ZH.md)为准。
在一台已注册的 LanderPi（当前基线目标为 `mentorpi`）上，
由 Codex 作为调用方，按用户意图独立调用 Probe、Trace 或 Certify。Probe 负责确定性采集、
请求 Codex 分析并形成关联；Trace 负责消费已绑定 Tool/RKB 完成任务；Certify 只在用户明确
要求测试时执行测试并产出报告。三者不是强制流水线。现场 MVP 运行在
`SUPERVISED_FIELD_DEBUG`，安全员和调试工程师在设备周围；这不是无人值守或功能安全认证。

## 1. 当前 main 基线与缺口

以下结论以当前 `origin/main` 的工程台账和代码为准，而不是以历史计划中的目标状态为准。

| 能力 | main 已有能力 | 对本 MVP 的结论 |
|---|---|---|
| Probe enrollment/evidence | `rolo target profile`、`rolo probe`、TargetEvidenceBundle、SSH 目标绑定，E4 | 可直接复用 |
| Native Tool Surface/ToolPlan | 四类只读 surface、allowlist、digest、预算、Conformance，E4 | 需增加“可被 Agent 消费的操作目录”和实验写操作元数据 |
| RKB typed read models | identity、OS、hardware、middleware、application、capability、state/safety snapshot，LanderPi live smoke，E3 | 可作为 Trace/Certify 的事实输入；未知必须保留为 UNKNOWN |
| MHS | generic Linux observer 的 manifest/inspect/status/read SPI，LanderPi canary，E3；当前 `callable=false` | 可消费厂商 MHS Manifest；无厂商 Manifest 时只能标记观察能力，不得伪造写能力 |
| RKB Episode | metadata-only publish/load/rollback/query，LanderPi canary，E4 | 可承载 Trace/Certify 证据索引；不等同于动作结果或安全证明 |
| HTTP/API | `/v1/features`、robots、RKB、MHS、tools、episodes；loopback runtime | 可作为外部 Agent adapter 的第一版接口 |
| Workbench host | `/workbench/`、`/rolo-api/*` 同源适配和插件校验；未挂包时 503 | 需补最小 rolo-vis-v2 前端，作为可选观测面，不做写授权面 |
| Trace/Certify | main 台账明确“不属于本轮交付”；无任务会话、自诊断循环、测试执行器 | MVP 的主要新增范围 |
| LanderPi 底盘旋转 | 当前 application operation 是 route-level candidate，旋转 Tool 由 Probe + Harness 发现、生成并注册 | 必须先用 Probe 观察软件栈，再由 Harness 生成 evidence-bound 旋转 Tool；发现不到则 MVP 进入 BLOCKED，不得硬编码为事实 |

## 2. MVP 用户旅程和完成定义

### 2.1 用户下发的两条典型指令（当前旋转 MVP）

Trace：

> 调用已经注册的 rolo 工具，在当前环境内完成地盘旋转，过程中若遇到系统问题，自行诊断并尝试解决。

Certify：

> 帮我执行地盘旋转的 10 条测试用例，数据路径为 `/opt/rolo/cases/chassis-rotation-10.json`，在
> `/opt/rolo/reports/` 输出测试报告。

### 2.2 Codex 调用流程

```text
工程师在场并确认设备安全
        │
        ▼
Codex 加载 rolo skill
        │
        ▼
用户意图路由：probe / trace / tool-invoke / certify / read
        │
        ├─ probe：Rolo 采集 evidence → Codex 分析 proposal
        │          →（需要时）Codex 请求下一轮受控 Probe → 用户确认关联
        │
        ├─ trace：Codex 读取已绑定 Tool/RKB → 调用 Tool
        │          → 读回 → 自诊断/恢复 → Trace artifact
        │
        └─ certify：Codex 明确触发 → 加载测试套件
                   → 调用 Tool/RKB → 判定 → 报告
                           │
                           ▼
             Episode/evidence/artifact 持久化
                           │
                           ▼
       Agent 对话结果 + rolo-vis-v2 状态/报告视图
```

### 2.3 MVP 完成定义（Release Gate）

1. Codex 能通过 `rolo skill` 完成安装/preflight，并按用户意图调用独立的 Probe、Trace、
   Tool Invoke 或 Certify 入口；Certify 不被隐式触发。
2. Probe 能在 LanderPi 上采集 evidence，并向 Codex 提供结构化 analysis input；Codex 生成的
   association proposal 只能引用真实 evidence，补充探测受 budget 和 allowlist 约束。
3. Trace 能在已有有效绑定的 Tool/RKB 基础上创建有 TTL、预算、取消/停止和审计的 task session，只调用注册
   Tool；每次调用前后都能关联 RKB snapshot/evidence ID。
4. 在 `SUPERVISED_FIELD_DEBUG` 下，已注册且声明 `experimental_write` 的 MHS/应用 Tool
   可以直接执行运动或写操作；必须有 target/session/参数边界、超时、急停/取消、结果读回和
   审计。不得开放任意 shell、任意 topic/argv 或无限重试。
5. Trace 遇到失败时至少执行一次有证据约束的诊断/恢复尝试；无法解决时输出
   `BLOCKED`/`UNKNOWN`，说明尝试、证据和下一步，不得把猜测写成事实。
6. 用户明确触发 Certify 时，Certify 能读取固定的 10 条旋转用例，逐条调用注册 Tool，输出每条的 expected/actual、
   状态（PASS/FAIL/BLOCKED/UNKNOWN）、证据 ID、耗时、artifact digest 和汇总结论。
7. Probe、Trace 或 Certify 任一独立旅程都可在 LanderPi 真机重复；可从 Agent 对话和 rolo-vis-v2 看到运行状态、工具调用、
   诊断尝试和最终报告；所有产物可按 digest 重放或审计。
8. 结论仅适用于有人在场的实验现场。MVP 不宣称无人值守安全、功能安全、厂商驱动合规或
   物理行为正确性。

## 3. 最大并行开发设计

先用一个短的 M0 冻结接口，随后启动所有不互相阻塞的工作流。各工作流以契约和 mock
artifact 开工，避免等待 LanderPi 空闲。

| 工作流 | 开发内容 | 主要产物 | 前置 | 并行度 |
|---|---|---|---|---|
| W0 契约与意图路由冻结 | 固定 API/schema、Probe/Trace/Tool Invoke/Certify 命令、10 条用例格式、现场模式边界 | `ROLO_V2_PROBE_TRACE_CERTIFY_ZH.md`、intent matrix、JSON Schema、验收清单 | 无 | Day 0，随后只维护兼容性 |
| W1 Probe/MHS/Tool 目录 | 将已发现 Tool、MHS Manifest、RKB read model 统一投影为 Agent catalog；保留 vendor source、digest、capability 和 limitations；支持 `experimental_write` 元数据但不自造 MHS | `tool-catalog.json`、`mhs-inventory.json`、目录 API、vendor Manifest adapter | W0 | 与 W2/W3/W4/W5/W7 并行 |
| W2 rolo skill 与 Codex caller | skill 安装/preflight、意图路由、Probe analysis input、proposal/follow-up、Trace/Certify CLI 调用和 JSON 解析；Rolo 不反向调用 harness | `skills/rolo/SKILL.md`、caller adapter、prompt/context builder、contract tests | W0、W1 mock contract | 与 W3/W4/W5/W6 并行 |
| W3 Probe Agent 分析循环 | analysis input、Codex proposal、evidence follow-up、proposal validation、用户确认和关联发布 | `probe-analysis-input.json`、`probe-association-proposal.json`、follow-up artifact | W0、W1、W2 | 与 W4/W5/W6 并行 |
| W4 Trace runtime | task session、计划执行、Tool call、读回、错误分类、自诊断/恢复 proposal、有限重试、停止/取消、Episode evidence | Trace state machine、audit JSONL、evidence bundle、replay fixture | W0、W1、W2 | 与 W5/W6 并行；集成时依赖 W2 |
| W5 Certify runner | test catalog loader、setup/teardown、逐例执行、expected/actual matcher、失败分类、报告和 artifact index | 10-case suite、JSON/Markdown/HTML report、JUnit 可选导出 | W0、W1、W2 | 与 W4/W6 并行；只在用户触发时运行 |
| W6 rolo-vis-v2 MVP | 目标/新鲜度、Tool/MHS/RKB 目录、Probe proposal/确认、Trace live timeline、诊断尝试、Certify 报告和证据详情；只读观察，不成为写授权面 | Workbench plugin package、UI contract tests、截图验收 | W0、现有 Workbench host | 与 W1/W2/W3/W4/W5 并行 |
| W7 LanderPi enablement | 真机 enrollment、Probe 发现并绑定旋转 Tool、现场安全检查、故障注入、数据与报告路径 | LanderPi profile、Tool fixture、10-case data、现场 runbook、真机 artifacts | W0；硬件可用后接入 | 与 W1/W3/W4/W5/W8 并行 |
| W8 测试/发布/观测 | CI 合约测试、离线 replay、LanderPi canary、日志/指标、artifact 签名和版本兼容 | CI job、release checklist、MVP evidence index、回滚脚本 | W0 | 与所有工作流并行 |

### 3.1 依赖图

```text
                         ┌── W2 rolo skill/caller ──┐
W0 contract ──► W1 catalog ─► W3 Probe analysis ─────┼──► I1 Probe journey
      │                  ├──► W4 Trace runtime ──────┤
      │                  └──► W5 Certify runner ─────┤
      ├──────────────────────► W6 rolo-vis ──────────┤
      ├──────────────────────► W7 LanderPi ──────────┤
      └──────────────────────► W8 CI/release ────────┘
```

W2、W3、W4、W5、W6、W7、W8 在 I0 后可以并行；它们使用 W0/W1 定义的 contract fixture。
Probe、Trace、Certify 分别有独立集成门，不要求一次旅程全部执行。

## 4. 里程碑、集成门与验收

| 里程碑 | 目标 | 通过条件 | 集成门 |
|---|---|---|---|
| M0：契约与意图冻结 | 统一 Codex→Rolo 的输入输出和命令路由 | schema、状态机、intent matrix、10-case 格式、模式边界和拒绝码评审通过 | G0：不再新增破坏性字段 |
| M1：Probe baseline on main | 在 LanderPi 复验现有基线 | enrollment、fresh Probe、RKB typed read、MHS observer、Tool Surface artifact 齐全；无旋转 Tool 则明确 BLOCKED | G1：目录只消费证据，不填充厂商 MHS |
| M2：rolo skill/caller | Codex 能安装 Rolo 并按意图调用独立入口 | skill bootstrap、Probe/Trace/Tool Invoke/Certify 路由和 JSON contract 通过；Rolo 不反向调用 Codex | G2：调用方向固定为 Codex→Rolo |
| M3：Probe Agent analysis | Probe 证据可被 Codex 分析并关联 | collect→analysis proposal→follow-up probe→proposal validation→用户确认闭环通过 | G3：proposal 不能创建未观测事实 |
| M4：Trace offline/fixture | 无硬件也能证明旋转执行和自诊断状态机 | fixture 上完成成功、工具失败→诊断→恢复、不可恢复→BLOCKED 三条 replay | G4：审计和 evidence 完整 |
| M5：Trace LanderPi field MVP | 真机完成一次旋转 Trace 任务 | 现场模式下调用真实注册旋转 Tool，完成或明确阻塞；写/运动操作均有超时、停止、读回和审计 | G5：安全员在场，非 unattended |
| M6：Certify LanderPi | 用户明确触发时真机执行 10 条旋转测试 | 10 条均有独立结果和 evidence/artifact digest，报告可读、可机器解析 | G6：Certify 可独立运行，不是必经步骤 |
| M7：rolo-vis journey | 观测面可见已调用的入口和结果 | UI 能显示 Probe proposal/确认、Trace timeline、Certify 报告和证据详情；刷新后状态一致 | G7：UI 无独立写权限 |
| M8：MVP release | 一键重复任一用户意图旅程 | `landerpi-mvp-journey` runbook 可分别运行 Probe、Trace 或 Certify；CI、真机 artifact index、回滚和已知限制齐全 | R1：发布候选 |

## 5. Trace 与 Certify 的最小接口

### 5.1 Agent adapter 暴露给 Agent 的动作

- `discover_target(target_id)`：返回 Tool catalog、MHS inventory、RKB snapshot 摘要和新鲜度；
- `read_rkb(query)`：只能读取已验证 read model，返回 value/evidence_ids/limitations；
- `analyze_probe(input)`：Codex 消费 Probe analysis input，返回 association 或 follow-up proposal；
- `submit_probe_follow_up(request)`：提交受控补充探测请求，返回新的 evidence bundle；
- `publish_association(proposal)`：在 proposal 通过 Rolo 校验且用户确认后发布关联；
- `start_trace(task, target_id)`：在已有有效绑定的 Tool/RKB 上启动一次 Trace；
- `invoke_tool(tool_id, arguments, session_id)`：由 Rolo 校验 target、digest、allowlist、预算、
  模式和参数，返回 operation result 或拒绝原因；
- `start_certify(suite_path, target_id)`：仅在用户明确要求测试时启动 Certify；
- `get_run(run_id)`：读取 Trace/Certify 状态、Episode 和 artifact index。

Agent 产品自身的 harness 负责加载 `rolo skill`、完成安装/preflight、循环调度、上下文压缩
和模型调用；Rolo 不再另造一个通用 harness，但必须提供上述稳定 connector contract 和可
离线 replay 的 fake server。`rolo skill` 根据用户意图指导调用 `probe`、`trace`、
`tool-invoke` 或 `certify`，不把 Certify 设为每次用例的必经步骤。

### 5.2 Trace 状态机

```text
DISCOVERED → PLANNED → CALLING → OBSERVED
                         │           │
                         │           ├─ SUCCESS → COMPLETED
                         │           └─ ISSUE → DIAGNOSING
                         │                         │
                         │             recoverable └─► RECOVERING → CALLING
                         │                         └─► BLOCKED/UNKNOWN
                         └─ CANCELLED/STOPPED
```

每个状态转移必须写入 `trace-session.jsonl`；诊断提示只允许引用本次 session 的 Tool result、
RKB evidence 和已注册 operation 语义。

### 5.3 Certify 最小报告字段

`run_id`、`target_id`、`snapshot_digest`、`suite_digest`、`case_id`、`operation_ids`、
`expected`、`actual`、`status`、`started_at`、`finished_at`、`evidence_ids`、
`artifact_digests`、`failure_class`、`operator_notes`。报告必须同时输出 JSON 和 Markdown；
HTML 由 rolo-vis 渲染，不产生第二份事实。

## 6. LanderPi 真机验收走查

1. Codex 加载 `rolo skill`，完成安装、版本检查、`runtime health` 和 profile preflight。
2. 用户提出一个明确意图；Codex 只调用对应入口，不自动串联其他阶段。
3. 若意图是 Probe，Codex 调用 `rolo probe collect`，读取 analysis input，生成关联或
   follow-up proposal；Rolo 校验 proposal，用户在 rolo-vis 中确认后发布关联。
4. 若意图是 Trace，Codex 在已有有效绑定的 Tool/RKB 基础上调用 Trace；发生错误时读取
   RKB 和诊断 Tool，按 session budget 尝试有限恢复。
5. 若意图是 Certify，Codex 明确调用 runner；runner 从指定路径加载 10 条固定用例，依次
   执行并生成报告。
6. 现场人员观察设备；Rolo 强制 session TTL、超时、取消、参数范围、operation allowlist、
   result read-back 和 JSONL 审计。
7. 用户在 Agent 对话或 `/workbench/` 查看本次调用的 timeline、proposal、报告和 evidence；
   归档 artifact index，使用 digest 验证可重放。

## 7. 产物和目录约定

```text
.rolo/mvp/<run_id>/
  probe-baseline-manifest.json
  probe-analysis-input.json
  probe-association-proposal.json
  probe-follow-up-request.json
  target-tool-surface.json
  rkb-read-model-catalog.json
  mhs-inventory.json
  trace-session.json
  trace-events.jsonl
  trace-evidence-bundle.json
  certify-test-suite.json
  certify-test-report.json
  certify-test-report.md
  artifact-index.json
  operator-safety-check.json
```

`artifact-index.json` 是唯一索引，所有文件记录 SHA-256、schema version、生成者和关联的
`target_id/snapshot_digest/run_id`。vendor MHS 原文件只作为 source artifact 保存，Rolo 只
建立引用和验证结果。

## 8. 非目标与升级路线

- 不在本 MVP 中实现任意机器人协议、任意 shell、云端控制或无人值守写入。
- 不把 RKB 变成功能安全控制器；RKB 只提供带来源和 freshness 的事实/未知投影。
- 不因某个 LanderPi 未发现 map route 而硬编码 route；应补 vendor MHS/adapter 或将该运行
  标记为 BLOCKED。
- `SUPERVISED_FIELD_DEBUG` 的实验写能力通过真实旅程后，才可另立生产 Write Execution
  阶段，增加审批、双人确认、回滚和更严格安全门。

## 9. 外部标准参考

厂商提供的 MHS Manifest/driver 应作为 source of truth 由 Probe 发现、校验并注册；Rolo
只消费其声明，不替厂商补填能力。MHS 的研究预览描述了标准化硬件驱动、可发现格式以及
read/write primitives，适合作为 W1 的适配输入，但不替代 LanderPi 真机证据：
[Anthropic Model Hardware Standard research preview](https://www.anthropic.com/news/model-hardware-standard-research-preview)。
