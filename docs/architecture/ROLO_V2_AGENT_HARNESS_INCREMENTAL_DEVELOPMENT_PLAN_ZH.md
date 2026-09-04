<!-- status: draft; authority: plan; owner: rolo maintainers; last_reviewed: 2026-09-04; source_of_truth: ROLO_V2_PROBE_TRACE_CERTIFY_ZH.md -->

# Rolo v2 Agent Harness 增量开发计划

本文承接 [LanderPi Agent 用户旅程 MVP 开发计划](ROLO_V2_LANDERPI_AGENT_JOURNEY_MVP_PLAN_ZH.md)，只定义 Harness 交付和适配工作包；
把“Agent 使用自己的 harness，按用户意图调用 Rolo 的 Probe、Tool、Trace 或 Certify”的
增量项拆成可实现、可验收、可并行的工作包。

本文不要求 Rolo 再开发一个通用 Agent harness。Codex、Claude Code 或其他 Agent 产品继续
负责模型调用、上下文压缩、循环调度和用户对话；Rolo 提供可信的 discovery、Tool 执行、RKB
读取、证据和运行时边界。

## 1. 目标调用链路

```text
Agent 产品自带 harness
  │
  ├─ 加载/更新 rolo skill，完成安装和 preflight
  ├─ 根据用户意图选择 probe / trace / tool-invoke / certify / read
  ├─ 读取需要的 Tool / RKB / MHS context
  ├─ 调用 Rolo CLI 或 loopback API
  ├─ 读取结构化结果、状态和 evidence
  └─ 仅在用户明确要求测试时调用 certify
```

目标不是让 Agent 获得一台机器的 shell，而是让 Agent 通过 skill 知道何时调用哪一个语义化
命令，并获得一组 target-bound、digest-bound、session-bound 的已注册操作。Probe、Trace、
Certify 是可独立调用的产品入口，不是强制流水线。

## 1.1 调用方向原则

统一采用 `Codex/Agent harness → Rolo` 的调用方向：

- Codex 加载 `rolo skill`，根据用户意图选择 Probe、Trace、Tool Invoke、Certify 或 Read；
- Rolo 不主动调用 Codex，不保存模型凭据，也不在 Probe/Trace/Certify 内嵌模型循环；
- Rolo 返回结构化 input、result、event 和 artifact，Codex 负责下一步推理；
- 需要多轮时，由 Codex 根据上一次结果再次调用 Rolo；
- Rolo 只执行已校验的请求，并对每一轮保持 target/session/digest 绑定。

## 2. 当前基线和新增项

| 链路步骤 | 当前 main | 增量开发 |
|---|---|---|
| 安装和使用 Rolo | `skills/rolo/SKILL.md`、`skills/rolo-tool-planning/` 已有基础规则 | 完整 skill bootstrap、安装/升级/preflight、意图路由和版本校验 |
| 读取 Tool/RKB/MHS | API read model 和 CLI 已有 | 统一 connector contract、分页/新鲜度和 context builder |
| 生成 ToolPlan | `rolo target tool-plan`、schema、allowlist、digest、budget 已有 | 支持单步 proposal、计划增量和 Trace session |
| 调用 Rolo | `NativeToolSession` 可执行已校验只读计划 | 暴露统一单步 invocation；现场实验写操作走注册 capability |
| 读取结果 | 有结构化 CLI 结果和 evidence artifact | 统一 result envelope、错误分类、事件流和 run 查询 |
| 自主诊断 | 当前无 Trace runtime | 诊断上下文、恢复 proposal、有限重试和停止/取消 |
| Certify | 当前无测试 runner | suite schema、runner、expected/actual matcher、报告 |
| rolo-vis | Workbench host/read-only API 已有 | Trace timeline、诊断和 Certify 结果视图 |
| LanderPi | enrollment、Probe、RKB/MHS observer 已有 | 真实旋转 Tool 发现/生成、现场实验运行和 10 条旋转用例 |

## 3. Rolo v2 如何交付给 Agent harness

### 3.1 推荐交付形态：skill 作为入口，CLI/API 作为执行面

Rolo 不以“把 Python 内部模块交给 Agent”作为交付方式。Agent 首先加载 `rolo skill`，由
skill 指导安装、检查、意图路由和结果处理；实际执行仍由 CLI/API 完成：

```text
Rolo distribution
  ├─ rolo skill：安装、preflight、意图路由、错误处理和调用约束
  ├─ 运行时包：rolo / robotctl CLI + loopback API
  ├─ Agent contract：JSON Schema、Tool descriptor、RKB/MHS envelope、错误码
  └─ Evidence：Probe/Trace/Certify artifact、报告和 replay fixture
```

skill 是 Agent 的正式产品入口，但不是安全边界；安全边界始终在 Rolo CLI/API 和目标执行
session 内。

### 3.2 CLI 交付（MVP 首选）

适用于 Codex、Claude Code 等已经具备 terminal harness 的 Agent 产品。

Agent 产品安装 Rolo 后调用：

```bash
uv sync --locked --dev
uv run rolo target tool-surface --profile landerpi
uv run rolo target tool-plan --profile landerpi PLAN.json
```

CLI 输出必须是机器可解析 JSON；Agent 不解析人类日志，不读取 `.rolo` 内部未声明文件。

CLI 交付包包含：

- `rolo`：目标注册、Probe、Tool Surface 和 ToolPlan；
- `robotctl`：Probe status、runtime health、artifact 查询；
- `schemas/`：ToolPlan、Tool result、RKB、MHS、Episode schema；
- `skills/rolo/SKILL.md`：安装、升级、preflight、命令路由和安全边界的主 skill；
- `skills/rolo-tool-planning/`：告诉 Agent 如何读取 surface、生成 digest-bound plan 和处理拒绝；
- `skills/rolo-harness-codegen/`：把已知 Tool 的 typed arguments、binding 和派生 request
  预先编译成可复用 Harness bundle，避免每次执行重新手工编码和拼接 SSH 载荷；
- `examples/harness-plugin/`：Agent 产品接入和 conformance 示例。

### 3.3 Loopback API 交付

适用于独立 Web/Desktop Agent 产品。Rolo 在目标侧启动一个只绑定 loopback 的 runtime：

```bash
uv run rolo runtime serve --host 127.0.0.1 --port 8765
```

第一版 API：

```http
GET /v1/features
GET /v1/robots
GET /v1/robots/{robot_id}/tools
GET /v1/robots/{robot_id}/rkb
GET /v1/robots/{robot_id}/mhs
GET /v1/robots/{robot_id}/episodes
```

Trace MVP 增加：

```http
POST /v1/runs
POST /v1/runs/{run_id}/tool-calls
GET  /v1/runs/{run_id}
GET  /v1/runs/{run_id}/events
POST /v1/runs/{run_id}/cancel
POST /v1/certify/runs
GET  /v1/certify/runs/{run_id}/report
```

API 是 Agent adapter 的远程边界；Agent 不直接连接 SSH，也不直接调用目标机原生命令。

### 3.4 rolo skill 交付和 bootstrap

`rolo skill` 是 Codex 或其他 Agent harness 的第一入口，必须覆盖完整生命周期：

```text
detect → install/upgrade → preflight → configure profile → route intent → execute → report
```

skill 可以指导 harness 执行安装命令，但不能绕过 harness 的执行权限安装未知代码。安装源、
版本和 digest 必须固定；安装完成后至少执行 `rolo --version`、`robotctl runtime health`
和 capability check。

Skill 至少说明：

- 用户要求发现能力时调用 `probe`；
- 用户要求完成任务时调用 `trace`；
- 用户要求执行明确操作时调用 `tool-invoke`/`tool-plan`；
- 用户明确要求测试或回归时才调用 `certify`；
- 仅在需要时读取 Tool/RKB/MHS，不强制每次用例先 Probe；
- 只能使用 `agent_callable=true` 的 Tool；
- RKB 是带 freshness 的事实投影，未知必须保留；
- Tool 失败时先读取证据，再决定诊断或恢复；
- 不得执行任意 shell、topic、argv；
- 结束时输出 run、evidence 和 artifact 引用。

### 3.5 推荐的 MVP 混合方式

```text
Agent harness
  ├─ 加载 rolo skill 并完成安装/preflight
  ├─ 按用户意图选择一个 Rolo 命令
  ├─ 按需读取 Tool/RKB/MHS 目录
  ├─ CLI：生成并执行单步 ToolPlan 或调用 Trace/Certify
  ├─ JSON：读取结果和 evidence
  └─ Agent 自己处理后续对话或诊断
```

该方式可以复用 main 已有的 `NativeToolSession`，先不等待完整 Trace HTTP API。等 Trace
runtime 稳定后，再把 CLI 执行替换为 API，Agent 上层的 skill 和 intent contract 保持不变。

## 4. 增量工作包

### W0：Contract 和 Intent Matrix Freeze

开发：

- 固定 discovery、read、invoke、run、cancel、certify 的请求/响应 schema；
- 固定用户意图到命令的映射：probe、trace、tool-invoke、certify、read；
- 固定状态、错误码和拒绝原因；
- 固定 `target_id/snapshot_digest/surface_digest/session_id/run_id` 关联字段；
- 固定 CLI JSON 与 API JSON 等价关系。

产物：

```text
schemas/AgentDiscoveryEnvelope.schema.json
schemas/AgentToolInvocation.schema.json
schemas/AgentRunEvent.schema.json
schemas/CertifyRequest.schema.json
docs/architecture/AGENT_ROLO_CONNECTOR_CONTRACT.md
```

验收：同一 fixture 通过 CLI 和 API 产生可等价验证的 envelope；每类用户意图都有独立调用
路径，certify 不被隐式触发。

### W0.5：rolo Skill Bootstrap

开发：

- 合并 `skills/rolo/SKILL.md` 和 `skills/rolo-tool-planning/` 的安装、升级、preflight 规则；
- 定义固定安装源、版本、digest 和回滚方式；
- 定义 `rolo`、`robotctl`、runtime health 和 contract version 检查；
- 定义 skill 到 CLI/API 的 intent routing 表；
- 为 Codex 和通用 Agent 提供加载方式、环境变量和最小示例；
- 将安装失败、版本不匹配和能力缺失转换为可读的 BLOCKED 结果。

产物：

```text
skills/rolo/SKILL.md
skills/rolo-tool-planning/SKILL.md
docs/agent/ROLO_SKILL_INSTALL.md
docs/agent/ROLO_INTENT_ROUTING.md
examples/agent/rolo-skill-bootstrap/
```

验收：空环境中，Agent 按 skill 完成安装、版本检查和 health；已有旧版本时能安全升级或
明确拒绝；安装失败不执行目标操作。

### W1：Discovery Context Builder

开发：

- 从 Tool/RKB/MHS read model 构造有限 Agent context；
- 过滤 stale、unverified、`callable=false`；
- 保留 UNKNOWN、BLOCKED 和 limitations；
- 加入 snapshot/surface digest；
- 设定最大 Tool 数、字段数和上下文大小；
- 清理目标输出中的提示词注入内容。

验收：给定同一 artifact，context digest 稳定；未验证能力不会出现在 executable tools 区域。

### W2：rolo Skill/Codex Caller Adapter

开发：

- `rolo skill` 的安装、preflight 和 intent routing；
- Codex 调用 Probe、Trace、Tool Invoke、Certify 的 CLI wrapper；
- 单步 PLAN 生成器和 JSON result parser；
- exit code 到标准状态/错误类映射；
- stdout/stderr/evidence/artifact 归档；
- 明确 Rolo 不反向调用 Codex。

验收：fake target 上分别执行 Probe、Trace、Tool Invoke、Certify；每次只执行用户选择的入口，
Codex 读取上一步结果后自行决定是否发起下一次调用。

### W2.5：Probe Agent Analysis Loop

开发：

- `probe-analysis-input` envelope：target、evidence index、candidate、RKB/MHS 摘要和 limitations；
- Codex 的 association/follow-up proposal schema；
- proposal 证据引用校验；
- `NEED_MORE_EVIDENCE` 的 bounded follow-up Probe；
- 最大轮数、命令数、超时和重复调用去重；
- rolo-vis 中的 proposal review 和用户确认；
- 关联发布为 Tool/RKB read model 的规则。

验收：Probe 可重复执行“collect → Harness 交互式编码 → validate → register”；
proposal 不能引用不存在的 evidence，也不能把模型猜测发布为能力。

本 MVP 对 W2.5 做以下产品取舍：Rolo 不主动调用 Codex，也不增加第二个
rolo-vis 审阅门。Rolo 通过 `probe-analysis-input` 把 target/evidence/routes/RKB/MHS
摘要交给当前 Harness；用户直接在 Harness 窗口中纠正、迭代和测试生成的 adapter。
Harness 最终提交 `rolo-tool-registration-proposal/v1`，Rolo 校验 target、evidence、
descriptor 和 digest 后立即注册。MVP 暂不要求隔离工作区，注册后的 application Tool
可以进入真实设备执行路径，但仍必须经过 Rolo 的 target-bound session 和 typed
ToolPlan。该协议是通用的，旋转只是第一个 adapter；后续 mapping/navigation 等 Tool
复用同一 envelope、proposal 和 registry。

本轮补充 `rolo-harness-codegen` 子 skill：当目标 Tool 已知时，Harness 依据 descriptor
机械生成与参数列表同构的输入校验函数，并依据 observation contract 生成输出校验函数；
再计算 binding 定义的派生 request，生成带 source/binding digest 的 bundle。SSH 或本地执行
只由 Rolo target executor 选择，不能在生成代码中重复拼接。用户在 Harness 窗口修正代码或
参数时，只重新生成 bundle 并复用同一执行入口；Tool 注册后，后续 Trace 直接实例化同一
模板，不再重新编码。新增 Tool 不需要修改该 Skill。

### W3：Trace Session Runtime

开发：

- session 创建、TTL、budget、cancel/stop；
- `DISCOVERED → PLANNED → CALLING → OBSERVED` 状态机；
- 单步 Tool invocation；
- 事件流和 run 查询；
- target/session/digest/allowlist 校验；
- Episode metadata 和 evidence index。

验收：成功、拒绝、超时、取消和过期五类场景均有确定状态和 artifact。

### W4：Diagnosis/Recovery Loop

开发：

- 错误分类：目标不可达、工具不可用、参数错误、Middleware 故障、结果不一致、超时；
- 诊断 context builder；
- recovery proposal schema；
- 只允许已注册诊断/恢复 Tool；
- 最大尝试次数和预算；
- 无法解决时输出 BLOCKED/UNKNOWN。

验收：fixture 中实现“Tool 失败 → 读取 RKB → 调用诊断 Tool → 恢复 → 重试”和不可恢复两条 replay。

### W5：Supervised Field Experimental Operations

开发：

- vendor MHS Manifest 引用和校验；
- `experimental_write` capability；
- 参数范围、timeout、stop/cancel、读回；
- operator/safety context；
- 现场 JSONL 审计；
- 禁止任意 shell/topic/argv。

验收：LanderPi 现场安全员在场时完成一次注册旋转操作；异常时能停止并保留完整调用证据。

### W6：Certify Runner

开发：

- 测试 suite schema 和 digest；
- setup/teardown；
- 逐例 Tool 调用；
- expected/actual matcher；
- PASS/FAIL/BLOCKED/UNKNOWN；
- JSON、Markdown 报告和 artifact index。

验收：用户明确触发 Certify 后，固定 10 条旋转用例逐条执行；不允许 Agent 修改用例或跳过未通过项。

### W7：rolo-vis-v2 观测集成

开发：

- 目标和 freshness；
- Tool/RKB/MHS 目录；
- Trace timeline；
- 诊断和恢复尝试；
- Certify 进度和报告；
- evidence/artifact 详情。

验收：UI 刷新后与 API 状态一致；UI 没有独立的 Tool 执行或授权权限。

### W8：LanderPi Journey/Release

开发：

- LanderPi profile 和新鲜 Probe；
- 真实旋转 Tool 发现/生成/绑定；
- 10 条测试数据；
- 故障注入；
- 一键 runbook；
- artifact index、回放和 release checklist。

验收：从 profile 到 Trace 旋转、诊断、Certify 报告完整运行一次，并能复核所有 digest。

### W9：CI、Replay 和兼容性

开发：

- CLI/API contract tests；
- fake target 和 fake Agent replay；
- Python 版本矩阵；
- artifact digest、schema migration 和过期 session 测试；
- 失败日志和最小复现包；
- release candidate 检查。

验收：不连接 LanderPi 也能回放成功、诊断、阻塞、取消和 Certify 五类主路径；任何
contract 破坏都阻止发布。

## 5. 最大并行计划

```text
Day 0：W0 Contract + Intent Matrix Freeze
       │
       ├── W0.5 rolo skill bootstrap ─┐
       ├── W1 Context Builder ────────┤
       ├── W2 Skill/Codex caller ──────┤
       ├── W2.5 Probe analysis ────────┤
       ├── W5 Field Operations ───────┤ 可并行
       ├── W6 Certify Runner ─────────┤
       ├── W7 rolo-vis-v2 ────────────┤
       ├── W8 LanderPi fixture ───────┤
       └── W9 CI/replay ──────────────┘
                    │
                    ▼
             I1 Probe analysis integration
                    │
                    ▼
             I2 Offline Trace integration
                    │
                    ▼
             I3 LanderPi Trace integration
                    │
                    ▼
             I4 Certify + UI
                    │
                    ▼
             I5 MVP release
```

实际工作包依赖：

| 集成门 | 依赖 | 通过条件 |
|---|---|---|
| I0 Contract + Skill | W0、W0.5 | schema、意图路由、拒绝码、安装和版本规则冻结 |
| I1 Probe Analysis | W1、W2、W2.5 | collect、analysis、follow-up、proposal validation 和确认闭环通过 |
| I2 Offline Trace | W1、W2、W3、W4 | fixture 成功/诊断/阻塞 replay 全部通过 |
| I3 LanderPi Trace | I2、W5、W8 | 真机完成旋转或有证据地 BLOCKED；无伪造能力 |
| I4 Certify/UI | W6、W7、I3 | 用户明确触发后 10 条用例报告和 UI 视图一致 |
| I5 Release | W9、I4 | runbook、artifact index、回滚和限制说明齐全 |

W1、W2、W2.5、W5、W6、W7、W8、W9 在 I0 后可以同时开发；W0.5 在 I0 后优先完成，W3/W4
使用 W1/W2 的 fixture。Probe、Trace、Certify 的集成门相互独立，I5 只在用户选择的旅程和
发布条件全部满足后执行。

## 6. Agent 提示词和上下文协议

每次 Agent 决策都由 adapter 生成以下结构，而不是直接拼接原始日志：

```text
SYSTEM
  角色、不可伪造事实、禁止任意执行、提示词注入防护

TARGET
  robot_id、mode、session_id、snapshot_digest、surface_digest

AVAILABLE_TOOLS
  仅 agent_callable=true 的 Tool、参数 schema、风险、timeout、evidence_ids

RKB_FACTS
  typed value、freshness、source、limitations、UNKNOWN 原因

RUN_HISTORY
  已调用 Tool、结果、错误分类、诊断尝试、剩余 budget

TASK
  用户目标和本轮完成条件

OUTPUT_SCHEMA
  intent_result / association_proposal / additional_probe / next_tool_call /
  diagnosis / recovery_proposal / final_status / evidence_used
```

Probe 场景返回 `association_proposal` 或 `additional_probe`；Trace 场景返回
`next_tool_call`/`diagnosis`；Certify 场景只返回 run 状态和报告引用。Agent 返回的任何
proposal 或 `next_tool_call` 都必须再次由 Rolo 校验，提示词本身不是授权凭证。

## 7. 最终 MVP 验收矩阵

| 场景 | 期望 |
|---|---|
| Skill bootstrap | Agent 能安装/升级 Rolo、完成 preflight 并验证 contract version |
| 新鲜 Probe + 目录读取 | Agent 得到 target/tool/RKB/MHS 结构化 envelope |
| Probe 分析循环 | Codex 能消费 evidence、请求 bounded follow-up、提交并获得用户确认的关联 |
| 未发现旋转 Tool | Agent 停止并输出 `BLOCKED: capability not observed` |
| 正常旋转 | Trace 完成，产生 run、episode、evidence 和结果 artifact |
| Middleware 故障 | Agent 读取 RKB，调用已注册诊断/恢复 Tool，有限重试 |
| 不可恢复故障 | 输出 BLOCKED/UNKNOWN，不宣称成功 |
| 现场实验操作 | 有安全员在场、参数/TTL/停止/读回/审计齐全 |
| Certify 10 条用例 | 每条有 expected/actual/status/evidence/digest |
| UI 查看 | Trace timeline、诊断和 Certify 报告与 API 一致 |
| 重放 | 通过 artifact index 和 digest 重新核对执行事实 |

## 8. 交付版本和兼容性

Rolo 向 Agent harness 交付四类版本化资产，其中 `rolo skill` 是正式入口：

1. **Skill distribution**：`rolo` 主 skill、tool-planning 子 skill、安装/bootstrap、intent routing 和 Probe/Trace/Certify 调用规则；
2. **Runtime distribution**：Python package、`rolo`/`robotctl` CLI 和 loopback server；
3. **Contract distribution**：JSON Schema、错误码、Tool descriptor、RKB/MHS envelope；
4. **Evidence distribution**：Probe、Trace、Certify 的 artifact index、报告和 replay fixture。

版本兼容规则：

- schema 只允许向后兼容新增字段；
- skill、CLI、API 和 schema 使用同一 release version；
- skill bootstrap 必须先完成 preflight，未通过时不得执行目标操作；
- Agent adapter 必须先调用 `/v1/features` 协商能力；
- Tool/RKB/MHS 的 source digest 变化时，旧 session 不得继续调用；
- CLI 和 API 使用同一 canonical envelope，禁止各自定义含义不同的状态；
- vendor MHS 原文件作为 source artifact 保存，Rolo 只提供引用和校验结果。

## 9. 非目标

- 不为 Rolo 开发第二个通用 Agent harness；
- 不让 Agent 直接获得 SSH、shell 或原始 topic 权限；
- 不把提示词、模型输出或 Agent proposal 当作事实或安全授权；
- 不在本计划内承诺无人值守写入、功能安全认证或跨平台厂商驱动完整覆盖。
