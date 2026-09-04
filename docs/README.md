<!-- status: active; authority: guide; owner: docs maintainers; last_reviewed: 2026-09-02 -->

# Rolo v2 文档入口

Rolo v2 是一个给 Codex 类 Agent 使用的小而稳的目标工具层。当前产品链只有一条：

```text
TargetProfile → SSH Connector → TargetEvidenceBundle
             → NativeToolSession → Agent ToolPlan → Conformance
             ↘ application Candidate → Adapter bundle → application Conformance (only on a named gap)
```

## 核心文档

- [v2 架构](architecture/ARCHITECTURE.md)：用户、Agent、Rolo、机器人之间的职责和信任边界；
- [Probe/Trace/Certify 阶段规范](architecture/ROLO_V2_PROBE_TRACE_CERTIFY_ZH.md)：三阶段职责、Agent 交互和用户旅程唯一入口；
- [10 分钟只读闭环](getting-started/QUICKSTART_10_MIN.md)：从 profile 到 ToolPlan 的可复制流程；
- [Probe 用户短流程](getting-started/PROBE_SHORT_JOURNEY.md)：角色分工和最小命令集；
- [工程状态台账](reference/ENGINEERING_STATUS.md)：当前实现、证据等级、已知限制；
- [Agent-native Tool 标准](probe/AGENT_NATIVE_TOOLS.md)：四类小而稳的 Tool Surface、Session 和调用约束；
- [Application gap bundle](probe/APPLICATION_GAP_BUNDLES.md)：启动、导航、地图、操作四类窄应用闭环；
- [v1 application operation inventory](probe/APPLICATION_OPERATION_V1_INVENTORY.md)：137 项语义清单及 LanderPi 首批验证切片；
- [实现地图](reference/IMPLEMENTATION_MAP.md)：代码入口、Schema、产物与测试的对应关系；
- [真实目标机 enrollment 记录](validation/ROLO_V2_TARGET_ENROLLMENT_20260902.md)：一次物理目标的验证证据。

## 下一阶段草案与专项计划

- [RKB 设计](architecture/ROBOT_KNOWLEDGE_BASE_FOR_AGENT_DEBUGGING_ZH.md)：事实分层、来源和
  freshness 约束；
- [开发计划评审](review/ROLO_V2_RKB_DEVELOPMENT_PLAN_REVIEW_ZH.md)：基线校正与阻塞项；
- [可执行开发计划](architecture/ROLO_V2_RKB_EXECUTION_PLAN_ZH.md)：唯一的 RKB 排期入口；
- [Probe 后受控写执行计划（RKB 只读前置，最终版）](architecture/ROLO_V2_RKB_WRITE_TRANSITION_PLAN_ZH.md)：只读完工审计、
  受控写执行试点和后续灰度门禁。
- [Probe 后受控写执行计划复评](review/ROLO_V2_RKB_WRITE_TRANSITION_PLAN_REVIEW_ZH.md)：当前完工判定、
  阻塞项与修订要求。
- [rolo-vis Probe 证据与关联设计](architecture/ROLO_VIS_PROBE_ASSOCIATION_PLAN_ZH.md)：证据可视化、Agent 关联建议和 Trace 前用户确认流程。
- [Probe 端到端验收手册](validation/PROBE_E2E_ACCEPTANCE_RUNBOOK_ZH.md)：CLI、artifact、LanderPi canary 和 rolo-vis 只读 GUI 验收路径。
- [Probe 基线化后的后续开发计划](architecture/ROLO_V2_POST_PROBE_BASELINE_DEVELOPMENT_PLAN_ZH.md)：只读基线冻结、完工审计和后续集成门。
- [Probe/Trace/Certify 最大并发计划](architecture/ROLO_V2_PHASE_CONSUMPTION_MAX_CONCURRENCY_PLAN_ZH.md)：各阶段并发工作流；不重复定义阶段语义。
- [LanderPi Agent 用户旅程 MVP 开发计划](architecture/ROLO_V2_LANDERPI_AGENT_JOURNEY_MVP_PLAN_ZH.md)：单目标用户旅程和真机验收特化。
- [Agent Harness 增量开发计划](architecture/ROLO_V2_AGENT_HARNESS_INCREMENTAL_DEVELOPMENT_PLAN_ZH.md)：外部 Agent 的调用适配和交付方式。

根目录的 `OPERATION_CONTRACTS.md`、`CANONICAL_OPERATIONS.md` 和 Episode contract 文档，
以及 `architecture/WORKBENCH_PLUGIN_HOST_CONTRACT.md`，仅因生成流程或现有测试的固定引用
而保留；它们不是新增功能的设计入口。

## 目录职责

| 目录 | 只放什么 |
|---|---|
| `architecture/` | 当前架构规范、开发准则，以及 RKB 设计/计划草案 |
| `getting-started/` | 可复制执行的安装和 Probe 入门流程 |
| `probe/` | Agent-native Tool、Application gap 和 operation 参考 |
| `reference/` | 工程状态与代码/测试实现地图 |
| `setup/` | 配置字段和运行时前置条件 |
| `target/` | 目标证据部署与目标绑定边界 |
| `validation/` | 当前仍有价值的固定目标 enrollment 证据 |
| `review/` | 尚未成为规范的设计评审与阻塞项 |

## 四类稳定标准

产品只定义四类稳定语义：hardware、OS、Middleware、application。MVP 可以先实现其中
某个具体 provider；provider ID、命令和运行时依赖属于实现细节，不能改变四类标准或把
目标机未观测到的能力写成事实。

## 用户入口

```bash
rolo target profile init ssh://user@target.example/path/to/workspace --robot my-robot
rolo target inspect-profile --profile my-robot
rolo target tool-surface --profile my-robot
rolo target tool-plan --profile my-robot PLAN.json
robotctl probe target-evidence --help
```

正常使用只指定 profile。Rolo 自动选择已批准的 host key、SSH agent 或 pinned identity；
Agent 负责理解目标和生成计划，Rolo 负责固定 argv、目标绑定、预算、证据和 Conformance。

## 文档治理

本目录只保留 v2 开发所需的入口、规范、状态和验证材料。旧的 Registry、Adapt、Diagnose、
Verify、平台专用计划及历史证据已从工作树移除；完整内容仍可通过 Git 历史追溯，不能作为
当前实现依据。
