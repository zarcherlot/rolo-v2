<!-- status: active; authority: guide; owner: docs maintainers; last_reviewed: 2026-09-06 -->

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
- [LanderPi MVP 现场走查](validation/LANDERPI_MVP_JOURNEY_RUNBOOK_ZH.md)：Probe、Trace、Certify 的现场边界和离线回放入口。
- [Agent Harness 增量开发计划](architecture/ROLO_V2_AGENT_HARNESS_INCREMENTAL_DEVELOPMENT_PLAN_ZH.md)：外部 Agent 的调用适配和交付方式。
- [Rolo DSL Compiler 技术方案与开发计划](architecture/ROLO_V2_DSL_COMPILER_DEVELOPMENT_PLAN_ZH.md)：Compiler 独立实现、DSL/IR、fake backend、Bundle Plan 和离线 Conformance。
- [Rolo DSL Compiler 完成后的互补开发计划](architecture/ROLO_V2_DSL_POST_COMPILER_REMAINING_DEVELOPMENT_PLAN_ZH.md)：Compiler G7 后的 Probe Context、Agent、targetd、自动发布、Trace/Certify 和 LanderPi 集成。
- [Compiler 后续产品路线与任务拆解](architecture/ROLO_V2_POST_COMPILER_PRODUCT_ROADMAP_ZH.md)：产品节点、工程任务、并行工作流与 LanderPi MVP 交付门。
- [Compiler 后端到端整合开发计划](architecture/ROLO_V2_POST_COMPILER_INTEGRATED_EXECUTION_PLAN_ZH.md)：合并待办、依赖、验收门、并行工作流与现场发布路径的唯一排期入口。
- [发布与兼容窗口策略](architecture/ROLO_V2_RELEASE_COMPATIBILITY_POLICY_ZH.md)：版本、升级、STALE 和回滚约束。
- `src/rolo/dsl/candidates.py`：从 observed Compile Context 生成并查询 digest-bound Capability Candidate Index。
- `src/rolo/dsl/proposal.py`：发布/执行前的 digest-bound Mapping Proposal 与显式确认状态。
- `src/rolo/dsl/context_digests.py`：Context 分层 digest 与 `CLEAN`/`DIRTY` 变化报告。
- `rolo-dsl candidates CONTEXT.json`：生成并查询 observed Capability Candidate Index。
- `rolo-dsl proposal REQUEST.json INDEX.json --candidate-id ID`：生成需要用户确认的 Mapping Proposal。
- `rolo-dsl bootstrap-verify BOOTSTRAP_DIR`：离线只读校验 Bootstrap、Context、Candidate 和 digest 关联。
- [Rolo DSL 交接兼容矩阵](architecture/ROLO_V2_DSL_COMPATIBILITY_MATRIX_ZH.md)：Compiler 与 Probe、Agent、targetd、发布层之间的版本化资产和校验规则。
- [Rust 执行平面重构方案](architecture/ROLO_V2_RUST_REFACTOR_PLAN_ZH.md)：以 journey session、SSH fixed entrypoint、Unix socket、targetd、签名 Bundle 和双后端兼容迁移为边界。
- [LanderPi ROS2 运行时检测](validation/LANDERPI_ROS2_RUNTIME_DETECTION_20260905.md)：记录 MentorPi 容器内的 ROS2 Humble、消息包和 topic 证据。
- [LanderPi ROS2 运行时快照](validation/LANDERPI_ROS2_RUNTIME_OBSERVATION_20260906.json)：只读 graph 的归一化、digest-bound 结果。
- [LanderPi `/odom` 来源与 AMCL 检查](validation/LANDERPI_ODOM_SOURCE_ANALYSIS_20260906.md)：核对 bringup、odom_publisher、EKF remap 和 AMCL 是否启动，记录当前无可用 odometry sample 的阻塞。
- [LanderPi `/odom`/EKF 诊断证据](validation/LANDERPI_ODOM_EKF_DIAGNOSTIC_20260906.md)：记录 ROS2 OS 用户隔离、实际样本接收和 EKF/IMU yaw 不一致，以及 Trace Agent 的复测门禁。
- [Trace odom/EKF 证据链](validation/LANDERPI_TRACE_ODOM_EVIDENCE_20260906.md)：说明只读探针的图/接收分离、yaw 偏置与增量分析、IMU 语义和校准证据。
- [LanderPi EKF 修复后旋转结果](validation/LANDERPI_ROTATION_RESULT_20260906_EKF_FIXED.json)：记录持久化 EKF 修复后一次真实机 10° 旋转闭环结果。
- [LanderPi 旋转结果](validation/LANDERPI_ROTATION_RESULT_20260906.json)：记录临时 EKF 验证和因多个 `cmd_vel` 发布者而未放行的 1° canary。
- [LanderPi 底盘旋转 canary](validation/LANDERPI_ROTATION_CANARY_20260906.json)：现场受监督的 1° 低速尝试及安全阻塞证据。
- [LanderPi 旋转 canary schema](../schemas/rolo-mvp/v1/landerpi-rotation-canary.json)：受限 Twist、共同时间窗 yaw 和可选电机命令路径证据契约。
- [targetd 现场发布与 ROS2 调试 Runbook](validation/TARGETD_FIELD_RELEASE_RUNBOOK_ZH.md)：安装/升级、bringup 前置、故障分类和回滚窗口。
- [互补层离线旅程回放](../scripts/post_compiler_journey_replay.py)：在 fake target 上重放 DSL、targetd、Release、Trace 和 Certify，并生成 artifact index。
- [Post-Compiler 离线回放证据](validation/POST_COMPILER_JOURNEY_REPLAY_20260906.md)：记录当前完整离线链路和验证边界。
- [DSL Compiler G7 发布门禁证据](validation/DSL_COMPILER_G7_RELEASE_20260906.md)：记录互补开发启动条件、发行包和 digest。
- `src/rolo/observability.py`：journey 指标、日志脱敏和 artifact retention 的实现；契约 schema 位于 `../schemas/rolo-dsl/v1/journey-metric.json`。
- `/v1/mvp/targets/{target_id}/releases/{tool_id}`：提供给 rolo-vis 的当前 Release 只读 read model。

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
rolo trace --catalog catalog.json --calls calls.json --result-fixture results.json --task "inspect"
rolo certify --suite suite.json --result-fixture case-results.json --output certify-report.json
robotctl probe target-evidence --help
```

正常使用只指定 profile。Rolo 自动选择已批准的 host key、SSH agent 或 pinned identity；
Agent 负责理解目标和生成计划，Rolo 负责固定 argv、目标绑定、预算、证据和 Conformance。

## 文档治理

本目录只保留 v2 开发所需的入口、规范、状态和验证材料。旧的 Registry、Adapt、Diagnose、
Verify、平台专用计划及历史证据已从工作树移除；完整内容仍可通过 Git 历史追溯，不能作为
当前实现依据。
