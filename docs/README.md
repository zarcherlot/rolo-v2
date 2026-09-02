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
- [工程状态台账](reference/ENGINEERING_STATUS.md)：当前实现、证据等级、已知限制；
- [Agent-native Tool 标准](probe/AGENT_NATIVE_TOOLS.md)：四类小而稳的 Tool Surface、Session 和调用约束；
- [Application gap bundle](probe/APPLICATION_GAP_BUNDLES.md)：启动、导航、地图、操作四类窄应用闭环；
- [v1 application operation inventory](probe/APPLICATION_OPERATION_V1_INVENTORY.md)：137 项语义清单及 LanderPi 首批验证切片；
- [实现地图](reference/IMPLEMENTATION_MAP.md)：代码入口、Schema、产物与测试的对应关系；
- [真实目标机 enrollment 记录](validation/ROLO_V2_TARGET_ENROLLMENT_20260902.md)：一次物理目标的验证证据。

根目录的 `OPERATION_CONTRACTS.md`、`CANONICAL_OPERATIONS.md` 和 Episode contract 文档，
以及 `architecture/WORKBENCH_PLUGIN_HOST_CONTRACT.md`，仅因生成流程或现有测试的固定引用
而保留；它们不是新增功能的设计入口。

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
