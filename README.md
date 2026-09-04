<!-- status: active; authority: guide; owner: docs maintainers; last_reviewed: 2026-09-04 -->

<p align="center">
  <img src="rolo-logo.svg" width="720" alt="rolo Loop Exit — robot only loop once">
</p>

<p align="center">
  <strong>在每一次执行中自我进化</strong><br>
</p>

<p align="center">
  中文 · <a href="docs/README.en.md">English</a>
</p>

## rolo 是什么

rolo（robot only loop once）是一个面向 Codex 类 Agent 的目标工具层：把目标身份、只读证据、
固定工具调用和 Conformance 绑定成可审计闭环。当前版本是 Probe-first MVP；真实机器人能力
必须经过目标证据、独立校验、授权和相应的真机验收。

v2 的核心定位是“小而稳的可信工具面”：Rolo 定义 Tool、Discovery/Evidence、Conformance
和 Release 四类标准，并提供经过验证的 Probe CLI；Agent 负责发现、规划和解释，Rolo 负责
目标绑定、证据固化和运行时边界。Trace 与 Certify 将在此基础上消费已注册 Tool 和 RKB，
不把未观测能力写成事实。

## 快速开始

当前 main 的可执行入口是只读 Probe 链路：先注册目标，再采集新鲜证据，最后让 Agent 消费
目标绑定的 Tool Surface 生成 ToolPlan。完整的离线 Demo、环境变量和故障排查见
[Probe 端到端验收手册](docs/validation/PROBE_E2E_ACCEPTANCE_RUNBOOK_ZH.md)。

### 1. 安装

需要 Git、Python 3.10–3.13 和 [uv](https://docs.astral.sh/uv/)。

```bash
git clone https://github.com/zarcherlot/rolo-v2.git
cd rolo-v2
uv sync --locked --dev
uv run robotctl runtime health
```

### 2. 注册目标 profile

```bash
uv run rolo target profile init \
  ssh://user@landerpi.example/path/to/workspace \
  --robot landerpi
uv run rolo target inspect-profile --profile landerpi
```

首次使用时只批准目标 host key。密码若被使用，仅用于一次性置备，不会写入 profile、计划或
artifact；日常执行使用 profile 中固定的 host key 和 identity。

### 3. 采集新鲜 Probe 证据

```bash
uv run rolo probe --profile landerpi --evidence-timeout 60
uv run robotctl probe status --robot landerpi
```

Probe 只记录目标实际观测到的 identity、OS、Middleware、application、MHS 和 capability。
厂商提供的 MHS Manifest 作为 source artifact 被发现、校验和引用；没有真实证据的能力会保留
为 `UNKNOWN` 或 `BLOCKED`，不会由 Rolo 自行填充。

### 4. 获取 Tool Surface 并提交 ToolPlan

```bash
uv run rolo target tool-surface --profile landerpi > surface.json

# Agent 读取 surface.json 后生成带 target、session、nonce 和 digest 的 PLAN.json
uv run rolo target tool-plan --profile landerpi PLAN.json
```

Rolo 校验目标绑定、surface/plan digest、allowlist、TTL、预算和当前访问模式，并记录
evidence artifact 与 audit。Agent 只能调用已注册、已验证且 `agent_callable=true` 的 Tool；
不得把任意 shell、未登记 topic/argv 或猜测出的 route 当作 Tool。

### 5. 查看 API 和后续 Agent MVP

main 提供 loopback read-model API，供 Codex、Claude Code 等外部 Agent 产品接入：

```bash
uv run rolo runtime serve --host 127.0.0.1 --port 8765
curl http://127.0.0.1:8765/v1/features
curl http://127.0.0.1:8765/v1/robots/landerpi/tools
curl http://127.0.0.1:8765/v1/robots/landerpi/rkb
curl http://127.0.0.1:8765/v1/robots/landerpi/mhs
```

当前 API 和 RKB/MHS surface 是只读基线；Trace 的“调用已注册工具并自行诊断”和 Certify 的
“执行测试用例并输出报告”属于后续 LanderPi Agent MVP，开发计划见
[LanderPi Agent 用户旅程 MVP 开发计划](docs/architecture/ROLO_V2_LANDERPI_AGENT_JOURNEY_MVP_PLAN_ZH.md)。

### 6. 类 Codex CLI 的自然语言入口

需要交互式探索时可以启动自然语言控制台；它仍展示规范 CLI 和风险提示：

```bash
uv run rolo
```

没有真实目标时，Probe 会返回 `BLOCKED` 或等待证据，这是预期结果。模拟后端和离线 fixture
只用于开发验证，不替代急停、碰撞检测、人工授权或真机安全验收。

## rolo 特性

- **目标证据闭环**：固定目标身份、采集边界、digest、freshness 和结果 artifact，形成可审计的 TargetEvidenceBundle。
- **Canonical Tool Surface**：Hardware、OS、Middleware、Application 四类能力统一使用 Tool、Schema、错误码、风险和只读授权语义，详见 [Agent-native Tools](docs/probe/AGENT_NATIVE_TOOLS.md)。
- **有界 Discovery**：在目标自己的 OS/Middleware 环境采集硬件、运行时、通信和应用候选；静态声明、推断和目标观测分层记录。
- **Probe、Trace 与 Certify**：Probe 负责发现和关联；Trace 负责消费已注册 Tool/RKB 完成任务并在实验模式下自诊断；Certify 负责执行固定测试用例并生成证据报告。
- **平台无关 Probe**：ROS 仅是 Middleware provider 之一；四类稳定语义与目标绑定边界见 [v2 核心设计](docs/architecture/ROLO_V2_CORE_DESIGN_ZH.md)。

## 按需深入

- **真实目标机**：请阅读[目标机 enrollment 记录](docs/validation/ROLO_V2_TARGET_ENROLLMENT_20260902.md)和[Probe 端到端验收手册](docs/validation/PROBE_E2E_ACCEPTANCE_RUNBOOK_ZH.md)。
- **Robot Knowledge Base**：RKB 设计、[可执行开发计划](docs/architecture/ROLO_V2_RKB_EXECUTION_PLAN_ZH.md)、[Probe 后受控写执行计划](docs/architecture/ROLO_V2_RKB_WRITE_TRANSITION_PLAN_ZH.md)见[架构说明](docs/architecture/ROBOT_KNOWLEDGE_BASE_FOR_AGENT_DEBUGGING_ZH.md)。
- **LanderPi Agent MVP**：用户旅程、最大并行工作流、集成门和真机验收见 [MVP 开发计划](docs/architecture/ROLO_V2_LANDERPI_AGENT_JOURNEY_MVP_PLAN_ZH.md)。
- **rolo-vis-v2**：Probe 证据图、Agent 关联建议和 Trace 前用户确认见 [Probe 证据与关联设计](docs/architecture/ROLO_VIS_PROBE_ASSOCIATION_PLAN_ZH.md)。
- **远程证据**：控制器与目标机分离时，请按[目标证据部署规范](docs/target/TARGET_EVIDENCE_DEPLOYMENT.md)置备签名 bundle、SSH host-key 和 collector。
- **Codex/Claude Code**：模型 transport、授权和执行边界见 [Agent-native Tools](docs/probe/AGENT_NATIVE_TOOLS.md)。
- **阶段边界**：Probe、Trace、Certify 的职责和现场监督模式见[阶段词汇](docs/architecture/ROLO_V2_PROBE_TRACE_CERTIFY_ZH.md)与[架构说明](docs/architecture/ARCHITECTURE.md)。
- **配置与专家 CLI**：字段和细粒度命令见[配置说明](docs/setup/CONFIGURATION.md)与 [Probe 短流程](docs/getting-started/PROBE_SHORT_JOURNEY.md)。

## 工程结构

```text
src/rolo/targets/            profile、凭据、SSH connector 和目标执行器
src/rolo/stages/probe/       目标证据、硬件/OS/Middleware/Application Probe
src/rolo/agent_tools/        Tool descriptor、session、plan 和 Conformance
src/rolo/rkb/                RKB envelope、typed read model 和 Episode metadata
src/rolo/commands/           robotctl Probe/configuration 命令域
schemas/                     导出的 JSON Schema
tests/                       单元、API、contract 和 fixture 测试
docs/                        入口、规范、Probe 指南、目标证据与状态台账
```

实现入口和测试对应关系见[实现地图](docs/reference/IMPLEMENTATION_MAP.md)；当前成熟度、证据等级和
已知限制见[工程状态与可信度台账](docs/reference/ENGINEERING_STATUS.md)。

## 参与项目

欢迎通过 Issue 描述机器人平台、复现步骤和预期行为，并通过 Pull Request 提交小而可验证的改动。
提交前请运行：

```bash
uv run pytest
uv run ruff check .
python scripts/check_docs.py
```

代码、测试、文档和发布规则统一遵循[最高开发准则](docs/architecture/DEVELOPMENT_PRINCIPLES.md)。
