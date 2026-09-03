<!-- status: active; authority: guide; owner: docs maintainers; last_reviewed: 2026-08-30 -->

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

rolo（robot only loop once）是一个面向 Codex 类 Agent 的小而稳的目标工具层：把目标身份、
只读证据、固定工具调用和 Conformance 绑定成可审计闭环。当前版本是 Probe-first MVP；真实
机器人能力必须经过目标证据、独立校验、授权和相应的真机验收。

## 快速开始

rolo 用一条只读 Probe 链路，让 Agent 在目标自己的运行时消费受约束的 Tool Surface。
完整的离线 Demo、环境变量和故障排查见[10 分钟只读闭环](docs/getting-started/QUICKSTART_10_MIN.md)。

### 1. 安装

需要 Git、Python 3.10–3.13 和 [uv](https://docs.astral.sh/uv/)。

```bash
git clone https://github.com/zarcherlot/rolo.git
cd rolo
uv sync --locked --dev
uv run robotctl runtime health
```

### 2. 初始化目标 profile

```bash
uv run rolo target profile init \
  ssh://user@target.example/path/to/workspace \
  --robot my-robot
uv run rolo target profile show --profile my-robot
```

首次使用时只批准目标 host key；密码若被使用，仅用于一次性置备，不会写入 profile、计划或
artifact。

### 3. 采集目标证据并读取 Tool Surface

```bash
uv run rolo target inspect-profile --profile my-robot
uv run rolo probe --profile my-robot --evidence-timeout 60
uv run rolo target tool-surface --profile my-robot > surface.json
```

缺少可执行文件、依赖包、动态库或 Middleware 上下文时，结果会明确失败，不会用控制器环境
补齐目标事实。

### 4. 让 Agent 提交 ToolPlan

```bash
# Agent 读取 surface.json 后生成带 nonce 和 digest 的 PLAN.json
uv run rolo target tool-plan --profile my-robot PLAN.json
```

Rolo 校验目标、session、nonce、digest、allowlist、TTL、预算和只读边界，并写入 evidence
artifact 与 audit。若需要新增能力，先走 bounded Probe → Adapter bundle → independent
Conformance，不得直接提交任意 shell。

### 5. 类 Codex CLI 的自然语言入口

需要交互式探索时启动自然语言控制台；它仍展示规范 CLI 和风险提示：

```bash
uv run rolo
```

例如输入“检查 my-robot 当前状态，只执行只读 Adapt”或“为 my-robot 生成 Diagnose plan”。脚本和桌面启动器可使用 `uv run rolo run`；非交互环境不会启动 REPL，而是输出帮助。

这条路径会生成 Wiki、机器证据、诊断 Episode、验证证据包和阶段 handoff；没有真实目标时，Diagnose/Verify 返回 `BLOCKED` 或等待证据是预期结果。模拟后端和离线 fixture 只用于开发验证，不替代急停、碰撞检测、人工授权或真机安全验收。

## rolo 特性

- **目标证据闭环**：固定目标身份、采集边界、digest、freshness 和结果 artifact，形成可审计的 TargetEvidenceBundle。
- **Canonical Tool Surface**：Hardware、OS、Middleware、Application 四类能力统一使用 Tool、Schema、错误码、风险和只读授权语义，详见 [Agent-native Tools](docs/probe/AGENT_NATIVE_TOOLS.md)。
- **有界 Discovery**：在目标自己的 OS/Middleware 环境采集硬件、运行时、通信和应用候选；静态声明、推断和目标观测分层记录。
- **Application gap bundle**：只有在 native Tool Surface 不足时，才生成窄范围、只读、独立 Conformance 的 Adapter bundle。
- **平台无关 Probe**：ROS 仅是 Middleware provider 之一；四类稳定语义与目标绑定边界见 [v2 核心设计](docs/architecture/ROLO_V2_CORE_DESIGN_ZH.md)。

## 按需深入

- **真实目标机**：请阅读[目标机 enrollment 记录](docs/validation/ROLO_V2_TARGET_ENROLLMENT_20260902.md)和[目标证据部署规范](docs/target/TARGET_EVIDENCE_DEPLOYMENT.md)。
- **Robot Knowledge Base**：RKB 设计、[可执行开发计划](docs/architecture/ROLO_V2_RKB_EXECUTION_PLAN_ZH.md)、[Probe 后受控写执行计划（RKB 只读前置，最终版）](docs/architecture/ROLO_V2_RKB_WRITE_TRANSITION_PLAN_ZH.md)及[最新复评](docs/review/ROLO_V2_RKB_WRITE_TRANSITION_PLAN_REVIEW_ZH.md)见[架构说明](docs/architecture/ROBOT_KNOWLEDGE_BASE_FOR_AGENT_DEBUGGING_ZH.md)和[开发计划评审](docs/review/ROLO_V2_RKB_DEVELOPMENT_PLAN_REVIEW_ZH.md)。
- **远程证据**：控制器与目标机分离时，请按[目标证据部署规范](docs/target/TARGET_EVIDENCE_DEPLOYMENT.md)置备签名 bundle、SSH host-key 和 collector。
- **Codex/Claude Code**：模型 transport、授权和执行边界见 [Agent-native Tools](docs/probe/AGENT_NATIVE_TOOLS.md)。
- **阶段边界**：Probe-first 产品链和未来 Trace/Certify 的迁移语义见[阶段词汇](docs/architecture/ROLO_V2_PROBE_TRACE_CERTIFY_ZH.md)与[架构说明](docs/architecture/ARCHITECTURE.md)。
- **配置与专家 CLI**：字段和细粒度命令见[配置说明](docs/setup/CONFIGURATION.md)与 [Probe 短流程](docs/getting-started/PROBE_SHORT_JOURNEY.md)。

## 工程结构

```text
src/rolo/product_cli.py      面向用户和 Agent 的 target/Tool Surface CLI
src/rolo/stages/probe/       目标证据、硬件/OS/Middleware/Application Probe
src/rolo/agent_tools/        Tool descriptor、session、plan 和 Conformance
src/rolo/targets/            profile、凭据、SSH connector 和执行器
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
```

代码、测试、文档和发布规则统一遵循[最高开发准则](docs/architecture/DEVELOPMENT_PRINCIPLES.md)。
