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

rolo（robot only loop once）是一个面向具身机器人的开发与验证框架：每次用例执行都记录
输入、过程、结果和外部观测，形成可解释、可回放、可复现的证据闭环。当前版本仍是开发中的
MVP；真实机器人能力必须经过目标证据、独立 Gate、授权和相应的真机验收。

## 快速开始

rolo 用一条可审计的三阶段路径，把机器人工作区从“已发现”推进到“可诊断”和“可验证”。
完整的离线 Demo、环境变量和故障排查见[10 分钟安装与 Demo](docs/getting-started/QUICKSTART_10_MIN.md)。

### 1. 安装

需要 Git、Python 3.10–3.13 和 [uv](https://docs.astral.sh/uv/)。

```bash
git clone https://github.com/zarcherlot/rolo.git
cd rolo
uv sync --locked --dev
uv run robotctl runtime health
```

### 2. Adapt：发现并建立机器人上下文

```bash
uv run rolo adapt /path/to/robot-workspace \
  --robot my-robot \
  --urdf /path/to/robot.urdf
uv run robotctl adapt status --robot my-robot
```

`--urdf` 可以省略。Adapt 会生成 Wiki、目标证据、候选操作和 handoff；静态源码、mock 或
`--help` 输出不会直接被当成真实运行能力。

### 3. Diagnose → Verify：推进阶段闭环

```bash
uv run robotctl diagnose plan --robot my-robot
uv run robotctl diagnose run --robot my-robot --confirm
uv run robotctl verify plan --robot my-robot
uv run robotctl verify run --robot my-robot --confirm
uv run robotctl pipeline-status --robot my-robot
```

### 4. 类 Codex CLI 的自然语言入口

需要交互式探索时启动自然语言控制台；它仍展示规范 CLI、风险提示，并要求对写入操作明确确认：

```bash
uv run rolo
```

例如输入“检查 my-robot 当前状态，只执行只读 Adapt”或“为 my-robot 生成 Diagnose plan”。脚本和桌面启动器可使用 `uv run rolo run`；非交互环境不会启动 REPL，而是输出帮助。

这条路径会生成 Wiki、机器证据、诊断 Episode、验证证据包和阶段 handoff；没有真实目标时，Diagnose/Verify 返回 `BLOCKED` 或等待证据是预期结果。模拟后端和离线 fixture 只用于开发验证，不替代急停、碰撞检测、人工授权或真机安全验收。

## rolo 特性

- **证据闭环**：关联命令、执行状态、遥测、配置版本、测试判定、异常区间和诊断结论，形成可追溯 episode。
- **Canonical CLI**：Hardware、Linux、Middleware、Application 四层能力统一使用 Operation、Schema、错误码、风险和授权语义；产品 Registry 当前定义 294 个操作，详见 [Canonical Operations](docs/CANONICAL_OPERATIONS.md)。
- **主动发现与机器人 Wiki**：有界 Discovery 汇总主机、软件栈、依赖、启动关系、通信接口、目标证据和未知项，并将静态声明、启发式推断和运行时观测分层记录。
- **Diagnose、Verify 与 `robot_use`**：Diagnose 负责基线到回归，Verify 负责计划到证据；`robot_use` 可提供带时间戳的图像、状态和遥测监督，但不拥有安全决策权。
- **ROS 与非 ROS**：ROS 不是 Adapt 前置条件；非 ROS 工程的 CLI Route 设计见 [非 ROS 工程适配](docs/adapt/NON_ROS_ADAPTATION.md)。

## 按需深入

- **真实目标机**：请阅读[真实目标机验证手册](docs/target/REAL_MACHINE_VALIDATION_RUNBOOK_ZH.md)。
- **远程证据**：控制器与目标机分离时，请按[目标证据部署规范](docs/target/TARGET_EVIDENCE_DEPLOYMENT.md)置备签名 bundle、SSH host-key 和 collector。
- **Codex/Claude Code**：模型 transport、授权和执行边界见[Agent-native Tools](docs/adapt/AGENT_NATIVE_TOOLS.md)与[Stage Agent Plugin Kit](docs/adapt/STAGE_AGENT_PLUGIN_KIT.md)。
- **Diagnose/Verify 细节**：阶段 contract、artifact 和 handoff 约束见[三阶段架构](docs/architecture/ARCHITECTURE.md)与[工程状态台账](docs/reference/ENGINEERING_STATUS.md)。
- **配置与专家 CLI**：字段和细粒度命令见[配置说明](docs/setup/CONFIGURATION.md)与[Adapt 短流程](docs/getting-started/ADAPT_SHORT_JOURNEY.md)。

## 工程结构

```text
src/rolo/stages/adapt/       发现、适配、conformance 与 handoff
src/rolo/stages/diagnose/    诊断、调参与 robot_use
src/rolo/stages/verify/      验证计划、证据与验收门禁
src/rolo/commands/           robotctl 命令域
schemas/                     导出的 JSON Schema
tests/                       单元、API、contract 和 fixture 测试
docs/                        架构、操作手册、验证 runbook 与状态台账
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
