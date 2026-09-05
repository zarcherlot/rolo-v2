<!-- status: draft; authority: plan; owner: rolo maintainers; last_reviewed: 2026-09-05; prerequisite: ROLO_V2_DSL_COMPILER_DEVELOPMENT_PLAN_ZH.md G7 -->

# Rolo DSL Compiler 完成后的互补开发计划

## 1. 目标

本文只规划 Compiler standalone G7 完成后的互补工作。它消费冻结的 DSL、Compile Context、
Canonical IR、Bundle Plan、Compile Result 和 diagnostics 契约，不修改 Compiler 核心语义。

目标产品链：

```text
Probe
  → Compile Context adapter
  → Coding Agent 生成 Rolo DSL
  → Rolo Compiler check/compile
  → targetd 在目标机解析 Bundle Plan
  → 生成目标绑定 Bundle
  → Conformance
  → 自动发布 Tool Release
  → Trace / Certify 消费
```

Compiler G7 是本计划的启动门。没有 G7 证据时，只能继续修复 Compiler，不能以临时解析器、
Agent 脚本或 targetd 私有格式替代冻结契约。

## 2. 互补工作范围

### 2.1 包含

- Probe evidence 到 Compile Context 的适配；
- `rolo skill` 和 Coding Agent 的 DSL 生成、诊断和修复循环；
- targetd 的 DSL bundle 接收、目标侧 runtime resolver 和 Bundle Plan 编译；
- `EXECUTE` 的 source bundle、runtime loader 和专用 backend；
- 目标侧 C3/C4 Conformance；
- immutable Tool Release、Tool Catalog 和 stale/rollback；
- Trace/Certify 对 Tool Release 的消费；
- LanderPi 建图 MVP、真机 canary 和回放。

### 2.2 不包含

- 改写 Compiler parser、IR 或 DSL 语义；
- 让 Agent 直接操作 SSH、目标 shell 或 Tool Catalog；
- 通过 DSL 开发目标机不存在的机器人功能；
- 由 Rolo 替 vendor 编写 MHS 权威定义；
- 物理安全控制器和无人值守安全策略。

## 3. 稳定交接契约

互补组件只能消费 Compiler 发布的以下版本化资产：

```text
rolo-dsl/v1
rolo-compile-context/v1
rolo-canonical-ir/v1
rolo-bundle-plan/v1
rolo-dsl-compile-request/v1
rolo-dsl-compile-result/v1
Backend SPI version
Diagnostic code catalog
```

任何 Probe、Agent 或 targetd 扩展必须先转换为这些 schema，不能在各自组件中定义另一套
Operation、状态、digest 或 diagnostics。

## 4. Probe Context Adapter

Probe adapter 负责把真实 Probe/RKB/MHS 产物投影为 Compiler 的 `CompileContext`：

```text
TargetEvidenceBundle
  + RKB typed read model
  + vendor MHS Manifest
  + published Tool Catalog
  → rolo-compile-context/v1
```

必须完成：

- target identity、fingerprint、runtime revision 和 observed time 绑定；
- route/resource、消息 schema 和 schema digest 规范化；
- vendor MHS Manifest 原文件引用和 digest；
- 已发布 Tool 的 operation、input/output schema 和 release digest；
- freshness、限制、UNKNOWN 和缺失原因保留；
- Context canonicalization 和 digest 与 Compiler 一致。

Probe 未发现的 route、MHS operation 或 schema 不得写入 Context 的 observed 集合。需要补
采集时由 Agent 返回结构化 Probe 请求，再由 Probe 执行。

## 5. Coding Agent 和 rolo skill

Coding Agent 通过 `rolo skill` 获取 `AdapterMappingRequest`：

```json
{
  "schema_version": "rolo-adapter-mapping-request/v1",
  "journey_session_id": "journey-001",
  "user_goal": "完成建图并提供状态诊断",
  "context_digest": "0123456789abcdef...",
  "available_tool_catalog_digest": "0123456789abcdef...",
  "operation_candidates": ["app.mapping.run", "app.mapping.status"],
  "dsl_version": "rolo-dsl/v1"
}
```

Agent 输出 `mapping.dsl`；四种 Operation 都必须由 Agent 生成 DSL。`EXECUTE` 额外输出
source bundle 和 implementation contract。Agent 不能直接提交发布请求，也不能修改
Compile Context。

修复循环：

```text
Agent 生成 DSL
  → rolo dsl validate/compile
  → diagnostics
      ├─ DSL 错误：Agent 修复 DSL
      ├─ Context 缺失：Agent 请求 bounded Probe follow-up
      ├─ backend 缺失：返回 capability gap
      └─ EXECUTE contract 错误：Agent 修复 source bundle
```

循环绑定一个 `journey_session`，限制轮数、墙钟时间和 artifact 数量；达到上限返回
`BLOCKED`，不得自动降级成未验证 Tool。

## 6. targetd 目标侧编译

targetd 复用已有 journey session SSH stdio，接收签名的 DSL/Bundle Plan：

```text
DSL_PUT
  → DSL_CHECK
  → PLAN_RESOLVE
  → TARGET_COMPILE
  → TARGET_CONFORMANCE
  → DSL_RESULT
```

targetd 必须：

1. 验证 DSL、Context、IR、Bundle Plan 和 compiler version digest；
2. 解析目标机真实 ROS/Middleware、provider、route 和 message schema；
3. 为 `OBSERVE`、`COMPOSE`、`INVOKE` 选择已注册 runtime backend；
4. 为 `EXECUTE` 加载 source bundle 并验证 implementation contract；
5. 在专用 cache/run 目录生成目标绑定 Bundle；
6. 返回 generated bundle manifest、compile log、artifact digest 和 C3/C4 报告。

targetd 不写机器人业务工作区，不接受自由 shell，不接受未声明的依赖或网络地址。

## 7. Conformance 和自动发布

Compiler standalone 已完成离线 C1～C4；互补层增加目标相关检查：

| 层级 | 互补检查 |
|---|---|
| T1 Target Resolve | 目标 runtime、provider、route、MHS 和 schema 真实存在 |
| T2 Bundle Build | 目标绑定 Bundle manifest、entrypoint、依赖和 digest |
| T3 Runtime Behavior | 归一化输入输出、错误映射、事件和结果符合 DSL contract |
| T4 Release Integrity | DSL、IR、Context、Bundle、compiler 和 target fingerprint 一致 |

自动发布条件：

```text
Compiler C1～C4 PASS
  + targetd T1～T4 PASS
  + source/dsl/evidence digest 一致
  → immutable Tool Release
  → Tool Catalog current 原子更新
```

Release Publisher 生成：

```text
release-manifest.json
tool-descriptor.json
generated-bundle-manifest.json
conformance.json
source-and-dsl-digests.json
catalog-update.json
```

发布失败不得覆盖旧 current；Context、route、MHS、target fingerprint 或 compiler version
变化时，旧 Release 标记为 `STALE`。

## 8. Trace / Certify 消费

Trace 和 Certify 只读取 `PUBLISHED` 且 digest 匹配的 Tool Release：

- Trace 按用户意图规划和调用 Tool，支持事件流、诊断、有限重试和 Episode evidence；
- Certify 按用户指定测试套件逐例调用 Tool，输出 expected/actual/status/evidence；
- 两者共享一个 journey session 的 SSH 通道和调用级 idempotency key；
- 目标上下文或 release digest 漂移时，调用返回 `STALE` 或 `BLOCKED`。

Trace/Certify 不重新解释 DSL，也不直接调用 targetd backend；它们消费 Tool Catalog 中的
发布版本。

## 9. 最大并行开发工作流

| 工作流 | 内容 | 依赖 | 主要产物 |
|---|---|---|---|
| R0 | 交接 contract、feature negotiation 和版本锁定 | Compiler G7 | adapter contract、compatibility matrix |
| R1 | Probe Context adapter | R0、Probe/RKB/MHS | `compile-context.json`、context builder |
| R2 | rolo skill 和 Agent DSL generation | R0、R1 | skill、mapping request、prompt fixture |
| R3 | targetd DSL transport 和 cache | R0、SSH targetd baseline | typed frames、cache、compile state |
| R4 | 目标 runtime backend | R3、vendor/runtime provider | ROS/MHS/CLI backend、LanderPi adapter |
| R5 | Target Conformance | R3、R4 | T1～T4 报告、negative canary |
| R6 | Release Publisher 和 Tool Catalog | R5 | immutable release、stale、rollback |
| R7 | Trace consumer | R6、journey session | Trace runtime、Episode evidence |
| R8 | Certify consumer | R6、test suite contract | runner、report、artifact index |
| R9 | LanderPi MVP 集成 | R1～R8 | 真机 canary、建图 Tool、十条用例 |
| R10 | CI、replay、观测和发布 | R0～R9 | release checklist、回放包、指标 |

R1、R2、R3、R10 可在 Compiler G7 后并行；R4 依赖 R3；R5 依赖 R4；R6 依赖 R5；R7、R8
可在 R6 后并行；R9 在 R7、R8 均通过后集成。

## 10. 集成里程碑

| 门 | 完成条件 |
|---|---|
| I0 Contract Handoff | Compiler G7 artifact 和 schema 版本被所有适配层消费 |
| I1 Context Ready | 真实 Probe 可生成可验证 Compile Context |
| I2 Agent DSL Ready | Codex 可从 Context 生成四类 DSL，并能消费 diagnostics |
| I3 Target Compile Ready | targetd 可在真实目标机生成目标绑定 Bundle |
| I4 Target Conformance | T1～T4 全部通过；失败不会生成 Release |
| I5 Auto Publish | PASS artifact 自动生成 Release 并原子更新 Catalog |
| I6 Trace Ready | Trace 可消费发布 Tool 完成目标任务和诊断 |
| I7 Certify Ready | Certify 可执行固定测试套件并生成报告 |
| I8 LanderPi MVP | 完整完成 Probe → DSL → compile → conformance → publish → Trace/Certify |

## 11. LanderPi 验收旅程

```text
1. Codex 加载 rolo skill，创建 journey_session。
2. Probe 采集 LanderPi identity、runtime、Middleware、应用 route 和 vendor MHS。
3. Context adapter 生成并签名 compile-context.json。
4. Coding Agent 读取 Context，生成建图相关 Rolo DSL。
5. Rolo Compiler 校验 DSL 并生成 Canonical IR/Bundle Plan。
6. Rolo 通过 session SSH 把 Bundle Plan 交给 targetd。
7. targetd 解析目标 ROS/Middleware，生成目标绑定 Bundle。
8. T1～T4 Conformance 通过后，Release Publisher 自动发布 Tool。
9. Trace 消费建图 Tool，完成建图并记录 Episode/evidence。
10. Certify 消费同一 Release，执行十条用例并输出报告。
```

必须能从 artifact index 复核 Context、DSL、IR、Bundle、Conformance、Release、Trace 和
Certify 的全部 digest。

## 12. 互补计划完成定义

- Probe Context 可以稳定转换并通过 Compiler schema；
- Coding Agent 可以只通过 rolo skill 生成和修复 DSL；
- targetd 可以在目标机编译 Bundle Plan；
- C1～C4 和 T1～T4 全部通过才会自动发布；
- Trace 和 Certify 只消费已发布、未过期的 Tool Release；
- LanderPi 完成一次完整用户旅程并产出可回放 artifact index；
- 任一失败都保留旧 Release 和旧 Tool Catalog current。
