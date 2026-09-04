<!-- status: draft; authority: plan; owner: rolo maintainers; last_reviewed: 2026-09-04; source_of_truth: ROLO_V2_PROBE_TRACE_CERTIFY_ZH.md -->

# Rolo v2 Probe/Trace/Certify 最大并发开发计划

本文只负责开发拆分、依赖和并发边界。Probe/Trace/Certify 的职责、Agent 调用方向、用户旅程、
handoff 和运行模式以[阶段规范](ROLO_V2_PROBE_TRACE_CERTIFY_ZH.md)为唯一事实源；本计划不
复制这些定义，也不把计划中的功能描述成当前已发布能力。

## 1. 开发前置与不变量

在 `B0` 完成前不得并行扩展 Trace 或写能力：

- 冻结 `TargetToolSurface`、`RKBReadModelCatalog`、`TraceHandoffReceipt`、`TraceSession`、
  `CertificationInput` 和 `CertificationReport` 的版本、错误码与所有权；
- 明确当前 Probe 是唯一已交付的生产入口，Trace/Certify 默认 `BLOCKED`；
- 所有产物绑定 `robot_id`、target fingerprint、snapshot/evidence digest、schema version、
  freshness 和 scope；
- 任何失败不改变既有 Probe 只读链路，不能以 fake、Manifest、设备 ACK 或 Agent 结论替代
  目标证据和后置观察。

## 2. 责任分工

| 事项 | Probe | Trace | Certify |
|---|---|---|---|
| 目标身份与 evidence | 采集、验证、发布 baseline | 启动时重新校验 | 校验输入引用 |
| Tool/RKB catalog | 发现、规范化、Conformance、发布 | 建立独立 session 并消费 | 按测试用例消费 |
| Agent/用户交互 | 提供证据视图和边界 | 消费用户确认的 handoff | 消费用户指定的测试套件 |
| 诊断/任务 | 不执行任务闭环 | 执行任务、诊断、重试并记录 Episode | 不改变事实，只记录测试结果 |
| 测试结论 | 不输出 | 不输出 Certify 结论 | 输出 PASS/CONDITIONAL/BLOCKED/REVOKED |
| 写操作 | 不提供写入口 | 仅按运行模式和 Write Execution 门禁请求 | 仅执行已批准测试中的工具 |

MHS 是输入来源：Probe 只引用并校验 vendor/provider Manifest 和 driver digest；Rolo 不代替
vendor 定义权威语义。Trace/Certify 只能通过已注册 route 和 Rolo session 消费 MHS。

## 3. 最大并发工作流

`B0` 通过后，以下工作流可并行；每个工作流都必须有正向、负向和回滚测试：

| 工作流 | 交付范围 | 依赖 | 不得越过的边界 |
|---|---|---|---|
| **W1 Probe baseline** | Tool/RKB catalog、Manifest 引用、baseline manifest、freshness 和限制 | 当前 Probe | 不新增写入口，不把 `CALLABLE` 当全局权限 |
| **W2 Trace read-only** | 独立 Trace session、handoff receipt、任务预算、诊断/重试、Episode evidence | W1、阶段规范 | 只消费已注册 Tool；目标/digest 变化即阻断 |
| **W3 Supervised field** | operator identity、SafetyDeclaration、资源锁、stop/cancel、post-read、审计 | W2、现场责任人 | 仅 `SUPERVISED_FIELD_DEBUG`；不自动升级无人值守资格 |
| **W4 Certify runner** | 测试套件、用例执行、expected/actual、回归/验收报告 | W1；可选 W2 evidence | 不发现新 Tool，不修改 Probe/RKB 事实 |
| **W5 Agent/rolo-vis** | `ProbeEvidenceView`、AssociationReport、EvidenceRequest、用户 review receipt | W1；外部 Harness 自带模型 | Agent 只能返回 `PROPOSED/UNKNOWN/UNSUPPORTED` |
| **W6 目标与 fixture** | 离线 replay、LanderPi 只读 canary、拒绝矩阵和 no-write audit | W1–W5 各自测试 | 远程无人值守和物理动作另立 canary |
| **W7 CI/发布** | schema、digest、pytest collection、feature flag、回滚指针和责任人 | 各工作流产物 | 任一失败可独立关闭 Trace/Certify |

## 4. 集成门

1. **G0 Contract Freeze**：版本、错误码、状态和 artifact 关系冻结，文档/Schema 检查通过。
2. **G1 Probe Baseline**：identity、evidence、Tool/RKB catalog、MHS 引用和只读审计可重放；
   没有写调用。
3. **G2 Trace Readiness**：用户完成关联审阅并生成 handoff receipt；Trace 重新校验目标、
   digest、freshness、scope 和 session 预算。
4. **G3 Certify Readiness**：测试套件、输入、预期、风险、超时、停止条件和证据引用冻结。
5. **G4 Supervised Write（可选）**：仅在现场责任人、已注册工具、资源/参数绑定、停止路径、
   post-read 和审计全部满足时开放；生产化写入遵循独立的 [Write Transition Plan](ROLO_V2_RKB_WRITE_TRANSITION_PLAN_ZH.md)。

门禁失败时返回 `BLOCKED`，保留上一份 immutable artifact 和 Probe 只读入口。

## 5. Agent 调用与用户旅程索引

本计划只给出依赖顺序，具体交互统一引用[阶段规范](ROLO_V2_PROBE_TRACE_CERTIFY_ZH.md)：

```text
用户意图
  → Agent Harness 选择 Probe / Trace / Certify
  → Rolo 返回结构化 catalog/result/evidence
  → 用户确认关联或 handoff
  → 独立 session 消费已注册 Tool/RKB
  → Agent 向用户解释结果、限制或 BLOCKED 原因
```

Agent 不拥有 Rolo 的 target identity、写权限或最终结论；用户确认是有 scope/TTL 的收据，不
是对任意命令的授权。

## 6. 交付物与回滚

```text
probe-baseline-manifest.json
target-tool-surface.json
rkb-read-model-catalog.json
trace-handoff-receipt.json
trace-session.json
trace-evidence-bundle.json
certify-test-suite.json
certify-test-report.md
no-write-or-write-canary-audit.json
```

每个工作流维护自己的 feature flag 和 latest 指针。新增产物写入失败、schema/digest/fingerprint/
freshness 漂移或负测失败时，只撤销新指针并保留上一版本；不得覆盖旧 EvidenceBundle、RKB
snapshot 或审计记录。

## 7. 完成定义

| 阶段 | 最低完成条件 |
|---|---|
| Probe | baseline 可重放，MHS/RKB/Tool 证据和限制完整，写调用为 0 |
| Trace | handoff、独立 session、预算、诊断/重试和 Episode evidence 可重放 |
| Certify | 固定测试套件可重放，报告完整关联 expected/actual 和证据 |
| Supervised field | 现场责任、停止/取消、post-read 和审计可重放；不产生无人值守资格 |
| Remote/physical | 独立安全计划和物理 canary 通过；不从其他阶段继承 |

