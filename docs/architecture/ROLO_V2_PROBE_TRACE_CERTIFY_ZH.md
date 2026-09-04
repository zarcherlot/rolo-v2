<!-- status: active; authority: normative; owner: rolo maintainers; last_reviewed: 2026-09-04 -->

# Rolo v2 阶段词汇

Rolo v2 的产品主链路使用三个阶段名称：

| v2 名称 | 当前职责 | 现状 |
|---|---|---|
| **Probe** | enrollment、目标证据、inspect CLI、Native Tool Session 和 ToolPlan | 当前唯一重点实现 |
| **Trace** | 消费已注册 Tool/RKB 完成用户指定任务，记录过程、诊断和结果 | 当前为契约/设计，默认未开放 |
| **Certify** | 消费固定 Tool/RKB 执行测试用例，比较 expected/actual 并生成报告 | 当前为契约/设计，默认未开放 |

旧名称 `Adapt / Diagnose / Verify` 不再注册为 v2 用户命令，也不作为新 API 名称。
正在删除的旧模块路径只允许作为迁移期间的内部实现细节：

```text
adapt    -> probe
diagnose -> trace
verify   -> certify
```

Probe 的最小闭环是：

```text
SSH target enrollment
  -> pinned Credential/HostKey
  -> TargetEvidenceBundle
  -> NativeToolSession
  -> Agent ToolPlan
  -> independent Conformance
```

Trace 和 Certify 不参与 Probe 的事实裁决。当前代码只交付 Probe；任何 Trace/Certify
入口必须先通过本文件定义的 handoff、session、allowlist 和 digest 校验，未满足条件时
明确返回 `TRACE_BLOCKED` 或 `CERTIFY_BLOCKED`，不能模拟成功。

## Agent 交互方式

Agent 产品（Codex、Claude Code 或其他 Harness）负责对话、意图解析、上下文压缩和循环
调度；Rolo 负责 target identity、Tool/RKB catalog、session、预算、授权边界、执行和证据。
调用方向固定为：

```text
用户 → Agent Harness → Rolo Probe/Trace/Certify → 结构化结果/evidence → Agent → 用户
```

Agent 只能从 Rolo 返回的 catalog 选择已注册工具和 query；不能凭自然语言创建新工具、
任意 shell、任意 argv 或未注册 route。Agent 的关联结果只能是 `PROPOSED`、`UNKNOWN`
或 `UNSUPPORTED`，不能自行写成 `VERIFIED`、`ELIGIBLE` 或授权结论。

### Probe 构造闭环（MVP）

当 Probe 只读结果暴露出应用能力缺口时，Probe 不再停在候选报告。Rolo 输出
`rolo-probe-analysis-input/v1`，当前 Agent Harness 在自己的交互窗口中与用户一起编写、
运行和修改 adapter，再提交 `rolo-tool-registration-proposal/v1`。MVP 不增加第二个
rolo-vis 确认步骤，也暂不要求隔离工作区；Harness 对代码负责，Rolo 对 proposal 的
target、evidence、descriptor、digest 和 session 边界负责。校验通过后，Rolo 把 Tool
发布到 registered application catalog，后续 Trace 从该 catalog 消费。

这个闭环对所有应用 Tool 通用。以旋转为例，`app.base.rotate` 是应用语义，proposal
只声明参数和目标绑定的 `base.motion.velocity` route；provider/driver 负责把 route
映射到具体控制输入（例如 `/cmd_vel`），因此 harness 不能在 proposal 中嵌入 shell 或
topic publish。角度反馈、停止和超时属于 route/provider contract，只有写入已注册
Tool 和 route 后才允许进入现场调试执行路径。

## 用户使用旅程

用户不需要手工编排内部 artifact，按意图进入下列路径：

1. **连接/了解目标**：用户说明目标和观察目的，Agent 请求 Probe；Rolo 完成 profile、host
   key、TargetEvidenceBundle 和只读 Tool Surface。
2. **关联/补证**：Agent 读取 `ProbeEvidenceView`/RKB，提出带 evidence 引用的关联建议；
   Rolo 校验格式和范围，用户在审阅面确认或要求补证。
3. **执行任务（Trace）**：用户明确任务、允许范围和停止条件；用户确认后生成不可变
   `TraceHandoffReceipt`，Trace 创建独立 session，重新校验 target、digest、freshness 和 scope。
4. **执行测试（Certify）**：用户提供测试套件、输入、预期和报告位置；Certify 只消费已
   注册 Tool/RKB，逐例记录 expected/actual、失败、重试和证据。
5. **结束/回退**：任一身份、证据、新鲜度、授权或停止条件失败，Rolo 返回 BLOCKED，
   Agent 向用户解释限制并回到 Probe/审阅，不自动扩大权限。

典型用户指令分别是：

```text
Trace：调用已经注册的 rolo 工具，在当前环境内完成建图，过程中若遇到系统问题，自行诊断。
Certify：帮我执行建图的 10 条测试用例，测试数据位于 <path>，输出测试报告到 <report-path>。
```

Trace 是开放目标的任务执行与问题闭环；Certify 是测试套件驱动的可重复执行与判定。两者
都只能消费 Probe 发布的 Tool/RKB；每条 Certify 用例必须有固定输入、预期、风险、超时、
停止条件和证据记录。真实写入是否允许由独立运行模式和 Write Execution 门禁决定，不能
由用户措辞或 Agent 自主诊断升级。

进入 Trace 不是 `READ_ONLY_COMPLETE` 后的自动跳转。必须先完成 Probe 最终关联审阅，
由用户生成绑定 target fingerprint、snapshot/evidence digest、association IDs、Trace
目标、允许范围和 TTL 的不可变 `TraceHandoffReceipt`（或等价的 `UserIntentReceipt`）。
Trace 启动时必须重新读取并比对目标身份、digest、freshness 和 scope；不一致、过期或未
确认时返回 `TRACE_BLOCKED` 并回到 Probe。Trace 的默认入口是独立的任务执行 session，不
继承 Probe session nonce；在 `OBSERVATION_ONLY` 下只读，在 `SUPERVISED_FIELD_DEBUG` 下
可按批准范围直接消费已注册的实验性操作（包括写和运动类 Tool）。

若未来 Trace 请求包含设备写动作，必须明确运行模式：默认 `OBSERVATION_ONLY` 直接拒绝；
`SUPERVISED_FIELD_DEBUG` 只能在安全员/调试工程师在场、用户范围明确、Tool schema/resource/
参数绑定、停止/取消、post-read 和审计全部生效时运行。生产化或无人值守写入还必须通过
独立 Write Execution 计划中的 SafetyDeclaration、QuiescenceLease、challenge、dry-run 和
执行前后证据门禁。Agent、GUI 或 Harness 始终不得调用未注册接口、任意 Shell 或绕过 MHS driver。
