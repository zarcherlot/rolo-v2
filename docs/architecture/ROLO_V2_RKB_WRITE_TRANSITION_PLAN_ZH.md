<!-- status: frozen; current_state: BLOCKED_BY_READ_ONLY_PRECONDITIONS; authority: plan; owner: rolo maintainers; last_reviewed: 2026-09-04; reviewed_commit: c05ab27e62b4d61351d99a711be930f6a7abc27b; source_of_truth: ROBOT_KNOWLEDGE_BASE_FOR_AGENT_DEBUGGING_ZH.md; predecessor: ROLO_V2_RKB_EXECUTION_PLAN_ZH.md; revision: final -->

# Rolo v2 Probe 后受控写执行计划最终版：RKB 只读完工审计与非运动写执行

本计划适用于 [RKB 可执行开发计划（修订版）](ROLO_V2_RKB_EXECUTION_PLAN_ZH.md)完成后的下一阶段。
它回答两个问题：

1. Probe/RKB 只读链路什么时候才算真正开发完成；
2. 只读完成后，如何在目标绑定、授权、状态前置条件和可回滚约束下逐步开放**非运动**受控写执行。

## 0. 术语与责任边界

- **Probe** 只负责目标上的观察、读取和证据采集；Probe 默认只读，不因本计划而获得写入口。
- **RKB** 只负责保存和查询目标事实、能力资格、写前置条件、执行前后证据及 Episode 记录；RKB
  不生成设备命令、不调用物理 Provider，也不承担写执行或安全控制器职责。
- **Write Execution** 是独立的 Rolo 执行层，负责授权、租约、challenge、固定 operation、Provider
  调用、补偿/回滚和审计。它可以消费 RKB 的资格与前置条件，并把结果写回 RKB，但“写入 RKB 记录”
  不等于“写入设备”。

因此，本计划不称为“RKB 写操作”或“RKB 可写转型”，而称为“Probe 后受控写执行”：
`Probe（只读） -> RKB（事实/资格/证据） -> Rolo Write Execution（受控调用） -> Provider/设备`。

文件路径保留历史兼容名 `ROLO_V2_RKB_WRITE_TRANSITION_PLAN_ZH.md`；规范标题和术语以本页为准，
后续新文档不得再把设备写执行归属于 RKB。

本计划不是物理动作安全计划。zero-stop、bounded motion 和 global navigation 属于独立的
`R3_PHYSICAL_CANARY_PLAN`，必须在本计划完成后另行进行 State/Safety、物理场地和安全责任评审。

本计划不把“代码已合并”“Provider 注册成功”“一次 read 返回成功”视为只读完成，也不把
“能发出写请求”视为写操作成功。所有阶段默认关闭，未通过门禁不得进入下一阶段。

本最终版已将复评中的阻塞项转为强制条款：RKB 测试必须进入 CI 收集范围；Write Execution 请求必须使用独立
的一次性 challenge；W1 必须先批准具体 R1 pilot；dry-run 必须有可验证的无副作用证据；W5
必须使用量化阈值。没有这些条件，计划状态保持 `BLOCKED`，不允许通过文档状态推断实现完成。

## 1. 前置条件与产品边界

### 1.1 前置条件

本计划只能在前一计划的 RKB-0 至 RKB-4 已有可核验产物后启动。以当前仓库基线看，以下前置
条件尚未成立，因此本文当前状态为 `BLOCKED`，不是可直接排期的实现计划：

- RKB schema、Evidence Envelope、canonical digest 和迁移工具已存在；
- Bundle → RKB → typed query → DiscoveryReport 兼容投影离线闭环已通过；
- identity、freshness、provenance、UNKNOWN、STALE 和失败关闭测试已纳入 CI；
- MHS 只读 manifest/inspect/status/read 通过 fake backend 和固定目标机只读 canary；
- Episode metadata、latest 原子指针和旧 artifact 双读一写已验证；
- `tests/test_rkb_*.py` 已被 `pyproject.toml` 的 pytest 收集规则实际收集，并在 CI 中执行；
- `docs/reference/ENGINEERING_STATUS.md` 已记录对应证据等级和限制。

前置完成必须由 `read-only-completion.json` 逐项绑定 artifact、digest、测试命令和责任人，
不能以“文档已写”或“代码已合并”代替。

若上述条件无法逐项提供 artifact、测试结果和责任人签字，本计划停留在 `BLOCKED`，只允许
补齐只读缺口。

前置证明必须使用机器可读的 `schemas/ReadOnlyCompletionAudit.schema.json` 校验；人工复核
只能确认责任归属和例外说明，不能替代 schema、测试或目标证据。

### 1.2 本阶段不改变的边界

- RKB 仍是目标事实和能力门禁层，不是急停、碰撞检测或功能安全控制器；
- Agent、Wiki、源码声明和 MHS manifest 不能单独授予写权限；
- 首个可写切片不包含运动、动力电源、固件、校准参数批量修改或不可逆机械动作；
- 任何写操作必须由用户/运行时策略显式授权，默认 deny，且只允许固定 operation allowlist；
- 未观察到新鲜的 state/safety 前置条件时，写能力必须是 `UNAVAILABLE` 或 `STALE`。
- 当前只读 Native Tool、TargetEvidence 和 `ApplicationOperationAdapterBundle` 不得被放宽为写入口；
- W1 必须先指定一个真实的非运动 R1 pilot operation，否则保持 `BLOCKED`。

## 2. 总体阶段、判定与决策门

```text
phase=W0 READ_ONLY_AUDIT
        │
        ├─ BLOCKED/FAIL ──> READ_ONLY_REMEDIATION ──┐
        │                                         │
        └─ PASS ──────────────────────────────────┘
        ▼
phase=W1 WRITE_CONTRACT_FROZEN
        │
        ▼
phase=W2 WRITE_SIMULATION ──失败──> WRITE_REMEDIATION
        │
        ▼
phase=W3 WRITE_SHADOW / DRY_RUN
        │
        ▼
phase=W4 ONE_TARGET_ONE_OPERATION
        │
        ├─失败/未知──> decision=REVOKED + COMPENSATE/ROLLBACK
        ▼
phase=W5 LIMITED_WRITE_REVIEW
        │
        ▼
WRITE_EXPANSION_REVIEW
```

阶段和判定必须分开持久化，不能用一个枚举混合两个维度：

- `phase`：`W0`、`W1`、`W2`、`W3`、`W4`、`W5`；
- `decision`：`PASS`、`CONDITIONAL`、`BLOCKED`、`ELIGIBLE`、`VERIFIED`、`REVOKED`。

判定含义：

- W0 的 `PASS` 等价于 `READ_ONLY_COMPLETE`，`CONDITIONAL` 等价于
  `READ_ONLY_CONDITIONAL`，`BLOCKED` 等价于 `READ_ONLY_BLOCKED`；
- `ELIGIBLE` 只表示某一个明确 operation 满足写前置条件，不代表同设备其他 operation 可写；
- `VERIFIED` 只表示该 operation 的请求、执行、后置观察和审计链完整通过；
- `REVOKED` 表示证据过期、digest 漂移、异常或回滚失败后已自动撤销写资格。

`phase`/`decision` 的持久化格式由 `schemas/RKBWriteTransitionState.schema.json` 定义；
两者必须分列存储，并带 `plan_version`、`updated_at`、`evidence_ids` 和 `reason_codes`。
任何无法通过该 schema 的状态文件都视为 `BLOCKED`。

## 3. W0：只读完工审计

W0 是本计划最重要的阶段。它产出的是“只读是否完成”的证据结论，而不是新功能数量。

### 3.1 审计输入与输出

输入：

- 前一计划各阶段的 schema、artifact manifest、latest index、测试结果和 canary 日志；
- `TargetEvidenceBundle`、RKB snapshot、typed query 和 DiscoveryReport 投影样本；
- `docs/reference/ENGINEERING_STATUS.md`、CI 记录和未关闭问题清单。

输出：

- `docs/review/ROLO_V2_RKB_READ_ONLY_COMPLETION_AUDIT_ZH.md`；
- `artifacts/rkb/audits/<audit_id>/read-only-completion.json`；
- 逐条 gate 的 `PASS/FAIL/BLOCKED`、证据引用、限制、负责人和整改截止条件；
- 明确的 `READ_ONLY_COMPLETE`、`READ_ONLY_CONDITIONAL` 或 `READ_ONLY_BLOCKED` 决策。

### 3.2 只读完工硬门

以下六类硬门必须全部通过；任一 `FAIL` 或 `BLOCKED` 都不能进入 W1。

| 门 | 完工判据 | 必须证据 |
|---|---|---|
| A 契约 | schema、版本、canonicalization、迁移和 query 所有权唯一 | schema 校验、兼容 fixture、实现地图 |
| B 身份/完整性 | 每个 snapshot/fact 可独立验证 robot、fingerprint、probe runner、nonce、digest | 正/负向 envelope 测试、签名验证 artifact |
| C freshness/来源 | observed、declared、verified、inferred、decision 不混淆；事实 TTL 可拒绝过期读取 | stale/future/clock-skew/source-only 测试 |
| D 只读行为 | 固定 argv、allowlist、预算、无写入口；UNKNOWN/UNAVAILABLE 不压缩成成功 | ToolPlan/Conformance、拒绝路径和审计记录 |
| E 数据/恢复 | secret 不进入 RKB/query；latest 原子更新；写失败或损坏不覆盖上一 snapshot | artifact manifest、损坏注入、回滚演练 |
| F 目标证据 | 固定目标机至少完成 identity → runtime → graph → app CLI 的只读 smoke | 目标机 bundle、日志、时间窗和人工复核 |

### 3.3 完工阈值

- 所有 P0/P1 缺陷为零；P2 必须有责任人、期限和不影响只读信任边界的说明；
- 维护的 Python 3.10–3.13 CI、文档检查、ruff、release-check 和 wheel build 全部通过；
- 新增 RKB 测试的正向、负向和边界场景全部纳入 CI，pytest 收集清单有自动断言，不能依赖
  未收集的 examples 测试；
- 固定目标机至少两次独立只读采集的 identity、schema/digest、资源绑定和 freshness policy
  一致；middleware graph、进程和状态等动态字段允许变化，但必须有 revision、差异和限制说明；
- 任一 fingerprint、probe runner、digest、TTL 或 schema mismatch 都能在 query 前拒绝；
- 不能以“无 `/cmd_vel`”“Provider 可注册”或“读到一个数”推断安全、停止或物理正确。

### 3.4 审计结果处理

- `READ_ONLY_COMPLETE`：允许进入 W1，但写能力仍默认关闭；
- `READ_ONLY_CONDITIONAL`：只允许执行明确的补测和文档整改，不允许写 shadow 以外的动作；
- `READ_ONLY_BLOCKED`：回到前一计划的对应阶段，保留旧 latest，禁止新增写接口。

## 4. W1：Write Execution 契约与风险分级冻结

只有 W0 为 `READ_ONLY_COMPLETE` 后，才可冻结 Write Execution 契约。写资格以 operation 为单位授予，
不能以设备或 Provider 为单位整体放开。

### 4.1 风险级别

| 级别 | 允许范围 | 本计划状态 |
|---|---|---|
| R0 | 只读 inspect/status/read | 已在前一计划交付 |
| R1 | 有界、非运动、可幂等、可补偿的配置/会话动作 | 首个可写候选 |
| R2 | reset、calibrate、模式切换或可能中断设备的动作 | 需单独 operation 审批，默认关闭 |
| R3 | 运动、动力电源、固件、不可逆机械动作 | 不在本计划，需独立安全项目 |

首个写 operation 必须同时满足：非运动、影响范围单一、参数有 schema 和范围、具备 timeout/
cancel/idempotency、可观察前后状态、可补偿或可回滚。无法满足任一项则降级为只读或留在
`WRITE_CONTRACT_FROZEN`。

W1 还必须冻结一个具体 pilot，而不是只冻结抽象规则：

```text
pilot_operation_id
pilot_provider / adapter
pilot_target_id
pilot_hardware_resource_id
pilot_route_resource_ids
pilot_input_schema / pilot_postcondition
pilot_compensation_operation
```

当前应用 operation slice 的写操作仍然是 `DEFERRED_WRITE`；在没有明确 R1 pilot 之前，W1
保持 `BLOCKED`，不得进入 W2。

R1 pilot 的选择不是从现有 60 个 R2/R3 应用写操作中降级产生。W1 必须新增一份
`pilot-selection.json`，由 Core/证据、Adapter/硬件、安全/QA 四方共同批准，至少包含：

- 单一 target、单一稳定 hardware resource 和单一 provider；
- 非运动、单资源、可幂等的动作；
- 明确的 pre/post state fact、补偿动作和最大影响范围；
- 失败率、超时、UNKNOWN 和回滚阈值；
- 若当前产品没有满足条件的真实 R1 动作，文件必须明确记录 `NO_ELIGIBLE_PILOT`，计划
  继续保持 `BLOCKED`，不得为了推进阶段而修改风险级别。

### 4.2 SafetyDeclaration 与 QuiescenceLease

用户安全声明和目标状态证据必须是两个独立对象。建议新增版本化 `SafetyDeclaration`：

```text
declaration_id, robot_id, principal, session_id,
operation_id, resource_ids, risk, scope,
max_duration_s, expires_at, workspace,
acknowledgement_text, declaration_sha256
```

它只证明用户/策略允许某个有限范围的动作，不能证明目标当前安全、已停止或物理环境无障碍。
没有有效声明时，写请求返回 `APPROVAL_REQUIRED`。

`principal` 必须映射到已认证的用户/服务身份；`authorization_ref` 必须由 Rolo-owned
authorization issuer 签发，并覆盖 operation、target、resource、参数 digest、风险级别和
过期时间。`acknowledgement_text` 只作为审计文本，不能单独产生授权。撤销、重放、范围不符
和签发者未知均返回 `AUTHORIZATION_INVALID`。

`QuiescenceLease` 必须绑定 `robot_id`、operation、resource、input_sha256、state_revision、
lease owner、`quiescent_since` 和 `expires_at`。获取、释放、过期、锁冲突、cancel 和进程
崩溃后的自动回收都必须有明确状态和审计事件。已有 JSON schema 只能作为迁移输入，不能代替
当前 `src/rolo` 中的真实实现。

### 4.3 写请求与结果的最小契约

```text
WriteRequest:
  request_id, write_session_id, robot_id, target_fingerprint, source_id,
  write_challenge, challenge_expires_at,
  operation_id, hardware_resource_id, route_resource_ids,
  manifest_digest, driver_digest, route_schema_digest,
  authorization_ref, safety_declaration_ref, quiescence_lease_ref,
  state_revision, state_precondition_digest, expires_at, arguments, idempotency_key,
  max_duration_s, cancel_operation, compensation_operation

WriteResult:
  request_id, status, started_at, finished_at,
  pre_evidence_sha256, post_evidence_sha256,
  pre_state_fact_ids, post_state_fact_ids, feedback_fact_ids,
  ack_evidence_ref, cancel_result, evidence_ids,
  compensation_ref, safety_gate_decision, resource_lock_id, limitations
```

`status` 至少区分 `REJECTED`、`ACCEPTED`、`APPLIED`、`VERIFIED`、`UNKNOWN`、`ROLLED_BACK`。
`write_challenge` 必须由 WriteToolSession 为本次写请求签发、一次性消费并绑定
`write_session_id`、target fingerprint、operation、resource 和 arguments digest；它不能复用
只读 Bundle 的 `request_nonce`。目标侧必须原子比较 `state_precondition_digest` 或等价 revision，
防止“读状态 → 状态变化 → 写入”的竞态。没有后置观察时，不能把 `ACCEPTED` 或设备 ACK 转换为
`VERIFIED`；超时后的物理结果必须是 `UNKNOWN`，不能自动重试非幂等动作。

动作型 operation 还需要 `RUNNING`、`CANCEL_REQUESTED`、`CANCELLED`、`CANCEL_FAILED`、
`POSTCHECK_FAILED` 和 `WRITE_REVOKED`。统一失败路径为：

```text
timeout → cancel → stop/compensation → post-read → VERIFIED / UNKNOWN / REVOKED
```

### 4.4 WriteAdapterBundle

`WriteAdapterBundle` 属于 Write Execution 层，由 Provider/adapter 维护；RKB 只保存其 digest、
资格和验证结果。W1 必须新增独立的 `WriteAdapterBundle`，不能把现有只读的
`ApplicationOperationAdapterBundle` 扩展成写入口。Bundle 至少包含：

- exact route identity 和 route schema digest；
- input/output schema、单位和坐标系；
- preconditions/postconditions；
- operation-specific feedback/cancel/compensation route；只有动作型 operation 才要求 stop route；
- resource locks、最大边界和超时；
- authorization、SafetyDeclaration 和 compensation 要求；
- target evidence digest、manifest/driver digest。

只有独立 Write Conformance 通过后，才可产生 `ELIGIBLE` 或 `VERIFIED` 判定。

### 4.5 写前置条件

每个 operation 的 Gate 必须检查：

1. robot identity、target fingerprint、probe runner 和 request nonce 一致；
2. hardware resource identity 稳定，manifest/driver digest 与已审核版本一致；
3. route resource ID、provider、interface/schema digest 和 runtime revision 精确匹配；
4. state/safety 快照在该 operation 的 TTL 内，所需字段不是 `UNKNOWN`；
5. resource lock/quiescence 成功，且没有冲突的运行会话；
6. authorization_ref 和 SafetyDeclaration 未过期，范围覆盖 operation/资源/参数，且可审计到
   用户或策略；
7. 参数通过 schema、范围、单位、坐标系和速率限制校验；实际边界取
   `min(contract, declaration, target_state, driver_hard_limit)`，并记录每个来源；
8. timeout、cancel、幂等键、补偿/回滚策略已经声明并可执行。

## 5. W2：Write Execution 模拟与离线闭环

W2 不连接真实物理设备，只验证 Rolo 的策略、审计和状态机。

### 实施内容

- 新增 write contract schema、`SafetyDeclaration`、`QuiescenceLease` 和 `CapabilityRecord` 的
  写状态字段；
- 新增独立 `WriteToolSession`；现有 read-only `NativeToolSession`、TargetEvidence 和
  `ApplicationOperationAdapterBundle` 保持不可写；
- 让 Provider/Adapter 接口显式区分 `inspect/read` 与 `write`，写入只能由固定 operation
  allowlist 和 provider-owned argv builder 生成，禁止任意 shell、argv 或消息 payload；
- fake backend 支持成功、拒绝、超时、重复请求、异常、补偿和回滚；
- WritePlan/Session 增加 `authorization_ref`、SafetyDeclaration、短 TTL、单 operation
  allowlist、route digest 和 resource lock；旧 read-only ToolPlan 不得调用 write session；
- 所有写结果进入 immutable Episode event，不修改历史事实。

### Exit Gate

- 无 authorization、过期授权、错误 fingerprint、digest 漂移、未知状态和越界参数全部拒绝，
  backend 不产生调用；
- 幂等请求最多产生一个物理意图；非幂等超时不自动重试；
- 模拟执行、后置验证失败和补偿失败都能产生可查询的明确状态；
- provider 只收到经过 schema 校验的结构化参数，不收到任意命令文本；
- 现有只读 CI 全部保持通过，write feature flag 默认关闭。

## 6. W3：目标机 shadow / dry-run

W3 只把真实目标机用于检查写前置条件和参数渲染，不执行物理写入。

### 实施内容

- 在目标机读取最新 identity、manifest、driver、state/safety 和 resource lock；
- 生成固定 operation 的 dry-run plan，显示将要使用的 route、参数、影响范围、回滚动作和
  authorization_ref；
- 将 dry-run 结果记录为 `PLANNED`，不能记录为 `APPLIED`；
- 对目标 runtime、MHS transport、权限和超时做兼容性检查；
- 记录 dry-run 前后的 process/daemon、route graph revision 和设备状态摘要，证明没有 daemon
  副作用或设备写调用；同时必须启用 transport/argv allowlist、driver audit hook 或目标侧
  写调用计数。仅凭前后摘要未观察到变化不等于证明无副作用；无法形成独立证据时，结果必须是
  `BLOCKED`。

### Exit Gate

- 同一 target fingerprint、manifest/driver digest 和稳定 hardware resource 连续通过；
- dry-run 不产生目标状态变化、daemon 副作用或设备写调用；
- 任何前置条件不确定都显示 `BLOCKED/UNKNOWN`，不能自动降级为执行；
- 用户可审阅完整参数和补偿路径后，才允许 W4 使用一次性授权。

## 7. W4：单目标、单 operation 的真实 Write Execution 试点

W4 是唯一允许在本计划中执行一次真实写入的阶段，且必须选择 R1 operation。每次试点只允许
一个固定目标、一个固定设备资源、一个固定 operation 和一个短时授权窗口。

W4 只适用于可幂等、非运动、可补偿的 pilot operation。若 operation 需要移动、急停、动力
电源、校准、reset、模式切换或不可逆机械动作，必须转入独立的
`R3_PHYSICAL_CANARY_PLAN`，不得借用 W4 资格。

### 执行序列

```text
fresh identity/state read
  → acquire resource lock/quiescence
  → issue one authorized bounded write
  → collect immediate result
  → re-read post-state and independent evidence
  → VERIFIED / UNKNOWN / ROLLED_BACK
  → immutable Episode decision
```

### 试点硬门

- 人工确认 operation、资源、参数、风险、窗口和回滚方式；
- 目标证据、state/safety 和 manifest/driver digest 在执行前重新采集；
- route identity、interface/schema digest 和 runtime revision 在执行前重新确认；
- 写入过程有硬 timeout、cancel 语义和单次调用预算；
- post-state 由独立 read/probe 验证，ACK 不能代替验证；
- `UNKNOWN`、超时、锁丢失、digest 漂移或后置验证失败自动撤销该 operation 的写资格；
- 试点结束生成完整 evidence、Episode、用户决策和回滚结果。

### 失败处理

- 可补偿动作执行补偿；补偿失败标记 `UNKNOWN`/`WRITE_REVOKED`，不得猜测设备状态；
- 不允许自动扩大到第二个目标或第二个 operation；
- 保留旧只读 latest 和写前 snapshot，所有异常进入 review queue。

## 8. W5：有限 Write Execution 灰度与扩展评审

W5 不是自动放量，而是按 operation、设备资源和目标逐项扩展。

### 扩展顺序

1. 同一目标、同一 operation、更多参数边界；
2. 同一设备型号、第二个固定目标；
3. 第二个 R1 operation；
4. R2 operation 的独立安全评审和单独 canary；
5. R3 operation 另立项目，不从本计划自动继承资格。

### 每次扩展的准入条件

- 前一批次没有未解释的 `UNKNOWN`、回滚失败、锁冲突或证据漂移；
- 目标和设备身份映射稳定，失败率、超时率和补偿率在预先批准的阈值内；
- 新 operation 有独立 contract、测试、授权范围和回滚演练；
- 工程状态台账记录成熟度变化，不能只更新“支持的 Operation 数量”。

在 W1 统一冻结首版灰度阈值，除安全/QA 书面批准不得放宽：每个扩展批次至少 20 次有效
尝试、0 次安全事件、0 次未解释 `UNKNOWN`、0 次补偿失败、0 次 identity/digest 绕过；超时
率不得超过 5%。任一硬指标失败立即 `WRITE_REVOKED` 并回到 W2/W3 复盘；批次不足 20 次时
只能记为 `CONDITIONAL`，不得扩大范围。拒绝请求不计入“有效尝试”，但必须单独统计原因。

## 9. 物理写入边界：独立 R3_PHYSICAL_CANARY_PLAN

本计划不授权物理动作。前置 Know-how 中的 Probe Level 1–3 应在独立计划中实现，顺序固定为：

```text
Level 1 zero-stop
  → Level 2 bounded rotate / drive_on_heading
  → Level 3 global navigation
```

`R3_PHYSICAL_CANARY_PLAN` 是外部阻塞依赖，不是本计划的隐含交付物；在其独立文档、owner、
场地/设备前置条件、State/Safety contract、测试和回滚证据存在前，W5 不得把任何 R3 操作
转入排期。

### Level 1 zero-stop

zero-stop 应定义为独立 Probe operation（例如 `probe.motion.zero_stop`），不能直接复用
`app.base.stop`。它必须在执行前验证最新 state/safety、精确 route/interface/schema、下游
subscriber、取消/停车路径和用户 SafetyDeclaration；执行中重复发布受限零速度，观察实际速度
收敛到零、位置未越过容差，并以 zero-stop 收尾。只有命令 ACK 而没有 subscriber、速度反馈、
位置复核或收尾停车，不能判为 `VERIFIED`。

### Level 2 bounded motion

bounded motion 应优先使用带 feedback/cancel 的 provider action（例如旋转或按航向短动作），
固定最大角度/距离、速度、加速度和执行时长，并记录前后位姿、cancel、stop 和最终稳定状态。
不得开放通用 `/cmd_vel` 或任意 `ros2 topic pub` payload；参数必须由 adapter 的固定 schema
和 provider-owned argv builder 生成。

### Level 3 global navigation

只有地图、定位、重定位、frame 一致性、全局导航 route、feedback、cancel 和 stop 证据全部
新鲜且独立 conformance 通过后，才可创建 global-navigation Candidate。存在 `/cmd_vel` 和
`/odom` 不能单独提升为全局导航能力。Level 3 需要独立物理评审，不从 W4/W5 自动继承资格。

## 10. 测试与验收命令

### 本地/CI

```bash
uv sync --locked --dev
uv run pytest
uv run ruff check .
python scripts/check_docs.py
```

新增测试建议：

- `tests/test_rkb_read_only_completion.py`：六类只读硬门和完工决策；
- `tests/test_rkb_write_contract.py`：写 schema、状态、授权和前置条件；
- `tests/test_rkb_safety_declaration.py`：声明范围、过期、actor/session 和 digest 绑定；
- `tests/test_rkb_quiescence.py`：lease 获取、冲突、过期、释放和崩溃回收；
- `tests/test_rkb_write_simulation.py`：fake backend、幂等、超时、补偿和回滚；
- `tests/test_rkb_write_shadow.py`：目标 dry-run 无副作用；
- `tests/test_rkb_write_canary.py`：单目标单 operation 的成功、UNKNOWN 和撤销；
- `tests/test_rkb_write_migration.py`：旧只读 artifact 双读、写失败 latest 不变。

RKB-0 必须同步修改 `pyproject.toml` 的 `python_files`，加入 `test_rkb_*.py` 或逐个列出新增
测试，并增加“pytest 实际收集数量/文件名”的断言；否则这些测试不构成 CI 证据。

W0/W1 必须同时生成并校验：`schemas/ReadOnlyCompletionAudit.schema.json`、
`schemas/RKBWriteTransitionState.schema.json`、`schemas/WriteRequest.schema.json` 和
`schemas/WriteResult.schema.json`。Schema 缺失、版本不匹配或无法验证时，阶段状态为 `BLOCKED`。

前置 inventory 的统计必须在 W0 一并校正：文档所称“60 个写 operation”与“23 个 R2 + 35
个 R3”相加为 58，不能用未解释的总数作为完工门槛。

### 禁止的验收替代

- 不能用静态 manifest 替代目标机 state/safety 观察；
- 不能用 ProviderHost 注册替代写资格；
- 不能用设备 ACK、进程返回码或 route 存在替代后置物理观察；
- 不能用 fake backend 结果宣称真机写入安全；
- 不能因只读成熟度为 `STABLE` 就自动把任何写 operation 标成 `ELIGIBLE`。

## 11. 回滚、撤销与审计责任

- 所有新写能力默认 feature flag/off-by-default，且必须有 operation allowlist；
- 任一 identity、digest、TTL、state/safety、权限或 driver 变化立即撤销写资格；
- 写失败不得覆盖只读 snapshot、EvidenceBundle 或 latest index；
- 只读 query 在写阶段仍是独立可信路径，不因写试点失败而降级为未知成功；
- 撤销事件、补偿、回滚、人工确认和最终决策写入 immutable Episode；
- 发布前由 Core/证据、Probe/Query、Adapter/硬件、安全/QA 四方分别确认，不允许单一 Provider
  维护者自行批准自己的写能力。

## 12. 阶段完成定义

| 阶段 | 完成条件 |
|---|---|
| W0 | 六类只读硬门全通过，形成 completion audit 和明确结论 |
| W1 | 具体 R1 pilot、write contract、一次性 challenge、SafetyDeclaration、quiescence、授权和后置验证语义冻结 |
| W2 | 独立 WriteToolSession/fake backend 离线闭环通过，默认无写入口，所有拒绝路径有测试 |
| W3 | 固定目标 dry-run 无副作用，前置条件和参数可审阅 |
| W4 | 一个 R1 operation 在一个目标上完成一次可审计写试点，失败可撤销/补偿 |
| W5 | 扩展批次逐项评审，指标和证据回写台账；不自动开放 R2/R3 |

## 13. 代码所有权与迁移边界

实现排期前必须在 RKB-0 的 implementation map 中冻结以下唯一所有权：

| 责任 | 当前基线/建议落点 | 边界 |
|---|---|---|
| Evidence identity/freshness | `src/rolo/core/models.py`、新增 `src/rolo/rkb/` | 不再把 identity 作为 `ProbeResult.data` 的可选字段 |
| Write request/result | 新增 `src/rolo/write_execution/contracts.py`（结果摘要可由 `src/rolo/rkb/records.py` 持久化） | 不修改只读 `TargetEvidenceBundle` 语义；RKB 只保存结果，不执行请求 |
| SafetyDeclaration/Quiescence | 新增 `src/rolo/write_execution/safety.py` | 授权、租约、状态和审计事件由独立 Write Execution 层持有 |
| Write challenge | 新增 `src/rolo/write_execution/session.py` | 一次性签发/消费，绑定 session、target、operation、resource 和 argument digest |
| Pilot selection | `docs/review` 审批 artifact + implementation map | 没有合格 R1 pilot 时保持 `BLOCKED`，不得调整风险级别 |
| Write session/plan | 新增独立 write session/plan 模块 | 不放宽 `src/rolo/agent_tools/session.py` 的 read-only catalog |
| Provider adapter | provider-owned fixed argv builder | 禁止任意 shell、argv 或消息 payload |
| Write conformance | 新增独立 conformance 模块 | 不复用只读 route-binding conformance 作为写成功证明 |
| Physical canary | 独立 `R3_PHYSICAL_CANARY_PLAN` | zero-stop、bounded motion、global navigation 不从本计划继承资格 |

当前计划状态为 `BLOCKED`。在 W0 产出 `READ_ONLY_COMPLETE` 之前，系统的对外承诺仍是 Probe/RKB 只读；
在 W4 完成前，不得对用户宣称已支持通用可写机器人操作；在独立物理计划完成前，不得宣称
支持 zero-stop、bounded motion 或 global navigation。
