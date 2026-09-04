<!-- status: draft; authority: plan; owner: rolo maintainers; last_reviewed: 2026-09-04; source_of_truth: ROLO_V2_PHASE_CONSUMPTION_MAX_CONCURRENCY_PLAN_ZH.md -->

# Rolo v2 Probe 基线后的开发计划

本文只定义 Probe 只读基线的冻结、验收和后续工作流。Probe/Trace/Certify 的职责、Agent 交互、
用户旅程和 handoff 规则统一以[阶段规范](ROLO_V2_PROBE_TRACE_CERTIFY_ZH.md)为准；并发拆分
统一以[最大并发计划](ROLO_V2_PHASE_CONSUMPTION_MAX_CONCURRENCY_PLAN_ZH.md)为准。本文不重复
定义 Trace 或写执行协议。

## 1. 基线定义

Probe 基线表示以下内容可重复验证：

- 目标身份、host key、collector、evidence digest 和 freshness；
- MHS ID/Manifest 引用及其来源、digest、状态和限制；
- RKB 只读 snapshot/query、Agent 关联候选和审计链；
- Tool Surface、schema、allowlist、预算、错误码和兼容版本；
- 离线 fixture、固定目标只读 canary、负测结果和回滚指针。

基线不表示设备可写、Manifest 已获 vendor authority、行为正确或具备物理安全证明。基线发布
后任何新增能力必须使用新版本或 feature flag，不得静默改变既有只读语义。

## 2. B0：冻结与 `READ_ONLY_COMPLETE` 审计

### 2.1 冻结输入

锁定代码 commit、schema/API 版本、错误码、目标 profile、collector、fixture、测试清单、
已知限制和责任人，生成 `probe-baseline-manifest.json`。manifest 必须列出所有输入/输出
artifact 的 digest、父子关系和回滚指针。

### 2.2 六类硬门

| 硬门 | 必须证明 | 失败结果 |
|---|---|---|
| A 契约 | schema、版本、canonical digest、迁移和所有权唯一 | `READ_ONLY_BLOCKED` |
| B 身份 | robot、fingerprint、collector、nonce、digest 独立一致 | `READ_ONLY_BLOCKED` |
| C freshness/来源 | observed、declared、verified、inferred、provisional 不混淆 | 过期/冲突值不可读 |
| D 只读行为 | 固定 argv、allowlist、预算和零写入口 | 写调用非零即阻断 |
| E 数据/恢复 | secret 脱敏、append-only、原子 latest、损坏隔离 | 保留上一版本并阻断 |
| F 目标证据 | 至少一个固定目标完成 identity → runtime → graph → application smoke | 缺证据即阻断 |

### 2.3 审计步骤

1. 运行 fixture → evidence bundle → MHS reference → RKB snapshot → typed query → Agent
   `AssociationReport`，保存 digest 和引用；
2. 在固定目标独立采集两次，比较稳定 identity、Manifest/driver digest、资源绑定和 freshness；
3. 执行缺失、过期、fingerprint mismatch、digest drift、schema 冲突、断线、超时、secret
   泄露和未授权访问负测；
4. 检查 Tool Surface、ToolPlan 和 provider call count，证明无 write route、任意 shell 或
   写凭据；
5. 注入损坏 snapshot、latest 指针和进程中断，证明旧 immutable artifact 仍可读取；
6. 生成 `read-only-completion.json`，逐项绑定命令、artifact、日志、责任人和限制。

只有 A–F 全部 PASS 才能写入 `READ_ONLY_COMPLETE`。该状态只允许提交 Trace handoff，不会
自动创建 Trace session 或授予写资格；具体 handoff 规则见[阶段规范](ROLO_V2_PROBE_TRACE_CERTIFY_ZH.md)。

## 3. 基线后的并行工作流

| 工作流 | 目标 | 退出条件 |
|---|---|---|
| T1 Evidence/RKB | 双读兼容、freshness/provenance、损坏恢复和负测 | 本地、CI、目标机拒绝码一致 |
| T2 Vendor MHS | Manifest schema、来源/digest、canonical route 和撤销 | vendor-like 与无 Manifest fixture 均可审计 |
| T3 rolo-vis | 目标、证据图、限制、关联候选和 review receipt 只读展示 | fixture → API → GUI → receipt 可重放 |
| T4 Agent association | `ProbeEvidenceView`、`EvidenceRequest`、proposal → 补证 → final review | Agent 不能伪造事实或授权 |
| T5 Trace/Write simulation | 独立 session、WriteRequest、dry-run、cancel、post-check 和补偿 fake | feature flag 默认关闭，拒绝路径全通过 |
| T6 CI/canary | docs/schema/lint/test collection、固定目标两次采集和发布包 | CI、fixture、canary、release packet 可重放 |

T1–T6 的依赖、并发关系和责任边界不在本文重复；详见[最大并发计划](ROLO_V2_PHASE_CONSUMPTION_MAX_CONCURRENCY_PLAN_ZH.md)。

## 4. 集成门

- **G1 Offline compatibility**：manifest、schema、错误码和来源 authority 通过校验；旧
  EvidenceBundle/DiscoveryReport 可读，新写入格式不覆盖旧 artifact。
- **G2 Fixed-target read-only**：固定目标至少两次采集的身份、digest、资源绑定和 freshness
  可比较；MHS 缺失、断线、漂移和过期均保留限制；写调用为 0。
- **G3 User review**：页面/API/Agent 看到相同 robot、snapshot digest、evidence IDs 和限制；
  用户确认只生成带 scope/TTL 的 receipt。
- **G4 Read-only completion**：G1–G3 和六类硬门全部通过，才允许提交 Trace handoff。

Trace 的只读执行、现场 experimental 写入和生产化 Write Execution 不是本门自动动作，分别
遵循阶段规范和[受控写执行计划](ROLO_V2_RKB_WRITE_TRANSITION_PLAN_ZH.md)。物理动作、无人
值守和 R3 canary 另立项目。

## 5. 交付物与回滚

```text
probe-baseline-manifest.json
read-only-completion.json
artifact-manifest.json
offline-replay-report.json
landerpi-canary-1.json
landerpi-canary-2.json
negative-test-report.json
no-write-audit.jsonl
recovery-report.json
human-review.md
```

所有产物必须绑定 target fingerprint、相关 digest、schema version、时间窗、来源和限制。
新增产物失败、schema/digest/fingerprint/freshness 漂移或负测失败时，只撤销新 latest 指针，
保留上一份完整 snapshot/evidence；不得覆盖或删除旧 artifact。

## 6. 验收命令

```powershell
python scripts/check_docs.py
uv run pytest
uv run ruff check .
uv run rolo release-check --require-artifacts
```

依赖、目标机或人工授权缺失时状态为 `BLOCKED`，不能用“代码已创建”替代验收通过。

