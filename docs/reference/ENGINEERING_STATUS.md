<!-- status: active; authority: reference; owner: rolo maintainers; last_reviewed: 2026-09-03; last_synced_commit: 1ca52e834299936691beb2f622845ee444774102 -->

# Rolo v2 工程状态

本台账只记录当前 Probe-first 产品链；Trace、Certify、MCP 和 Web UI 不属于本轮交付。
`STABLE` 表示边界和拒绝路径有测试，`PARTIAL` 表示仍需真实目标机或平台证据，`DRAFT`
表示仅有设计。证据等级：E0 文档、E1 单测、E2 离线闭环、E3 固定目标机、E4 真机闭环。

| feature_id | maturity | evidence | user surface | code_paths | test_paths | known limits |
|---|---|---|---|---|---|---|
| FEAT-PROBE-ENROLLMENT | STABLE | E4 | `rolo target profile`; `rolo target inspect-profile` | `src/rolo/targets/profiles.py`; `src/rolo/targets/credentials.py`; `src/rolo/targets/executor.py` | `tests/test_target_credentials.py`; `tests/test_target_executors.py`; `tests/test_product_cli_v2.py` | 需要用户首次批准 host key；密码只用于一次性置备，运行时不接受密码 |
| FEAT-PROBE-EVIDENCE | STABLE | E4 | `rolo probe`; `robotctl probe start` | `src/rolo/stages/probe/target_evidence.py`; `src/rolo/stages/probe/active_discovery.py`; `src/rolo/stages/probe/discovery.py` | `tests/test_probe_evidence_contract.py`; `tests/test_product_cli_v2.py` | Evidence 是采集时刻事实；可携带签名 source snapshot，但不证明物理安全或行为正确性 |
| FEAT-PROBE-NATIVE-SURFACE | STABLE | E4 | `rolo target tool-surface --profile` | `src/rolo/agent_tools/native_tools.py`; `src/rolo/agent_tools/session_factory.py` | `tests/test_agent_native_tools.py`; `tests/test_probe_session_factory.py` | 当前为四类 family 的只读 surface；缺失命令返回 UNAVAILABLE |
| FEAT-PROBE-TOOL-PLAN | STABLE | E4 | `rolo target tool-plan --profile PLAN.json` | `src/rolo/agent_tools/planning.py`; `src/rolo/agent_tools/session.py` | `tests/test_tool_planning.py`; `tests/test_native_tool_session.py`; `tests/test_product_cli_v2.py` | Agent 只能规划，Rolo 校验 digest、目标、allowlist、预算和只读模式 |
| FEAT-PROBE-SSH-RUNNER | STABLE | E4 | profile-bound remote Native Tool execution | `src/rolo/targets/executor.py`; `src/rolo/agent_tools/native_tools.py` | `tests/test_target_executors.py`; `tests/test_agent_native_tools.py`; `tests/test_product_cli_v2.py` | Provider 可能依赖目标 OS/Middleware setup、Python packages 和 runtime libraries；环境不全时明确失败 |
| FEAT-PROBE-CONFORMANCE | STABLE | E4 | Tool Surface / ToolPlan conformance artifacts | `src/rolo/agent_tools/conformance.py`; `src/rolo/product_cli.py` | `tests/test_tool_conformance.py`; `tests/test_native_tool_session.py`; `tests/test_product_cli_v2.py` | Conformance 只固化当前 Tool Surface；不声明 Trace/Certify 或 release authority |
| FEAT-APPLICATION-GAP-BUNDLE | STABLE | E4 | `rolo target application-bundle --profile --application` | `src/rolo/stages/probe/application.py`; `src/rolo/product_cli.py` | `tests/test_application_bundles.py` | MVP 只覆盖 startup/navigation/mapping/manipulation；当前目标未观测到 map route；route presence 不证明应用行为正确；无证据时 Conformance 明确失败 |
| FEAT-APPLICATION-OPERATION-SLICE | STABLE | E4 | `rolo target application-operation --profile --operation` | `src/rolo/stages/probe/application.py`; `src/rolo/product_cli.py` | `tests/test_application_bundles.py` | v1 137 项中先实现 32 个只读 route-binding rules；当前 bundle 是 route-level candidate，不等同于行为/结果验证；R2/R3 明确 DEFERRED |
| FEAT-RKB-EVIDENCE-ENVELOPE | PARTIAL | E4 | typed read-only envelope API | `src/rolo/rkb/models.py`; `src/rolo/rkb/canonical.py`; `src/rolo/rkb/migration.py`; `src/rolo/rkb/validation.py`; `src/rolo/stages/probe/target_evidence.py`; `schemas/RobotSnapshot.schema.json` | `tests/test_rkb_envelope.py`; `tests/test_rkb_contract_baseline.py`; `tests/test_rkb_compatibility.py` | RKB-1 已覆盖 identity/digest/freshness/source/access、HMAC 前置校验、v2/v3 兼容迁移与 DiscoveryReport 投影；开发机 74 passed/1 skipped，目标机 75 passed；尚无真机 Episode 持久化 |
| FEAT-RKB-TYPED-READ-MODELS | PARTIAL | E3 | `robot.identity`; `os.runtime.status`; `hw.inventory.scan`; `middleware.*`; `app.executable.inspect`; `capability.get`; `state_safety.snapshot` | `src/rolo/rkb/read_models.py`; `src/rolo/rkb/query.py`; `scripts/rkb2_landerpi_smoke.py` | `tests/test_rkb_typed_queries.py`; RKB-1 compatibility tests; LanderPi smoke | 固定 LanderPi `mentorpi` 已完成 fresh collector VERIFIED → bundle → snapshot → typed query `--live`（exit 0）；旧 Bundle 的 payload hash mismatch 仍 fail-closed；query 对 digest/fingerprint/freshness fail-closed，硬件枚举受目标机能力限制，middleware graph 与 state safety 仍保守为 UNKNOWN/观察投影 |
| FEAT-MHS-READONLY-PROVIDER | PARTIAL | E3 | MHS manifest/inspect/status/read SPI；bounded canary | `src/rolo/mhs_hardware.py`; `src/rolo/mhs_linux.py`; `scripts/mhs_rkb_canary.py`; `scripts/mhs_linux_canary.py`; `examples/mhs-sensor/` | `tests/test_mhs_hardware.py`; `tests/test_mhs_linux.py`; `tests/test_rkb_mhs_readonly.py` | 固定 LanderPi 已完成新 rkb-3 Linux observer 的 inspect/status/read canary，artifact=`docs/validation/RKB3_LANDERPI_MHS_CANARY_20260902.json`；尚无厂商 MHS actuator/controller driver，写能力（reset/calibrate/setpoint/power）不属于当前 v2 |
| FEAT-RKB-EPISODE-METADATA | STABLE | E4 | metadata-only Episode publish/load/rollback/query canary | `src/rolo/rkb/episodes.py`; `src/rolo/commands/lifecycle.py`; `src/rolo/rkb/alerts.py`; `src/rolo/rkb/keyring.py`; `src/rolo/rkb/schema_registry.py`; `src/rolo/rkb/scheduler.py`; `src/rolo/rkb/vault.py`; `scripts/rkb4_episode_canary.py`; `scripts/rkb4_fault_canary.py`; `scripts/rkb4_concurrency_canary.py`; `scripts/rkb4_migration_canary.py`; `scripts/rkb4_kill9_canary.py`; `schemas/RKBEpisodeMetadata.schema.json` | `tests/test_rkb_episode.py`; `tests/test_rkb4_hardening.py`; `docs/validation/RKB4_LANDERPI_SMOKE_20260903.json`; `docs/validation/RKB4_LANDERPI_POSTREBOOT_20260903.json`; `docs/validation/RKB4_LANDERPI_KILL9_20260903.json`; `docs/validation/RKB4_LANDERPI_STORAGE_CANARY_20260903.json`; `docs/validation/RKB4_LANDERPI_MIGRATION_CANARY_20260903.json`; `docs/validation/RKB4_HARDENING_CANARY_20260903.json` | LanderPi 上真实 MHS → snapshot → Episode 只读链路、操作员 reboot 后复验和 Episode publisher `kill -9` 恢复均已通过；合成 snapshot 已通过 fault recovery、跨进程并发和 migration rollback；告警策略、外部 vault resolver、周期调度适配器和 schema 兼容/弃用策略已有拒绝路径测试。STABLE 仅适用于已 enrolled mentorpi 的 metadata-only RKB-4 surface；设备写入、物理行为、安全结论以及部署侧 notification/vault/retirement transport 不在本 gate 内 |
| FEAT-RKB-0-BASELINE | STABLE | E1 | RKB 契约与依赖验收 | `docs/architecture/RKB_CONTRACT_DECISIONS_ZH.md`; `docs/reference/RKB_IMPLEMENTATION_MAP_ZH.md`; `docs/reference/RKB_DEPENDENCIES_ZH.md` | `tests/test_rkb_contract_baseline.py` | RKB-0 契约、schema、依赖入口和拒绝路径已冻结；真机 canary 与后续 read model 属于 RKB-1/RKB-3，尚未开始 |
| FEAT-PROBE-BASELINE | PARTIAL | E2 | B0 baseline manifest、artifact index、W0 read-only completion | `src/rolo/probe_baseline.py`; `scripts/probe_baseline.py`; `schemas/ProbeBaselineManifest.schema.json`; `schemas/ProbeBaselineArtifactIndex.schema.json`; `schemas/ReadOnlyCompletion.schema.json` | `tests/test_probe_baseline.py`; `scripts/probe_baseline.py` | 离线 baseline 可重放并 fail-closed 检测 schema/commit/artifact drift；READ_ONLY_COMPLETE 仍需固定目标两次 canary、人工责任确认和归档 no-write 证据 |

## 可信度边界

- Agent 的自然语言、候选工具和计划不是事实；Rolo 的 descriptor、session、digest、结果
  artifact 和 Conformance 才是可审计边界。
- Codex 已知的目标 OS/Middleware CLI 不重复包装；Rolo 只负责固定 argv、目标绑定、环境边界和证据。
- 当 Codex 无法稳定调用目标 OS/Middleware 或 application 的底层接口时，才值得新增 Adapter bundle；新增能力必须
  经过 bounded Probe、TargetEvidence、Adapter bundle 和独立 Conformance。
- 真实目标机验证当前覆盖 mentorpi 的当前 OS/Middleware 只读证据；provider-specific coverage
  仍不是产品级全平台承诺。写操作、驱动变更和
  物理行为验收仍需单独授权。

## 同步规则

修改 `src/rolo/targets/`、`src/rolo/agent_tools/`、目标证据、公共 CLI 或 schema 时，必须
更新本表和对应测试路径。只要证据等级没有提升，不得把 `PARTIAL` 自动改成 `STABLE`。
