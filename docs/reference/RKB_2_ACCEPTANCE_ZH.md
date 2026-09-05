<!-- status: active; authority: reference; owner: rolo maintainers; last_reviewed: 2026-09-02 -->

# RKB-2 分层只读模型与 typed query 验收记录

RKB-2 在 RKB-1 的 `robot-snapshot/v1` 上增加分层、只读、带 provenance 的 typed query。
查询只接受已验证 snapshot（或其 digest/fingerprint reference），不会暴露原始 bundle，也
不会新增写 Operation。

## 交付边界

- `src/rolo/rkb/read_models.py`：identity、runtime、hardware、middleware、executable、
  capability、state-safety 的显式模型和共享查询结果元数据；
- `src/rolo/rkb/query.py`：`robot.identity()`、`os.runtime.status()`、
  `hw.inventory.scan()`、`middleware.graph.snapshot()`、`middleware.route.inspect()`、
  `app.executable.inspect()`、`capability.get()`、`state_safety.snapshot()`；
- 所有结果携带 `evidence_ids`、`observed_at`、`fresh_until`、`limitations`、
  `status_reason`，并在 digest、fingerprint 或 freshness 不匹配时 fail-closed；
- hardware 仅有路径时标记 `UNSTABLE`；静态 capability 只能是
  `DISCOVERED_UNVERIFIED`；state/safety 缺失字段保持 `UNKNOWN`；middleware endpoint 与
  relationship 分离；查询排序和分页稳定；
- `tests/test_rkb_typed_queries.py` 覆盖成功、stale、fingerprint mismatch、静态能力降级、
  缺 route 和 UNKNOWN safety 拒绝/边界路径。

## 验收命令

```powershell
uv sync --locked --dev
uv run pytest tests/test_rkb_envelope.py tests/test_rkb_compatibility.py tests/test_rkb_typed_queries.py
uv run ruff check src/rolo/rkb tests/test_rkb_typed_queries.py
python scripts/check_docs.py
```

本地 bundled Python 已通过 RKB-2 目标测试、全量 pytest、compileall、ruff 与文档检查。
固定 LanderPi（`192.168.10.167`，严格 ECDSA host key）也完成了以下只读验收：

```text
target-evidence collect --robot-id mentorpi --deployment-config .../mentorpi.json
  status=VERIFIED, access=READ_ONLY, mode=local
python scripts/rkb2_landerpi_smoke.py bundle.json --deployment-config .../mentorpi.json --live
  deployment/HMAC verification + typed query; fresh live canary
pytest (RKB-1 envelope/compatibility + RKB-2 typed queries/storage/schema): passed
pytest (full suite) + compileall src tests: passed, 1 skipped
rkb2_landerpi_smoke.py --live (fresh probe runner bundle): exit 0;
  bundle payload_sha256=0b2bbd5a075fd8435f9c7a2727e4d1f1ecb67b8143036fa1559324cf33f2ed40;
  snapshot digest=089a70877ab1b01e2b214f830d467289928016dcb38765b45b27e72acbbdb6a6
```

实机结果保持 fail-closed 语义：硬件路径型资源标记 `UNSTABLE`，网络/PCI 枚举不可用；
middleware 图因运行时采样未稳定及缺少 RMW/schema/provider 信息保持 `UNKNOWN`；
state safety 没有观察证据，状态为 `UNKNOWN`。这些是目标机证据限制，不是查询层推断。

本轮 verifier 加固后，容器内旧 Bundle 仍按预期被拒绝为 `payload hash mismatch`；协调冲突的
临时调试进程后，重新 probe runner → HMAC/deployment verification → snapshot → typed query
的 live 链路已 exit 0。长期 bringup 进程未被停止；middleware/state-safety 的保守状态仍按
目标机实际观测记录，不将 UNKNOWN 误报为运行成功。

## 加固记录

- smoke runner 现在必须接收 pinned deployment config，并调用
  `verified_bundle_to_snapshot()`；缺少 deployment/HMAC 验证不能进入 typed query；
- snapshot 完整性与 identity freshness 分开校验，事实 freshness 按查询层处理；过期层返回
  `STALE` 且不暴露 value，无关层过期不会污染当前查询；
- 多个同层 fact 的列表型资源按事实合并，不再静默覆盖或在合并过程中修改输入事实；
- typed result 与主要 read model 带独立 schema version，runtime projection 只输出显式字段；
- middleware selector 使用 route/node/endpoint 的精确 token 匹配，避免模糊 substring 命中。

## 存储、Schema 与运行基线

- `src/rolo/rkb/storage.py` 提供 append-only snapshot、atomic `latest.json`、损坏 artifact
  隔离/回退、重启后 digest 校验，以及持久化 `metrics.json`；
- `schemas/RKBTypedReadModels.schema.json` 与 `tests/test_rkb_schema_roundtrip.py` 固化 typed
  result 的版本和 round-trip 入口；
- `scripts/rkb2_canary.py` 是一次 bounded、只读、可由 cron/systemd 调度的 latest/freshness
  检查；`scripts/rkb2_capacity_baseline.py --count N` 输出 bytes、读写吞吐和拒绝/损坏指标。

## 回滚

关闭 typed query 入口即可继续使用 RKB-1 的 `ReadOnlyKnowledgeBase.identity/facts/get` 和
旧 `DiscoveryReport` 投影；不会修改既有 EvidenceBundle 或 snapshot artifact。
