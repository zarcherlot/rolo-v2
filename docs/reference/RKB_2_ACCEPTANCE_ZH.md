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

本工作树的本地系统 Python 未安装 pytest/pydantic，无法在该解释器上宣称测试通过；CI 使用
Python 3.10–3.13 的同一命令矩阵。

## 回滚

关闭 typed query 入口即可继续使用 RKB-1 的 `ReadOnlyKnowledgeBase.identity/facts/get` 和
旧 `DiscoveryReport` 投影；不会修改既有 EvidenceBundle 或 snapshot artifact。
