<!-- status: active; authority: reference; owner: rolo maintainers; last_reviewed: 2026-09-02 -->

# RKB-1 Evidence Envelope 验收记录

RKB-1 在 `rkb-1` worktree 中交付 Evidence Envelope 与兼容读取。新路径只生成只读
`robot-snapshot/v1`，旧 `ProbeResult`、`TargetEvidenceBundle` 和 `DiscoveryReport` 字段不被
删除或回写。

## 交付边界

- `src/rolo/rkb/models.py`：`SnapshotIdentity`、`Fact`、`EvidenceEnvelope`、`Snapshot`；
- `src/rolo/rkb/canonical.py`：canonical JSON、SHA-256 payload digest、RFC 6901 JSON Pointer；
- `src/rolo/rkb/migration.py`：v2/v3 Bundle 和 Probe 的只读迁移、旧 Probe 投影；
- `src/rolo/rkb/validation.py`：identity、access、source、digest、freshness、可选 HMAC 验证；
- `schemas/RobotSnapshot.schema.json`：`robot-snapshot/v1` 的独立 schema；知识库 schema 同时
  接受新 snapshots 与旧 envelopes；
- `ProbeResult.to_rkb_snapshot()` / `to_evidence_envelope()`：版本化兼容读取入口。

迁移会保留 `UNKNOWN`/`UNAVAILABLE` 状态；敏感字段只保留 `<REDACTED>` 占位，过大的自由
字符串不会进入 envelope。旧 artifact 永不被覆盖。

## 验收命令

```powershell
.venv\Scripts\python.exe -m pytest --basetemp .pytest-tmp
.venv\Scripts\ruff.exe check src/rolo/rkb src/rolo/core/models.py tests/test_rkb_compatibility.py
python -m compileall -q src tests
```

当前开发机结果：`72 passed, 1 skipped`（仓库配置收集的测试）；RKB-1 定向测试 14 项通过。
目标机 `192.168.10.167` 已完成代码上传和 `compileall`；因设备 Python 3.11 环境缺少
`pydantic` 且无法完成依赖安装，目标机 pytest 状态保持 `BLOCKED`，不宣称真机测试通过。

## 回滚

停止调用 `rolo.rkb.migration` 新入口即可回到既有 Probe/Bundle/DiscoveryReport 读路径；
删除或撤销 RKB snapshot 生成入口不会改变任何旧 artifact。
