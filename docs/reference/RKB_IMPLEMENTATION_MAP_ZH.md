<!-- status: active; authority: reference; owner: rolo maintainers; last_reviewed: 2026-09-02 -->

# RKB v2 实现地图

本表冻结每个 RKB 模型的唯一代码所有权，避免在 Probe、Provider、CLI 或 Agent 层重复定义
事实。RKB-0 只建立边界；后续阶段必须沿此表扩展。

| 契约对象 | 唯一代码所有者 | 输入 | 输出/边界 |
|---|---|---|---|
| `ProbeResult` v2 metadata | `src/rolo/core/models.py` | Probe 采集器 | 只读 `identity/access/fresh_until` 元数据，不改变现有 `data` |
| Target identity / bundle verification | `src/rolo/stages/probe/target_evidence.py` | `TargetEvidenceBundle`、deployment、request | 校验 fingerprint、collector、nonce、digest、签名和 replay；输出 verified probes |
| `SnapshotIdentity`、`Fact`、`EvidenceEnvelope` | `src/rolo/rkb/models.py` | verified probe/bundle | canonical envelope、fact provenance、freshness 和 digest |
| typed read-only query | `src/rolo/rkb/query.py`; `src/rolo/rkb/read_models.py` | verified snapshot reference | 分层 identity/runtime/hardware/middleware/application/capability/state_safety 查询；不得读取未校验原始 bundle |
| MHS device manifest/provider | `src/rolo/mhs_hardware.py` | manifest + bounded backend | canonical `mhs://<device>/<capability>`，仅 inspect/status/read |
| MHS example | `examples/mhs-sensor/` | fake backend | 兼容示例，不进入生产 release authority |
| JSON schema | `schemas/RobotEvidenceEnvelope.schema.json`、`schemas/RobotKnowledgeBase.schema.json` | Pydantic/契约冻结 | 版本化 artifact shape；schema 不授予 capability |
| CI/test collection | `pyproject.toml`、`.github/workflows/ci.yml` | Python 3.10–3.13 + dev deps | 统一 lint、docs、targeted/full probe checks |

## 读取方向

```text
TargetProfile → Probe → TargetEvidenceBundle
             → verified ProbeResult → RKB EvidenceEnvelope → typed read-only query
             ↘ DiscoveryReport（现有兼容投影，不是 RKB 权威写入格式）
```

MHS manifest/driver digest、target identity、route、时间和 evidence IDs 只能作为 RKB
provenance 输入，不能绕过 Rolo Gate。未来新增 hardware、middleware、application 或
capability read model 时，必须新增独立 schema、正/负/边界测试和本表条目。
