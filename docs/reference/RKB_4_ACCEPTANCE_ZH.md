<!-- status: active; authority: reference; owner: rolo maintainers; last_reviewed: 2026-09-02 -->

# RKB-4 Episode 元数据与灰度迁移验收

RKB-4 在 RKB-1/2/3 的只读 snapshot、typed query 和 MHS canary 之上增加
metadata-only Episode。Episode 只索引 Probe run、bundle/report/snapshot 引用、digest、
目标身份和有限生命周期事件；不保存原始 telemetry、命令 payload、secret、模型上下文，
也不实现 Diagnose、Certify、replay、remediation 或设备写入。

## 实施入口

- `src/rolo/rkb/episodes.py`：Episode metadata schema、typed-query 投影、双读兼容和原子发布/回滚；
- `src/rolo/commands/lifecycle.py`：Probe 验证成功后自动 append snapshot 和 metadata-only Episode；
- `scripts/rkb4_episode_canary.py`：从已验证 `robot-snapshot/v1` 运行只读 Episode canary；
- `schemas/RKBEpisodeMetadata.schema.json`：`rkb-episode-metadata/v1` 契约；
- `schemas/RKBEpisodeQueryPage.schema.json`：`rkb-episode-query-page/v1` 分页契约；
- `tests/test_rkb_episode.py`：正向、身份/父 digest、幂等、恢复、分页、retention、失败不移动 latest、回滚、敏感字段拒绝和 legacy 双读测试。

## 双读一写

旧 `TargetEvidenceBundle`/`DiscoveryReport` 通过 `EpisodeStore.read_legacy_bundle()` 和
`read_legacy_report()` 只读解析；RKB-4 新写入只允许 `EpisodeStore.publish()` 生成
`episodes/<robot>/<episode>/records/<digest>.json` 和原子 `latest.json`。旧 artifact 不回写，
发布失败不会替换既有 latest，回滚只切换指针到已验证的上一份不可变记录。
EpisodeStore 同时持久化跨进程指标，支持 latest 损坏后的记录扫描恢复、按 identity/source/freshness/status
分页查询、同一 `probe_run_id` 的幂等重放和受限 retention；retention 不删除当前 latest。

## 验收命令

```powershell
$py = 'C:\Users\zarch\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$env:PYTHONPATH = (Resolve-Path 'src').Path
& $py -m ruff check src/rolo/rkb/episodes.py scripts/rkb4_episode_canary.py tests/test_rkb_episode.py
& $py -m pytest -q --basetemp (Resolve-Path '.pytest-tmp').Path tests/test_rkb_episode.py
& $py -m compileall -q src tests scripts/rkb4_episode_canary.py
python scripts/check_docs.py
```

## 灰度边界

本阶段首个闭环是离线 snapshot → typed query → Episode metadata → latest/rollback。固定
LanderPi 的 identity → runtime → graph → app 只读 smoke 必须使用当前 RKB-3 目标 fingerprint，
并在发布前记录 artifact；任何 MHS 观察结果仍只代表 generic observer 的 `OBSERVED` 事实，
不升级为物理安全、行为正确或写授权。

工程状态在完成本地拒绝路径和真机 smoke 前保持 `PARTIAL/E2`；本次 LanderPi smoke 已完成后提升为 `PARTIAL/E3`，但因 graph/app 为 `UNKNOWN` 仍不得改成 `STABLE`。
