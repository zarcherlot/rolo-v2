<!-- status: active; authority: reference; owner: rolo maintainers; last_reviewed: 2026-09-03 -->

# RKB-4 Episode 元数据与灰度迁移验收

RKB-4 在 RKB-1/2/3 的只读 snapshot、typed query 和 MHS canary 之上增加
metadata-only Episode。Episode 只索引 Probe run、bundle/report/snapshot 引用、digest、
目标身份和有限生命周期事件；不保存原始 telemetry、命令 payload、secret、模型上下文，
也不实现 Diagnose、Certify、replay、remediation 或设备写入。

## 实施入口

- `src/rolo/rkb/episodes.py`：Episode metadata schema、typed-query 投影、双读兼容和原子发布/回滚；
- `src/rolo/commands/lifecycle.py`：Probe 验证成功后自动 append snapshot 和 metadata-only Episode；
- `scripts/rkb4_episode_canary.py`：从已验证 `robot-snapshot/v1` 运行只读 Episode canary；
- `scripts/rkb4_fault_canary.py`：在不调用设备写路由的前提下验证 latest 恢复和损坏 record 隔离；
- `scripts/rkb4_concurrency_canary.py`：以两个独立进程验证并发 Episode 发布与指标合并；
- `scripts/rkb4_migration_canary.py`：验证迁移式新旧 Episode 发布、父 digest 绑定和 rollback 指针切换；
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

本轮工程加固还包括：指标写入按进程增量在独立锁下合并，避免并发发布丢计数；record digest
校验失败会移入 `corrupt-episodes/` 保留审计；retention 在 latest 锁内重新读取指针；
`tests/test_rkb_episode.py` 覆盖两个进程并发发布、指标合并和 digest 损坏隔离。LanderPi
目标机 storage canary 记录在 `docs/validation/RKB4_LANDERPI_STORAGE_CANARY_20260903.json`；
该 canary 使用目标 fingerprint 绑定的合成 snapshot，不替代真实 MHS provider 采集。
迁移 rollback canary 记录在 `docs/validation/RKB4_LANDERPI_MIGRATION_CANARY_20260903.json`，
已验证新旧 digest 父子绑定、latest 指针回退和只读边界。操作员完成重启后，已重新执行
真实 MHS → snapshot → Episode canary，并记录在 `docs/validation/RKB4_LANDERPI_POSTREBOOT_20260903.json`；
同时在 MentorPi 容器内观察到 ROS2 graph、service、topic 及 `/robot_api` 等应用 route presence。
Episode 进程 `kill -9` 后的持久化恢复仍需最后维护窗口，不能据此提升为 `STABLE`。

## 验收命令

```powershell
$py = 'C:\Users\zarch\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$env:PYTHONPATH = (Resolve-Path 'src').Path
& $py -m ruff check src/rolo/rkb/episodes.py scripts/rkb4_episode_canary.py scripts/rkb4_fault_canary.py scripts/rkb4_concurrency_canary.py scripts/rkb4_migration_canary.py tests/test_rkb_episode.py
& $py -m pytest -q --basetemp (Resolve-Path '.pytest-tmp').Path tests/test_rkb_episode.py
& $py -m compileall -q src tests scripts/rkb4_episode_canary.py scripts/rkb4_fault_canary.py scripts/rkb4_concurrency_canary.py scripts/rkb4_migration_canary.py
python scripts/check_docs.py
```

存储 fault canary（仅对指定 artifact root 做故障注入，不访问设备写接口）：

```powershell
& $py scripts/rkb4_fault_canary.py SNAPSHOT.json --artifact-root .rkb4-fault-artifacts --probe-run-id local-fault
```

并发发布 canary：

```powershell
& $py scripts/rkb4_concurrency_canary.py SNAPSHOT.json --artifact-root .rkb4-concurrency-artifacts --probe-run-id local-concurrency
```

迁移 rollback canary：

```powershell
& $py scripts/rkb4_migration_canary.py SNAPSHOT.json --artifact-root .rkb4-migration-artifacts --probe-run-id local-migration
```

## 灰度边界

本阶段首个闭环是离线 snapshot → typed query → Episode metadata → latest/rollback。固定
LanderPi 的 identity → runtime → graph → app 只读 smoke 必须使用当前 RKB-3 目标 fingerprint，
并在发布前记录 artifact；任何 MHS 观察结果仍只代表 generic observer 的 `OBSERVED` 事实，
不升级为物理安全、行为正确或写授权。

工程状态在完成本地拒绝路径和真机 smoke 前保持 `PARTIAL/E2`；本次 LanderPi smoke 与操作员
重启后复验已达到 `PARTIAL/E3`。ROS2/app 目前有 route presence 证据，但 typed graph/state-safety
仍未由 MHS snapshot 提供，且 kill-9 持久化恢复未闭环，因此不得改成 `STABLE`。
