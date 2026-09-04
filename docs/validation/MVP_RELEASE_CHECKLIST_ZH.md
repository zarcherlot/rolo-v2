status: active
authority: guide

# Rolo V2 MVP Release Gate 清单

该清单对应 `landerpi-mvp-journey` 发布候选（M7）。所有离线步骤必须在干净 checkout 中可重复；真机步骤必须保存目标指纹和 artifact index。

## 自动门禁（CI 必须通过）

- [ ] `uv run ruff check src/rolo/mvp scripts/mvp_release_gate.py tests/test_mvp_journey.py tests/test_mvp_release_gate.py`
- [ ] `uv run pytest -q tests/test_mvp_journey.py tests/test_mvp_release_gate.py`
- [ ] `uv run python scripts/mvp_release_gate.py --suite examples/mapping-10.json`
- [ ] 10-case suite digest 可重算，报告结论为 `PASS`，每个 case 都有 evidence 和 64 位 artifact digest。
- [ ] `artifact-index.json` 中每个路径均为 index 同目录下的普通文件，且 SHA-256 校验通过。
- [ ] Trace 离线 replay 覆盖成功、工具失败→诊断→恢复，状态分别为 `COMPLETED`；不允许调用未被 Probe 验证的 Tool。

## LanderPi 真机门禁（发布前执行）

- [ ] 在 `mentorpi` 上重新执行 Probe，记录 `target_fingerprint`、catalog/snapshot digest、采样时间和 freshness。
- [ ] 运行 `mapping-10`，10 条结果均可关联到独立 `run_id`、`case_id`、operation/evidence ID 和 artifact digest。
- [ ] 归档 `trace-session.json`、`trace-evidence-bundle.json`、Certify JSON/Markdown 报告与 `artifact-index.json`；下载后重新执行 digest 校验。
- [ ] 至少完成一次断连或 Tool 失败恢复演练，并确认失败时进入 `BLOCKED`/`UNKNOWN`，没有绕过 allowlist 的调用。
- [ ] 仅在现场操作员确认、`SUPERVISED_FIELD_DEBUG` 和安全声明齐全时运行实验写能力；默认保持只读。

## 发布与回滚

- [ ] 发布包通过 `rolo release-check --require-artifacts`，版本兼容矩阵和变更记录已更新。
- [ ] 将真机 evidence index 与构建版本绑定并签名（签名系统由部署环境提供）；签名缺失时发布状态为 `CONDITIONAL`。
- [ ] 保留上一稳定版本及其 catalog/snapshot digest；升级失败时按 `docs/validation/LANDERPI_MVP_JOURNEY_RUNBOOK_ZH.md` 的回滚步骤恢复，并重新运行只读 Probe。
- [ ] 发布说明列出已知限制：无真实 mapping capability 时 Trace 必须阻断，过期 catalog 不可消费，MVP 不支持 `UNATTENDED_REMOTE`。

## 门禁记录

发布负责人将 CI run URL、LanderPi 主机名、目标指纹、suite/catalog/snapshot/artifact digest、结论和限制写入发布工单；任何 `FAIL`、`BLOCKED` 或 `UNKNOWN` 均不得标记为 `PASS`。
