status: active
authority: guide

# Rolo V2 MVP Release Gate 清单

该清单对应 `landerpi-mvp-journey` 发布候选（M7）。所有离线步骤必须在干净 checkout 中可重复；真机步骤必须保存目标指纹和 artifact index。

## 自动门禁（CI 必须通过）

- [x] `uv run ruff check src/rolo/mvp scripts/mvp_release_gate.py tests/test_mvp_journey.py tests/test_mvp_release_gate.py`
- [x] `uv run pytest -q tests/test_mvp_journey.py tests/test_mvp_release_gate.py`（7 passed）
- [x] `uv run python scripts/mvp_release_gate.py --suite examples/mapping-10.json`
- [x] 10-case suite digest 可重算，报告结论为 `PASS`，每个 case 都有 evidence 和 64 位 artifact digest。
- [x] `artifact-index.json` 中每个路径均为 index 同目录下的普通文件，且 SHA-256 校验通过。
- [x] Trace 离线 replay 覆盖成功、工具失败→诊断→恢复，状态分别为 `COMPLETED`；不允许调用未被 Probe 验证的 Tool。

## LanderPi 真机门禁（发布前执行）

最近一次只读验证（2026-09-04）已确认 SSH 网络、host key 和 ED25519 identity 正常。`mentorpi` collector 返回了新鲜且可验证的 `hw`/`linux` bundle：目标指纹为
`70c798f35729aec4e4ca083b561f37dd45cf70c8dcbecfbe7ecc1110bd1d74c9`，设备为 Raspberry Pi 5、aarch64、Ubuntu 22.04。`ros` layer 在目标端未在超时窗口内返回，完整三层 Probe 因此保持 `BLOCKED`；不得用 controller 环境替代该证据，也不得把 mapping 能力标记为已验证。

- [x] 在 `mentorpi` 上重新执行 Probe，记录 `target_fingerprint`、catalog/snapshot digest、采样时间和 freshness。2026-09-04 实测 `Probe READY`：target fingerprint `70c798f35729aec4e4ca083b561f37dd45cf70c8dcbecfbe7ecc1110bd1d74c9`，evidence SHA-256 `e1089e99a9415e3a77b06275f2cc51aab454e990308b7929685e3fd304ff6649`，RKB snapshot SHA-256 `ca87af85d5a1f274b112442b6389ff55be14bcdaa16ad86460d6e95725f9847a`，采样时间 `2026-09-04T05:49:32Z`；hw=`PARTIAL`、linux/ros=`SUCCEEDED`。
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
