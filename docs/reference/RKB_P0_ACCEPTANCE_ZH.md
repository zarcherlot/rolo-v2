<!-- status: active; authority: reference; owner: rolo maintainers; last_reviewed: 2026-09-02 -->

# RKB P0 可执行验收

本页是当前 v2 的执行台账，不承诺保留历史 rolo 版本或旧 `adapt` 模块路径。Probe 的
canonical source path 是 `src/rolo/stages/probe/`；新 RKB artifact 是唯一新写入格式。

## 交付物与命令

| 工作流 | 输入 | 输出 | 本地命令 | CI job |
|---|---|---|---|---|
| RKB-1 envelope | `ProbeResult` 或已验证 `TargetEvidenceBundle` | `src/rolo/rkb/`、`schemas/RobotEvidenceEnvelope.schema.json` | `python -m pytest tests/test_rkb_envelope.py` | `probe` |
| MHS read-only | manifest + fake backend | `src/rolo/mhs_hardware.py`、MHS example | `python -m pytest tests/test_mhs_hardware.py examples/mhs-sensor/test_mhs_sensor.py` | `probe` |
| Schema/lint | source + schemas | deterministic JSON schema/digest | `python -m compileall -q src tests examples` | `probe` |

安装前提：Python 3.10–3.13、`uv sync --locked --dev`（或等价安装 `pyproject.toml` 的
project 与 dev 依赖）。没有 `pytest`/`uv` 时状态必须记为 `BLOCKED`，不能将“代码已创建”
标为完成。

## 失败关闭与边界

- identity tuple（robot、target fingerprint、probe runner、deployment、access、nonce）任一不一致拒绝读取。
- envelope digest、fact digest、freshness 或 replay window 任一校验失败拒绝读取；过期状态为 `STALE`。
- 未观测的 Domain/RMW/安全状态只能记录 `UNKNOWN`，不能推导 capability eligibility。
- MHS v2 仅开放 `inspect`、`status`、`read`；reset、calibrate、setpoint、stop、power-cycle 等写请求统一 `UNAVAILABLE`。
- manifest/driver digest、route 和 evidence IDs 随结果返回，但 Provider 注册本身不授予 release 或 capability Gate 资格。

## 回滚与外部依赖

新 envelope 只追加 immutable artifact；写入失败不得覆盖既有 snapshot 或 latest index。回滚动作是删除未发布的新 artifact
并保持上一份完整 envelope。真机 canary、ROS 环境、设备驱动和 secrets 是外部依赖；secret 只通过运行时路径读取，不能进入
RKB value、schema fixture 或日志。
