<!-- status: active; authority: reference; owner: rolo maintainers; last_reviewed: 2026-09-02 -->

# RKB-0 依赖与验收前置条件

## 本地依赖

- Python `>=3.10,<3.14`；CI 矩阵为 3.10、3.11、3.12、3.13。
- 运行时依赖由 `pyproject.toml [project.dependencies]` 管理；RKB-0 需要 `pydantic`、
  `pyyaml` 及现有 Probe 链依赖。
- 开发依赖由 `[dependency-groups].dev` 管理，至少包含 pytest、pytest-asyncio、pytest-cov、ruff。
- 推荐命令：`uv sync --locked --dev`。

## 每个 PR 的最小命令

```bash
uv sync --locked --dev
uv run ruff check src/rolo/rkb src/rolo/mhs_hardware.py src/rolo/mhs_sensor.py tests/test_rkb_contract_baseline.py
uv run pytest tests/test_rkb_contract_baseline.py tests/test_rkb_envelope.py tests/test_mhs_hardware.py examples/mhs-sensor/test_mhs_sensor.py
python scripts/check_docs.py
python -m compileall -q src tests examples
```

CI 在 Probe job 中复用同一入口，并覆盖 Python 3.10–3.13；package job 继续执行 release-check
和 wheel/sdist 构建。真机 canary 另需固定目标机、已批准 host key、只读 probe runner、ROS/驱动
运行时和人工授权；缺失任一条件必须标记 `BLOCKED`。

## 依赖失败处理

依赖下载、pytest、ruff、ROS、驱动或真机授权失败时，不得用“代码已创建”替代验收。记录
失败命令和缺失条件，保留上一份 immutable artifact；回滚只撤销新入口/latest 指针，不删除
旧 bundle/report。
