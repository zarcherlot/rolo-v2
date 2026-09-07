<!-- status: active; authority: reference; owner: rolo maintainers; last_reviewed: 2026-09-07 -->

# Post-Compiler P0–P2 状态（2026-09-07）

本记录对应 `codex/dsl-compiler-mvp` worktree。父 checkout 的用户 WIP 已复制到本分支，
父 checkout 未被清理、回退或重置；本记录只描述离线/fake-target 证据，不把真机门禁标成完成。

## 已完成的离线交接切片

| 节点 | 当前结果 | 主要入口 | 证据 |
|---|---|---|---|
| P0 Contract Handoff | `STABLE / E2` | `src/rolo/dsl/contracts.py`、`canonical.py`、`diagnostics.py`、`backends/fake.py`、`targetd/dsl_service.py`、`tests/test_dsl_contract_matrix.py` | 18 项交接版本 manifest、跨组件 version rejection matrix、source-bundle v1 锁定、canonical digest、重复键拒绝、稳定 diagnostics、backend negotiation、compile/conformance response cache digest 校验 |
| P1 Bootstrap/Candidate | `PARTIAL / E2` | `context_adapter.py`、`bootstrap.py`、`candidates.py`、`context_digests.py` | 只投影 `SUCCEEDED/PARTIAL` 观察、保留 limitation/freshness、候选证据与缺口、分层 `CLEAN/DIRTY`、幂等 bootstrap artifact |
| P2 Intent Mapping | `PARTIAL / E2` | `mapping.py`、`sufficiency.py`、`prompts.py`、`proposal.py`、`cli.py` | 意图别名查询、Context→Mapping Request、充分性判断、bounded follow-up、诊断修复上限、proposal 显式确认、validate/canonicalize/replay CLI |

## 回归门禁

在目标 worktree 执行：

```text
python -m compileall -q src scripts                         PASS
ruff check（post-compiler CI 同等路径）                      PASS
pytest -o addopts='' --basetemp=.pytest-final7 -q            358 passed, 1 skipped, 1 warning
scripts/post_compiler_journey_replay.py                     PASS（10-case Certify）
scripts/check_docs.py                                        PASS（74 Markdown）
```

## 尚未关闭的待办

- P0（E3+）：补真实 targetd transport 与跨语言 canonical-byte fixture；当前 contract matrix 仍是 Python/离线证据。
- P1：把真实签名 Probe/RKB/MHS 联合产物接入 Bootstrap，并在 rolo-vis 展示候选、freshness 和增量失效。
- P2：把 Agent/skill 的真实 caller 接到 request builder、proposal 确认和 bounded Probe receipt；继续保留禁止自由 SSH/shell、直接发布和修改 Context 的负向门禁。
- P3–P8：真实目标 runtime/backend、T1–T4、immutable catalog、Trace/Certify 现场旅程与安装升级 acceptance。
- LanderPi：当前仍受真实命令源独占、EKF/IMU 语义和稳定启动复测约束；离线 replay 不能替代现场证据。

因此本分支可以作为 P0–P2 的离线交接基线，但不能宣称 P7/I8 真机闭环完成。
