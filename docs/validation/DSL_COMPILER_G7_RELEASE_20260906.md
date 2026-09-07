<!-- status: active; authority: reference; owner: rolo maintainers; last_reviewed: 2026-09-06 -->

# DSL Compiler G7 发布门禁证据

本记录确认 Compiler standalone 已满足互补开发计划的 G7 启动条件。门禁针对当前
worktree 的源码、schema、replay、测试、文档和发行包执行；它不替代真实 LanderPi
运行行为验收。

## 门禁结果

| 检查 | 结果 | 证据 |
|---|---|---|
| DSL/Context/IR/Bundle schema | PASS | `schemas/` 与 Compiler contract tests |
| 四类 Operation offline replay | PASS | `scripts/post_compiler_journey_replay.py` |
| C1～C4 offline conformance | PASS | replay artifact 中的 compiler conformance |
| pytest | PASS | 当前配置全量测试，1 个既有 skip |
| compileall | PASS | `src/`、`tests/`、`scripts/` |
| documentation checks | PASS | `scripts/check_docs.py`，68 个 Markdown 文件 |
| release-check | PASS | `rolo release-check --require-artifacts` |
| wheel/sdist | PASS | Hatchling 构建成功，sdist 排除本地缓存目录 |

## 当前发行包

```text
rolo-0.1.0-py3-none-any.whl  327311 bytes  sha256: EE907250D42EF951046D04C198DC50A446E08703394E3790C0FF0AA0BE8038DE
rolo-0.1.0.tar.gz            927917 bytes  sha256: 87A939539D25F49A28C08F0516F8FA83796503C7B1E0CD15C3DAA18129A99DDE
```

G7 证据允许启动 Probe Context、Agent mapping、targetd、Release、Trace/Certify 和
LanderPi 互补开发。真实目标的 T1～T4、底盘反馈、Trace 和 Certify 仍必须单独记录，
不得由本地 G7 结果推断完成。
