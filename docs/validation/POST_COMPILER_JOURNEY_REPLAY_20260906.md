<!-- status: active; authority: reference; owner: rolo maintainers; last_reviewed: 2026-09-06; target: fake-target -->

# Post-Compiler 离线旅程回放

使用 `scripts/post_compiler_journey_replay.py` 在 fake target 上重放互补链路：

```text
DSL_PUT → DSL_CHECK → PLAN_RESOLVE → TARGET_COMPILE → TARGET_CONFORMANCE
→ immutable Release → Trace → Certify
```

执行命令：

```bash
python scripts/post_compiler_journey_replay.py --output-dir artifacts/post-compiler-replay
```

2026-09-06 结果：

- journey：`PASS`；
- target compile：`PASS`；
- target conformance：T1～T4 `PASS`；
- Trace：`COMPLETED`；
- Certify：10/10，`PASS`；
- artifact index 覆盖 DSL、Context、DSL check、Plan resolve、Compiler conformance、Bundle、
  target compile、target conformance、Release、Trace 和 Certify 绑定文件。

该回放不宣称真实目标机运行行为。LanderPi 的真实 ROS2 runtime 证据记录在
[LANDERPI_ROS2_RUNTIME_DETECTION_20260905.md](LANDERPI_ROS2_RUNTIME_DETECTION_20260905.md)，
归一化快照记录在
[LANDERPI_ROS2_RUNTIME_OBSERVATION_20260906.json](LANDERPI_ROS2_RUNTIME_OBSERVATION_20260906.json)。
现场 1° 旋转 canary 因 `/odom` 无消息安全阻塞（见
[LANDERPI_ROTATION_CANARY_20260906.json](LANDERPI_ROTATION_CANARY_20260906.json)），
因此真实 T3 运行行为和完整 Probe→Trace/Certify 仍需在恢复数据流后通过授权 SSH journey 采集。
