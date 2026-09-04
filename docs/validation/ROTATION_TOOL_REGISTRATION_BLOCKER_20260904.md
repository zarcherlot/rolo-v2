status: active
authority: guide

# LanderPi 地盘旋转 Tool 注册诊断

## Probe 结果

2026-09-04 已连续执行三次 `mentorpi` 新鲜 Probe，均返回 `READY`。最近一次目标证据
digest 为 `2e2db99d04e6d93a418514c1bd598f0bce52ba63023cf97f85eeb3491ae48de4`。

最近一次 runtime graph 观察到：

- `/odom`、`/odom_raw`、`/odom_rf2o`；
- `/ros_robot_controller/set_motor`，类型为
  `ros_robot_controller_msgs/msg/MotorsState`；
- route 没有稳定的 provider/subscriber identity；
- 当前 Probe Tool Surface 仍是 `rolo-v2-probe-readonly-v1`，只发布 22 个读 Tool。

`/cmd_vel` 和 `/controller/cmd_vel` 在较早的一次 bundle 中出现过，但在最近 bundle 中没有
稳定复现。无论 route 是否出现，route presence 都不会自动产生旋转写 Tool。

## 正式 operation discovery

对最新 bundle 执行 `app.base.rotate` 得到：

- candidate：`DEFERRED`；
- adapter access：`DEFERRED_WRITE`；
- conformance：`FAIL`；
- 失败原因：`v1 write operation is not exposed by the Probe Tool Surface`；
- 没有 service、action、executable 或 actuator 被调用。

结果 artifact 位于本机 Rolo artifact store 的
`application/mentorpi/operations/app_base_rotate/app-operation-bundle-65d9ed99018e364cf6db493e/`。

## 阻塞点

当前目标侧没有可被 Probe 注册的 MHS `rotate` command，也没有目标绑定的固定 driver route。
`/ros_robot_controller/set_motor` 是一个观测到的 ROS topic，不能直接作为 Tool 发布或写入。

要完成注册，需要目标侧提供并部署一个固定 schema 的 MHS command，例如 `rotate`，并由 Probe
观察到对应 driver/provider、资源绑定、参数边界和停止路径。随后才能生成
`experimental_write=true`、`agent_callable=true` 的旋转 Tool；Trace 随即可以在
`SUPERVISED_FIELD_DEBUG` 下直接调用它。

## Probe Harness registration slice

本次开发已补齐通用的 `rolo-probe-analysis-input/v1` →
`rolo-tool-registration-proposal/v1` → registered application catalog 链路。
Harness 可在自己的交互窗口中生成和修改 adapter，再通过
`rolo register-tool --proposal ... --evidence ...` 提交；MVP 不增加第二个用户确认门。

最新 LanderPi Probe 已成功刷新，evidence digest 为
`d8c2f83e4c398c62576ce990df2afa31ef556bf27f9f0652a22c25dac90cea20`，并观察到
`ros_topic:/cmd_vel`、`ros_topic:/controller/cmd_vel` 和 `ros_topic:/odom`。

本轮将 proposal 调整为 evidence-bound `ExecutionBinding`：Harness 只提交 ROS 2
接口、`/cmd_vel`、反馈 topic、停止策略和参数映射，Rolo 根据新鲜 Probe evidence
校验 command endpoint 是否真实观测到，再将 binding 注册到 application catalog。
它不要求预先存在 route，也不允许 proposal 携带 Python、shell 或任意 argv。

最新 LanderPi Probe evidence digest 为
`6cb678bd7145417d9373aeddc68db2d9ae2d4ea33e17b405cbc71765744787e2`；`/cmd_vel`、
`/controller/cmd_vel`、`/odom_raw` 和 `/odom_rf2o` 均出现在 ROS 运行时图中，但
provider identity 和稳定性证据仍不完整。因此本轮已完成 binding 发现和注册校验，
真实旋转尚未执行，避免把 topic 观测误报成可控能力。
