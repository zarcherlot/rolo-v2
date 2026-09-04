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
