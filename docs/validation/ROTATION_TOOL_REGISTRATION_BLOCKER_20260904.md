status: active
authority: guide

# LanderPi 地盘旋转 Tool 注册诊断

## Probe 结果

2026-09-04 已连续执行三次 `mentorpi` 新鲜 Probe，均返回 `READY`。最近一次目标证据
digest 为 `6cb678bd7145417d9373aeddc68db2d9ae2d4ea33e17b405cbc71765744787e2`。

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

使用该 evidence 在 workspace registry 中生成并注册了 `app.base.rotate` proposal，
证明了 proposal 校验、digest 和 descriptor reload 路径。真实设备执行没有伪造为成功：
当前注册 adapter 仍是直接通过 ROS CLI 发送 `cmd_vel` 的实验实现，尚未接入允许的
Rolo/MHS driver route；auto-review 因此拒绝了向本机 Rolo state registry 持久化并执行
该运动 Tool。下一步必须把 application adapter 接到已注册的 target execution route，
再进行现场旋转验证。

## Route-backed adjustment

随后已将旋转 proposal 调整为 route-backed 形式：proposal 只保留
`angle_degrees`、`max_speed_rad_s` 的边界和 `base.motion.velocity` route 引用，
descriptor 不再携带 Python、`ros2` 或 `/cmd_vel` 发布脚本。新增的
`ExecutionRouteRegistry` 与 `RoloRouteBroker` 只允许目标绑定且已注册的 provider handler
执行，并在进入 provider 前检查 route 的参数 schema。`register-tool` 现在会拒绝未注册 route
引用，`register-route` 负责把经 Probe evidence 绑定的 provider route 写入 registry。

LanderPi 当前仍没有真实的 `base.motion.velocity` provider-owned route；Probe 观察到的
`/cmd_vel` 只是资源证据，不能直接升级为写能力。因此本轮已完成架构和注册前校验，
真实旋转仍保持 BLOCKED，未向设备发送运动命令。

