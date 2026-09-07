<!-- status: generated; authority: reference; evidence: supervised field canary; target: MentorPi/LanderPi; last_reviewed: 2026-09-07 -->

# LanderPi bounded Twist 1° canary

本记录对应 `LANDERPI_BOUNDED_TWIST_CANARY_20260907.json`，由本次现场执行时
staged 到 MentorPi 容器内的 `bounded_twist.py` 直接输出；运行时源码 hash 在下文保留。
执行前以 `ros2 topic info --no-daemon`
复核 `/cmd_vel` 为 `Publisher count: 0`、`Subscription count: 1`，因此本次没有
启用共享 `/controller/cmd_vel` 的竞争发布者豁免。

## 执行边界

- command route: `/cmd_vel`
- feedback: `/odom_raw`, `/odom`
- independent feedback: `/imu`, `/imu_corrected`, `/ros_robot_controller/imu_raw`
- requested turn: `1°` (`0.017453292519943295 rad`)
- command cap: `0.15 rad/s`; runtime duration bound: `0.5 s`
- source assertion: `autonomous_source_confirmed=false` (isolated route)
- runtime SHA-256: `44c8cd13c98135ca01793f807ea538d975995c5ed196145d76ec2ee4e5f2df4f`
- raw artifact SHA-256: `9c89c604d737a0e322345341d2c8e18ed2a4104b5b5593fe2f463f73c97234e2`

## 结果

`SUCCEEDED`。三路独立陀螺积分的选中值为 `0.0190951042 rad`（约 `1.094°`），
相对目标误差 `0.0016418117 rad`（约 `0.094°`），目标容差 `0.005 rad`；
`angle_accuracy_status=VERIFIED`。零速命令已发布并观察到停止，最终 200 ms IMU
尾窗最大残余角速度 `0.0044315 rad/s`，`settled=true`。

`/odom_raw` 的报告角度为 `1.7663°`，与独立陀螺存在明显超调；它被保留为诊断
证据，但不参与精确角度验收。这是本次将独立 IMU 作为物理角度门禁的原因。
