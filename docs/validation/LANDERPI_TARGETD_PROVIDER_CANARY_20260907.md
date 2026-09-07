<!-- status: generated; authority: reference; evidence: supervised targetd provider canary; target: MentorPi/LanderPi; last_reviewed: 2026-09-07 -->

# LanderPi targetd/provider 1° canary

这份脱敏记录来自一次完整的 targetd bundle/provider journey，而不是直接调用目标机上的
`bounded_twist.py`。输入帧依次完成 `OPEN_JOURNEY → HANDOFF → PUT → CALL →
CLOSE_SESSION`；`PUT` 的签名 bundle observation contract 明确绑定 `/cmd_vel`、
`/odom_raw`/`/odom` 和三路独立 IMU。

## 结果

`CALL` receipt 为 `SUCCEEDED`。请求为 `1°`、`0.15 rad/s`，运动窗口为 `0.2094 s`。
`/odom_raw` 报告 `1.6282°`，但独立 IMU 选中 `/imu` 的积分为 `0.0140688 rad`
（约 `0.806°`）；三路 IMU spread 为 `0.0006331 rad`，独立角度误差为
`0.0033845 rad`，小于 `0.005 rad` 容差。零速命令、停止观察、physical stop 和
settle 均通过，settle 尾窗最大残余角速度为 `0.0042951 rad/s`。

`/odom_raw` 与独立陀螺的差异保留为诊断事实；本 receipt 的精确角度门禁使用独立
IMU，不把命令积分型 odometry 当作物理角度真值。

机器可读的脱敏字段见
[`LANDERPI_TARGETD_PROVIDER_CANARY_20260907.json`](LANDERPI_TARGETD_PROVIDER_CANARY_20260907.json)。
原始 targetd input/output 二进制及源包仅用于现场审计，不纳入仓库。
本记录证明 targetd transport/provider 与目标 runtime 的闭环；它不替代由 DSL
compiler 生成并经 release/catalog 绑定的生产 bundle 现场验收。
