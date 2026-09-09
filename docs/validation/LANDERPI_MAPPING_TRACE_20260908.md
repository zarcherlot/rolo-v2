<!-- status: active; authority: reference; owner: field validation; last_reviewed: 2026-09-08 -->

# LanderPi 自主建图 Trace 现场记录（2026-09-08）

本记录对应 `codex/landerpi-autonomous-mapping` 分支的受监督现场调试。目标侧基础能力仅用于本次 Rolo DSL/targetd 调试，不宣称为生产级导航栈。

> 2026-09-08 清理说明：经用户明确授权，本文所述远端 Rolo/RKB 工程、运行状态、地图、旧
> trace/canary/probe 脚本、ROS `.bak-rolo` 备份及 Rolo uv editable cache 后续已从 LanderPi host
> 和 `MentorPi` 容器不可恢复地删除。本文仅保留历史现场摘要与 digest，不表示这些远端路径或
> artifact 仍可访问或回放；`/home/pi/robot_pi` 与 ROS 当前文件未被修改。

## 现场基础能力

- MentorPi 容器内启动 `slam_toolbox` mapping，固定消费 `/scan`，发布 `/map`，坐标链为 `map → odom → base_footprint`。
- 调试探索器只允许固定 ROS 路由：`/controller/cmd_vel`、`/scan`、`/odom`、`/map`。
- 探索器以低速 bounded reactive policy 前进；LiDAR 使用扇区 p10 作为抗单点噪声判定，同时保留近场 minimum emergency guard；命令源干扰、传感器过期、距离/时间超限均 fail-closed。
- 运行、status 和 stop 受单实例锁保护；stop 先发布零速度，再回收锁持有的旧 runtime。容器内还有独立 `timeout` reaper，避免 provider 超时遗留匿名 `python3 -` ROS 节点。

## Tool 注册与 DSL/Trace 闭环

注册并通过 conformance 的工具：

`app.mapping.status`、`app.mapping.run`、`app.mapping.stop`、`app.mapping.save`

最终现场报告：

`artifacts/landerpi-mapping-trace-20260908-final-validated/validation/landerpi-mapping-trace-trace-WrSAg1YVslPMPoO2.json`

报告结论为 `PASS`，Trace 状态为 `COMPLETED`，安装归档 digest 为
`a653d6d1fd21762b86a43504880f730eb2bf980dbda0ee8f7f8c945cf10a55dc`，并包含
`rolo/targetd/landerpi_autonomous_mapping_runtime.py`。

本轮短监督 canary 参数为 5 s / 0.2 m / obstacle threshold 0.30 m，观测结果：

- `mapping.status`：传感器、里程计、SLAM map 均在线；front p10 约 0.369 m。
- `mapping.run`：`SUCCEEDED`，`motion_started=true`，累计里程 `0.126435 m`，`obstacle_events=0`，时间预算结束并发布零速度；`physical_stop_verified=true`、`stopped_observed=true`。
- `mapping.stop`：`STOPPED`，`stop_method=ros2_topic_pub_once`，返回码 0，stop elapsed 约 2.391 s，且记录了 prior run 状态。
- `mapping.save`：保存成功，SLAM 输出为 80×70、0.05 m/pixel 的 PGM/YAML：
  - `/home/ubuntu/rolo_debug/maps/rolo_mapping_trace_20260908_final_validated.pgm`，5613 bytes，SHA-256 `f36a040eebac2c82c272e024b1eb5638bb62bc15d1cc076b743758f5ac5fd9b6`
  - `/home/ubuntu/rolo_debug/maps/rolo_mapping_trace_20260908_final_validated.yaml`，162 bytes，SHA-256 `447d8a0005096b9b769805004913b1b7b4cde35b316c75d7c39ecef72dfe9983`

## 现场收尾与限制

当次运行结束时，复核确认 `/tmp/rolo-mapping-status.json` 为 `STOPPED`，
`motion_started=false`，ROS graph 中无 `rolo_mapping_debug` 节点；`slam_toolbox` 当时仍保持运行以
提供 `/map`。

随后经授权完成清理：host 与 `MentorPi` 容器内所有经精确枚举、解析并确认属于 Rolo/RKB 的工程/
部署目录、中间产物、旧 trace/canary/probe 脚本和结果、ROS `.bak-rolo` 备份以及 Rolo uv editable
cache 均已删除。清理后在 host 的 `/root`、`/home`、`/tmp`、`/var/tmp`、`/opt`、`/var/lib` 和
容器的 `/tmp`、`/var/tmp`、`/home/ubuntu`、`/root` 复核，无明确 Rolo/RKB 残留；相关进程和 Docker
命名资源也无残留。清理不可恢复，调试用 key-only SSH 公钥授权暂时保留。根分区约 1.9 GiB 可用、
97% 使用率，后续上传 bundle、保存地图或升级前仍需磁盘余量门禁。

该探索器不是 Nav2/生产 planner；vendor odom/EKF 可能为 open-loop，里程仅作诊断参考；多 publisher command route 仍由 interference gate 保护。任何再次运行都必须有现场操作员和独立物理急停。
