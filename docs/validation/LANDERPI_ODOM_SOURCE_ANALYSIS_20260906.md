<!-- status: active; authority: reference; owner: field validation; last_reviewed: 2026-09-06; target: pi@192.168.10.167 -->

# LanderPi `/odom` 来源与 AMCL 检查

本记录针对现场底盘旋转 canary 的 `/odom` 阻塞，核对 MentorPi 容器内的进程、launch 源码、参数和 ROS topic 图。随后在相同用户身份下完成了受限低速探针；没有执行无反馈的持续运动。

## 结论

- 当前 `bringup.launch.py` 已启动 `controller.launch.py`，其中包含 `odom_publisher.launch.py` 与 `robot_localization/ekf_node`。
- `odom_publisher` 的源码在 50 Hz 定时线程中发布相对 topic `odom_raw`，因此默认全局 topic 是 `/odom_raw`。它根据 `controller/cmd_vel` 更新内部速度和积分位姿；它不是从 AMCL 获取里程计。
- `ekf_node` 的配置输入为 `odom0: odom_raw` 和 `imu0: imu`，launch remap `odometry/filtered:=odom`，所以预期链路是 `/odom_raw` → EKF → `/odom`。
- `navigation/launch/include/localization.launch.py` 确实定义了 `nav2_amcl::AmclNode`，但当前 `bringup.launch.py` 没有 include 该 localization launch；现场进程表也没有 `amcl` 或 `map_server`。因此 AMCL 当前未启动。
- AMCL 负责基于地图、激光和 TF 估计 `map→odom` 的全局定位，不负责产生轮式底盘的 `/odom`。AMCL 缺失不能解释底层 `/odom_raw` 没有消息；当前首先要修复的是 odom publisher/EKF 的运行输出。

## 现场证据

容器 `MentorPi` 的进程表包含：

```text
ros2 launch bringup bringup.launch.py
controller/odom_publisher --ros-args -r __node:=odom_publisher ...
robot_localization/ekf_node --ros-args -r __node:=ekf_filter_node ... -r odometry/filtered:=odom
```

进程环境确认 `ROS_DISTRO=humble`、`ROS_DOMAIN_ID=0`、`MACHINE_TYPE=LanderPi_Mecanum`。没有 `amcl`、`map_server` 或 navigation localization 进程。

重启 ROS CLI daemon 后，topic 图可见 `/odom_raw`、`/odom` 和 `/odom_rf2o`；`ros2 topic info /odom -v` 报告 `nav_msgs/msg/Odometry`、publisher count 1、subscription count 1。以 root 执行 echo 时没有样本，但以节点相同的 `ubuntu` 用户执行后 `/odom_raw` 和 `/odom` 均能收到实时样本；这是 Fast DDS 共享内存跨用户隔离造成的发现/数据不一致假象。进一步比较显示 `/odom_raw` 的 yaw 增量与 `/odom`/IMU 的 yaw 不一致，剩余阻塞转为 EKF/IMU 配置问题。

## 源码与参数链路

`controller.launch.py` 在 `enable_odom=true` 时创建 EKF，并做如下 remap：

```text
odom0: odom_raw
imu0: imu
odometry/filtered := odom
cmd_vel := controller/cmd_vel
```

`odom_publisher.launch.py` 创建 `controller/odom_publisher`，设置 `pub_odom_topic=true`、`base_frame_id=base_footprint`、`odom_frame_id=odom`。其实现创建 `nav_msgs/msg/Odometry` publisher `odom_raw`，并在定时线程中持续发布。

## 根因与下一步门禁

现场源码显示 `/odom_raw` 是 `controller/cmd_vel` 的命令积分结果，初始 yaw 为 0，没有轮编码器反馈；`imu_filter` 设置 `use_mag=False`，而原始/校准 IMU orientation 是零四元数。因此 IMU yaw 只有陀螺积分的相对航向，启动初始航向未定义并受残余 bias 漂移。EKF 将这两个语义不同的 yaw 同时融合，产生 `/odom` 与 `/odom_raw` 的差异是预期风险。修复门槛是补轮反馈或绝对航向契约，或明确降级为相对 yaw 的开环用例。

在再次执行底盘运动前，现场必须先只读确认：

1. `/odom_raw` 在连续窗口内有样本且频率稳定；
2. `/odom` 在连续窗口内有 EKF 输出，且 `odom→base_footprint` TF 可读；
3. `controller/cmd_vel` 的自主命令源已确认，停止命令可验证；图中 joystick/app 发布者只作为诊断信息，不作为本用例判据；
4. 若需要地图定位，再单独启动并配置 localization launch，确认 `amcl`/`map_server` 生命周期已 active；这一步补充 `map→odom`，不替代底盘 odometry。

第 1、2 项已经在 `ubuntu` 身份下达成；现场还观察到 `/controller/cmd_vel` 有多个发布者，但本次用例已确认只考察自主发布。完成轮反馈或绝对航向契约、修正 EKF/IMU 融合语义并复测前，旋转 canary 仍应保持 fail-closed。详细现场记录见 [`LANDERPI_ODOM_EKF_DIAGNOSTIC_20260906.md`](LANDERPI_ODOM_EKF_DIAGNOSTIC_20260906.md)。
