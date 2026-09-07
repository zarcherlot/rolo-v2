<!-- status: active; authority: guide; owner: field validation; last_reviewed: 2026-09-06; target: pi@192.168.10.167 -->

# LanderPi `/odom` / EKF diagnosis (2026-09-06)

本轮在安全人员在场、无导航写入的条件下完成了只读链路核验，并执行了受限低速旋转
探针。命令均在 `MentorPi` 容器内以 ROS 节点相同的 `ubuntu` 用户运行；密码未写入
artifact。

## 已证实的运行事实

- `bringup.launch.py` 已启动 `odom_publisher`（PID 791）和 `ekf_filter_node`（PID 793）。
- `ros2` 使用 `rmw_fastrtps_cpp`，容器使用 host network，`ROS_DOMAIN_ID=0`。
- `/odom_raw` 与 `/odom` 各有 1 个发布者和 1 个订阅者，并能收到实时样本。
- 以 root 运行的诊断曾看到 endpoint 但收不到 ubuntu 发布的数据；切换为 ubuntu 后立即
  收到样本。这是 Fast DDS 共享内存跨用户隔离导致的“图存在、数据不可读”假象。
- `/odom_raw` 在 0.8 秒、0.03 rad/s 受限探针后 yaw 约变化 0.013 rad（约 0.7°），且
  停止后角速度为 0，说明发布器的积分和停止消息链路可工作。
- `/controller/cmd_vel` 图中同时存在 6 个发布者；现场已确认本次用例只考察本体自主发布，
  因此该数量作为图诊断记录，不作为本用例的自动阻断条件。
- `odom_publisher_node.py` 将 `controller/cmd_vel` 的速度在 50 Hz 定时线程中积分成
  `/odom_raw`，初始 `pose_yaw=0`，没有轮编码器或电机反馈输入。这是命令积分的开环姿态，
  不是测量得到的底盘 yaw。
- `/ros_robot_controller/imu_raw` 和 `/imu_corrected` 的 orientation 是零四元数；校准文件
  只提供比例矩阵 `SM` 与三轴 bias。`imu_filter.launch.py` 明确设置 `use_mag=False`，所以
  滤波器没有绝对航向观测，只能由陀螺积分出相对 yaw，启动初始航向未被定义且会受残余 bias 漂移。
- EKF 的 `odom0_config` 使用命令积分的 vx、vy、vyaw，`imu0_config` 又使用 IMU yaw、vyaw。
  `imu0_relative=true` 只把第一帧当作该传感器的相对零点，并不能生成磁航向，也不能把两个
  不同语义的 yaw 自动对齐。因此 `/odom` 与 `/odom_raw` 相差 1 rad 量级是当前配置的可预期结果。
- `/set_odom` 回调最初因 `self.clock().now()` 崩溃，修复后又因整数 `0` 写入 ROS float
  字段崩溃；两处均已在现场修补并验证 publisher 可继续运行。该路径必须成为 Trace 的
  `RESET_SURVIVAL` 门禁，不能只检查 topic graph。
- bringup launch 依赖 `need_compile`、`MACHINE_TYPE`、`LIDAR_TYPE`、`DEPTH_CAMERA_TYPE`
  等环境变量；缺失时 launch 会在不同阶段失败并留下孤儿节点，Trace 需要在启动前显式
  校验环境契约并在失败后清理整棵进程树。

## 结论与后续门禁

原先的 `NO_LIVE_SUBSCRIBER_OR_ODOMETRY` 是诊断身份错误造成的误报，Trace Agent 必须
记录并复用 ROS 发布者的 OS 用户。底盘旋转的剩余问题不是 AMCL，也不是单一初始值缺失，
而是“开环命令积分 odom + 无绝对航向的 IMU yaw”被当成同一姿态观测融合。必须补上真实
轮反馈或绝对航向契约；在此之前只能把旋转标记为开环并用 `/odom_raw` 做受限观测，不能
把当前 `/odom` 作为闭环真值。

建议客户主机上的安全修复顺序：

1. 以 `ubuntu` 身份重复 `PROCESS_PRESENCE`、`TOPIC_GRAPH`、`ODOM_RAW_SAMPLE`、
   `EKF_SAMPLE`、`IMU_SAMPLE` 和 `TF_CHAIN`；记录 `rmw_implementation` 与两端 OS 用户。
2. 记录并确认本用例的自主命令源；joystick/app 发布者只作为图诊断信息，不纳入本次用例的
   旋转判据。
3. 补齐轮反馈或绝对航向契约；若暂时没有磁航向，禁用未经验证的 IMU 绝对 yaw，仅融合经
   验证的 vyaw，并显式记录相对 yaw 初始化；重启 EKF。
4. 再次比较 `/odom_raw`、`/odom` 与实际反馈的 yaw 增量，差值小于 0.15 rad 且停止角速度小于
   0.03 rad/s 后，才允许 1° 低速旋转 canary。

可复用的只读步骤已编码为 `landerpi-odom-ekf/v1` Trace 诊断计划；其结果模型会把
`DDS_USER_MISMATCH`、`ODOM_OPEN_LOOP_COMMAND_INTEGRATION`、`IMU_YAW_UNOBSERVABLE`、
`IMU_INITIAL_HEADING_UNSET`、`EKF_RAW_YAW_INCONSISTENT` 和缺失的开发项分别落盘。
