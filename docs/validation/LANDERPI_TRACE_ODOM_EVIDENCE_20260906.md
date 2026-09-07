<!-- status: active; authority: guide; owner: Trace; last_reviewed: 2026-09-06 -->

# Trace 的 LanderPi odom/EKF 证据链

`scripts/landerpi_odom_trace.py` 是客户机上的只读探针。它订阅
`/controller/cmd_vel`、`/odom_raw`、`/odom`、`/odom_rf2o`、`/imu` 及相关 TF，
并读取 ROS 图和标准参数服务。它不发布 Twist，不调用 `/set_odom`，也不启动或停止
任何进程。输出由 `rolo-landerpi-odom-trace/v1` 描述，内含可回放的
`rolo-odom-ekf-observation/v1` 投影。

探针同时保留三种容易被混淆的事实：

1. 图发现事实：每个 topic 的 publisher/subscriber 数量、节点名、接口类型和 QoS；
2. 数据接收事实：本探针实际收到的样本数、频率、最大间隔、ROS header 时间戳、frame、
   四元数范数和角速度；
3. 语义事实：命令角速度的时间积分、`/odom_raw` 与 `/odom` 的初始偏置和增量误差、
   `/imu` 的 orientation 有效率、orientation covariance sentinel、陀螺角速度与 orientation
   导出的 yaw-rate 残差、EKF measurement mask、`use_mag`/`imu0_relative`、
   校准文件摘要和 TF 对。

## 如何解释 yaw 差异

- `yaw_relationship.classification=CONSTANT_OFFSET` 表示两个序列的增量一致但起始角
  不同。它需要明确 `odom` frame、IMU frame 和启动 heading 的对齐契约，不能直接当作
  漂移或底盘失控。
- `classification=DIVERGING` 表示增量也不一致。应检查 IMU 轴/偏置标定、frame、时间
  戳和 EKF covariance/mask；仅修改初始值不能修复这种速率误差。
- `imu_absolute_yaw_available=true` 只能在显式声明绝对来源并且 orientation 样本有效时
  使用。有限的非零四元数本身不证明磁航向；`use_mag=false` 或相对 gyro 输出只能提供
  相对 yaw。
- `source_inference=COMMAND_INTEGRAL_FIT` 是 `/odom_raw` 命令积分的运行证据。它仍应与
  源码或轮编码器证据一起审阅；没有实测轮反馈时，`odom_pose_source` 不得标成
  `MEASURED_FEEDBACK`。

## Trace 判定顺序

`observation_from_trace_payload()` 将探针产物投影到稳定模型，
`diagnose_trace_payload()` 再按以下顺序分类：身份/DDS → 图与接收一致性 → raw/EKF/IMU
样本 → odom 来源 → IMU 绝对航向与初始值 → reset 服务存活证据 → 启动环境 → yaw 关系。
诊断会保留“缺少开发项”，例如轮反馈、绝对航向标定、初始 heading contract、measurement
mask、reset survival probe 和统一 OS 用户；这些项不能由离线回放自动填成 PASS。

## 客户机采集

在与 ROS 发布者相同的 OS 用户和 ROS domain 下运行：

```text
python3 /home/ubuntu/landerpi_odom_trace.py --duration 12 --output /tmp/rolo-odom-trace.json
```

如果需要明确记录 EKF 当前语义，可在现场审阅后附加
`--imu-use-mag false|true`、`--imu-yaw-mode relative|absolute` 或
`--odom-source command_integration|measured_feedback`；本次用例已确认自主命令源时可加
`--autonomous-source-confirmed --publisher-user ubuntu`。这些参数只是声明/证据标签，
不会改变目标机状态。`--no-parameter-query` 和 `--no-tf` 只在目标缺少对应 ROS 包时使用，
并应把产生的限制保留在 artifact 中。

重置回调的存活性不能用只读探针声称通过：输出会分别记录 `/set_odom` topic 和同名
service（若存在）是否可发现，但 `reset_probe_performed=false`。只有单独获准的受控 staging probe 才能把
`reset_survival_verified` 置为 true。

## 受监督旋转 canary 的时间窗与电机证据

`landerpi_rotation_canary.py` 只在显式提供
`--autonomous-source-confirmed` 后创建 Twist publisher。它把收到的混合
`cmd_vel` 样本放在 `sample_records.cmd_vel`，把本进程实际调用 publisher 的命令单独放在
`sample_records.published_cmd_vel`；命令积分和 `command_to_raw_yaw_error_rad` 只使用后者，因而不会把
joystick/app 的闲置 publisher 当成本体命令。

`motion_start_t` 是首个非零 Twist 发布前的单调时钟基线，`motion_end_t` 在停止命令前记录。
`raw_yaw_delta_rad`、`ekf_yaw_delta_rad`、`imu_yaw_delta_rad` 只在这个窗口内计算；
`yaw_relationship` 和 `imu_raw_yaw_relationship` 在两条序列的共同 receipt-time 区间内线性插值，
并输出 `overlap_start_t`、`overlap_end_t` 和 `synchronized`。这样，准备阶段的旧样本或不同发布频率
不会伪造增量差异。没有共同窗口时分类为 `INSUFFICIENT_DATA`。

IMU 每条记录还保留 `quaternion_yaw`。当 covariance 为全零、`-1` sentinel 或 malformed 时，
`yaw` 会保持空值以阻止绝对航向声明，但 `quaternion_yaw` 仍可用于相对旋转比较；
`imu_relative_yaw_delta_rad` 和 `imu_gyro_integrated_yaw_delta_rad` 是同样的相对证据，
不是磁航向或已标定的绝对 heading。`imu_raw_yaw_relationship.second_stream_semantics`
会明确标注这一点。

publisher 创建成功后，无论 readiness、首个非零发布或反馈循环在哪一步失败，退出路径都会尝试六次
零角速度；`stop_published` 只表示至少一次 publish 调用成功，不代表底盘已经停止，仍需
`stopped_observed=true` 才能报告 `SUCCEEDED`。

`--motor-topic`（默认 `/ros_robot_controller/set_motor`）只做可选只读订阅和 graph 记录，类型或订阅
失败不会阻塞旋转。`motor_evidence_kind=COMMAND_PATH_SAMPLE` 表示收到电机命令路径消息，
`GRAPH_ONLY_OR_UNAVAILABLE` 只表示路径元数据或类型不可用；该证据不是编码器反馈，也不能证明实际轮速。
可用 `--no-motor-topic` 完全关闭该附加订阅。
