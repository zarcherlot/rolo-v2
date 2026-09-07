<!-- status: active; authority: reference; owner: rolo maintainers; last_reviewed: 2026-09-06; target: pi@192.168.10.167 -->

# LanderPi ROS2 运行时检测

## 结果

LanderPi 宿主机没有 `/opt/ros`，但运行中的 Docker 容器 `MentorPi` 使用镜像
`ros:humble`。在容器内加载 `/opt/ros/humble/setup.bash` 后：

- `ROS_DISTRO=humble`；
- `ros2` 位于 `/opt/ros/humble/bin/ros2`；
- `rclpy`、`sensor_msgs`、`geometry_msgs` 和 `nav_msgs` 均可导入；
- `ros2 topic list` 可读取 `/cmd_vel`、`/odom`、`/scan`、`/tf` 等目标运行时 topic。
- 容器内 `python3 -m pip show pydantic-core` 返回 `Version: 2.46.4`（Python 3.10）。

关键运行时类型：

| Topic | 类型 |
|---|---|
| `/cmd_vel` | `geometry_msgs/msg/Twist` |
| `/odom` | `nav_msgs/msg/Odometry` |
| `/scan` | `sensor_msgs/msg/LaserScan` |
| `/tf`、`/tf_static` | `tf2_msgs/msg/TFMessage` |
| `/joint_states` | `sensor_msgs/msg/JointState` |

检测到的节点包括 `/robot_api`、`/ros_robot_controller`、`/LD19`、`/lidar_app`、
`/odom_publisher`、`/scan_to_scan_filter_chain`、`/controller_manager` 和
`/rosbridge_websocket`。这些名称来自运行时发现，不能在 Context adapter 中静态补写。

## 可复现检查

```bash
ssh pi@192.168.10.167
docker ps --format '{{.ID}} {{.Image}} {{.Names}}'
docker exec MentorPi bash -c 'source /opt/ros/humble/setup.bash && ros2 topic list'
docker exec MentorPi bash -c 'source /opt/ros/humble/setup.bash && python3 -c "import rclpy, sensor_msgs, geometry_msgs, nav_msgs"'
```

要把一次只读 graph 采集保存为 targetd 可消费的证据，使用
`scripts/landerpi_ros2_snapshot.py`，输入必须只包含上述命令的原始 stdout；脚本不会连接目标机、
执行 shell 或补写未观测 topic：

```bash
python scripts/landerpi_ros2_snapshot.py --input ros2-capture.json --output ros2-runtime-observation.json
```

2026-09-06 的现场采集原文和归一化结果分别保存在
`LANDERPI_ROS2_RUNTIME_CAPTURE_20260906.json` 与
`LANDERPI_ROS2_RUNTIME_OBSERVATION_20260906.json`。该批次保持 `READ_ONLY`，没有发送
`/cmd_vel` 或其他写入指令；节点列表当次为空，因此没有把静态节点名称写入 observed 集合。

ROS2 运行时属于 `MentorPi` 容器边界；targetd 适配器必须通过已授权的容器入口访问，不能把宿主机缺失的 ROS2 路径当作目标事实。
