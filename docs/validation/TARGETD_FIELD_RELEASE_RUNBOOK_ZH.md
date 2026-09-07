<!-- status: active; authority: guide; owner: rolo maintainers; last_reviewed: 2026-09-06 -->

# targetd 现场发布与 ROS2 底盘调试 Runbook

本文用于安全人员在场的 LanderPi 现场验收。所有命令先做只读检查；只有现场负责人明确
批准后，才执行 targetd 安装/升级或 ROS2 bringup。Rolo 不保存或回显目标机密码。

## 1. 安装、升级和健康检查

在本地工作区执行 `rolo targetd install` 会通过已固定 host key 的 SSH 通道把当前 Python
包写入专用目录。重复安装是幂等升级，安装清单记录 package version、源码 digest 和文件
列表。卸载接口要求调用方显式传入确认标记，且拒绝 `/` 这类根路径。

安装后先执行：

```bash
rolo targetd status ssh://pi@landerpi/home/pi --known-hosts PATH --identity-file PATH
rolo targetd health ssh://pi@landerpi/home/pi --known-hosts PATH --identity-file PATH \
  --remote-root /opt/rolo --state-root /var/lib/rolo-targetd --signing-key KEY
```

健康状态只说明 targetd 协议服务可用，不代表底盘控制器或里程计可用。发布包必须保留
`rolo-targetd-install-manifest/v1`，并在升级失败时保留上一版本目录和 current release。

## 2. ROS2 bringup 和旋转前置条件

完整 MentorPi 软件栈通常由容器内的顶层 launch 启动：

```bash
ros2 launch bringup bringup.launch.py
```

启动前确认没有另一份 bringup；重复启动可能造成节点或硬件资源冲突。启动后必须使用
`--no-daemon` 验证实时图：

```bash
ros2 topic info --no-daemon /odom -v
ros2 topic echo --no-daemon --once /odom
ros2 topic info --no-daemon /cmd_vel -v
```

诊断命令必须与 ROS 节点使用相同的 OS 用户执行（当前 MentorPi 为 `ubuntu`）。root
诊断端可能仍能发现 endpoint，却因 Fast DDS 共享内存的跨用户隔离收不到样本；因此
“图存在”不能替代“实际收到消息”。同时记录 `RMW_IMPLEMENTATION`、发布者用户和订阅者
用户。

底盘旋转 canary 只有在 `/odom` 有实时发布者和样本时才可执行。无样本时，Rolo 必须返回
`BLOCKED` 且 `motion_started=false`，不得用定时速度替代反馈闭环。canary 结果应写入带有
目标、release、runtime snapshot 和安全人员确认信息的 artifact。

## 3. 故障分类和处理边界

| 状态 | 证据 | 下一步 |
|---|---|---|
| `CONTEXT_MISSING` | Compile Context 缺字段或 freshness 过期 | 只请求已定义的 bounded Probe follow-up |
| `MAPPING_FAILED` | DSL diagnostics 或 repair loop 达到上限 | 保留 diagnostics，不发布 Tool |
| `TARGET_COMPILE_FAILED` | targetd T1/T2 失败 | 检查 observed runtime/provider/schema 和 bundle digest |
| `RUNTIME_BLOCKED` | `/odom` 无样本、无订阅者或安全前置不满足 | 停止运动尝试，恢复控制器/反馈后重新做只读检查 |
| `DDS_USER_MISMATCH` | 诊断用户与 ROS 发布者用户不同且样本数为 0 | 以发布者用户重跑诊断，或由平台统一 DDS 共享内存身份 |
| `EKF_RAW_YAW_INCONSISTENT` | `/odom` 与 `/odom_raw` yaw 增量超出阈值 | 审阅 IMU frame、covariance 和 `imu0_config`，重启 EKF 后复测 |
| `COMMAND_MULTIPLE_PUBLISHERS` | `/controller/cmd_vel` 存在多个发布者 | 先停用 joystick/app 等竞争来源，只保留受监督 canary 发布者 |
| `RELEASE_STALE` | evidence、route、MHS、runtime 或 target fingerprint 变化 | 保留旧 Release，重新 Conformance 后再切 current |
| `UNKNOWN` | 超时、断线或无法判定结果 | 不推断物理结果，按 session 和 artifact index 恢复或人工复核 |

日志和指标使用 `rolo-journey-metric/v1`；敏感键在落盘前脱敏。artifact retention 先用
`ArtifactRetentionPolicy.plan_prune()` 预览，再由现场负责人显式调用 `prune()`。

## 4. 版本和回滚窗口

targetd 只接受声明版本和 digest 匹配的 DSL/Context/Bundle。升级先写入新版本目录并完成
health，再切换 release current；失败保留旧目录和旧 current。回滚只能指向同一 target
fingerprint 下已验证的 immutable release，禁止跨目标复用。
