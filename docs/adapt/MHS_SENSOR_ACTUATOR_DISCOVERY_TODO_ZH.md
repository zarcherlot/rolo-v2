<!-- status: active; authority: plan; owner: rolo maintainers; last_reviewed: 2026-09-03 -->

# 传感器与执行器 Discovery 需求

## 背景

当前 discovery 已确认 Linux 节点（I²C、SPI、GPIO、USB、thermal），但还没有完成：

```text
节点/总线 → 具体设备 → 稳定身份 → 协议/驱动 → MHS manifest → RKB evidence
```

因此最重要的传感器和执行器仍拿不到可用的 MHS。节点存在不等于设备身份、量程、命令
或安全限制已知；未知设备不能被猜测为可控设备。责任边界在 discovery：它负责追踪证据
和产出 candidate，不负责绕过安全 gate 执行控制。

## 目标与范围

目标是把 Linux 节点或总线上的具体设备追踪为可审计的 MHS candidate，并为 Rolo
capability gate 提供目标绑定、可复现、只读的证据。首批优先处理影响安全/运动决策、
具有稳定 serial/resource ID、且能从 driver/daemon/ROS graph 找到协议和反馈的设备；
仅能证明节点存在的对象保留为 presence-only candidate。每个设备必须有 owner、目标主机、
依赖、当前阶段和下一步行动。

## 状态与资格

```text
DECLARED -> DISCOVERED_UNVERIFIED -> ELIGIBLE -> VERIFIED -> STALE / UNAVAILABLE
```

`DISCOVERED_UNVERIFIED` 是 discovery 的最高直接产出；`ELIGIBLE` 需要 canonical route、
provider、目标身份、manifest/driver digest 和有效 runtime evidence；`VERIFIED` 必须由
Rolo gate/conformance 授予。path identity 只能保留为只读 candidate，不得进入写 gate 或
`VERIFIED`；缺失或冲突的信息保持 `UNKNOWN`。

## Discovery 工作包（只读优先）

- [x] **软件栈清点**：进程、systemd 服务、udev rules、内核 driver、ROS/DDS graph、
  串口/CAN/HTTP endpoint；记录 collector、目标 identity、时间、查询、退出码和 source ref；
  secret 必须脱敏。
- [x] **USB/串口追踪**：读取 VID/PID、接口、`/dev/serial/by-id`、serial 和 driver 绑定；
  将 CH340 等桥接节点追踪到上层协议，不凭 VID/PID 猜设备类别；首轮禁止发送串口数据。
- [ ] **I²C/SPI 设备识别**：只对有审批引用的地址和寄存器执行无副作用 identity probe；
  记录地址、芯片 ID、bus、驱动和失败原因；禁止盲写寄存器，未批准地址不访问。
- [ ] **GPIO 关系追踪**：读取 line name、consumer、chip/offset 和 device-tree/udev 来源；
  将 GPIO 线映射到传感器输入或执行器驱动，但不切换输出电平。
- [x] **执行器控制链追踪**：从 driver/daemon/ROS service/action 找到 enable、stop、
  feedback、limit、mode 和 fault；记录权威来源、power domain、watchdog、interlock、急停
  和 resource ownership；首轮只读取状态和反馈。
- [x] **稳定身份判定**：serial、device-tree、udev-by-id、controller resource ID 优先；
  生成 canonical identity tuple；来源冲突、重复 serial 或重插后 resource 变化标记 `UNKNOWN`。
- [x] **生成 MHS candidate**：为每个具体 sensor/actuator 生成 manifest、route、channels、
  state、commands、limits、driver digest；状态固定为 `DISCOVERED_UNVERIFIED`。声明 command
  不等于获得写权限，path identity 的 command 不得发布为可执行写能力。
- [x] **只读 provider probe**：执行 `inspect/status/read`，校验类型、单位、范围、断线和
  freshness；每类 transport 必须有 operation allowlist、timeout、retry/concurrency budget
  和 no-write 约束；失败也生成可审计的 unavailable evidence。
- [x] **Rolo gate 对接**：按状态机分别判断 `ELIGIBLE` 和 `VERIFIED`；任一 identity tuple、
  digest、freshness、route 或安全前置条件失败都必须 fail closed。

### 2026-09-03 LanderPi 进度

`start_app_node.service` 已按其真实 launch 链路重启并复测。通过加载
`/opt/ros/humble`、`/home/ubuntu/ros2_ws/install` 和
`/home/ubuntu/third_party_ros2/third_party_ws/install` 的 overlay，使用只读 `rclpy`
订阅取得 `/scan`、RGB/IR/Depth、`joint_states` 和 `servo_states` 的真实 payload。
结构化摘要和 replay gate 结果分别见：

```text
examples/mhs-landerpi/ros-structured-fixture-20260903.json
examples/mhs-landerpi/mhs-gate-20260903.json
```

物理 binding 的只读核查已落成
`examples/mhs-landerpi/physical-binding-20260903.json`：Aurora 930 已将稳定 USB
serial 与 `/aurora/aurora` 的图像流相关联；LiDAR 已解析 `/dev/ldlidar -> /dev/ttyUSB0`
及 LD19 launch 参数；控制器已解析 `/dev/rrc -> /dev/ttyACM0` 和稳定 by-id；舵机已将
配置中的逻辑 joint 与 `ServoStateList` ID 对齐。后 3 项仍是 `PARTIAL`，因为型号、物理
线束、限位和急停互锁尚未有独立证据。

Aurora 930 因稳定 serial、目标 fingerprint、digest、route 和 runtime evidence 已满足而
达到 `ELIGIBLE`；物理 binding、安全评审和 conformance 仍未满足，不能标记 `VERIFIED`。
LiDAR、控制器和舵机组的 payload 已取得，但稳定物理身份或安全前置条件仍不足，保持
fail-closed。I²C/SPI/GPIO 的设备级识别仍是后续工作项。binding 证据不会自动提升 gate：
安全评审、conformance、急停和限位必须分别通过。

安全评审与 conformance 的当前结果分别见
`examples/mhs-landerpi/safety-review-20260903.json` 和
`examples/mhs-landerpi/conformance-20260903.json`。安全评审对控制器/执行器保持
`BLOCKED_FOR_WRITE_AND_VERIFIED`；conformance 检查器已覆盖 schema、topic/type、空
commands、binding 引用和负测。Aurora 驱动根因已确认：设备支持模式在 640x400 RGB/IR
模式下报告 `depth_mode=kInvalid`，默认组合流 `rgbd_enable=True` 因而无法取得首帧；已将
源启动文件和安装树持久化为 `rgbd_enable=False` 并重启传感器节点，修复记录见
`examples/mhs-landerpi/aurora-fix-20260903.json`。随后从同一 ROS 时间戳重新取得 RGB/IR/Depth
payload 并独立计算 SHA-256；当前报告 `PASS_READ_ONLY`，单帧证据有效。CameraInfo 的
内参维度、畸变模型和非零内参已通过只读检查。生产近似多线程执行器下的 30 秒窗口内消息持续
可达且时间戳单调；排查发现 `joystick_control` 定时器的无限循环占用约 97% CPU，已在设备源/构建
副本修正为单次事件处理并重启。修复后 RGB/Depth 最大间隔降至 137–140 ms，IR 为 211 ms，
驱动错误扫描仍为 0；进一步的临时 IR-only A/B（关闭 RGB/Depth/PointCloud）达到 14.72 Hz、
最大间隔 76 ms 且无 >100 ms 间隔，确认问题来自共享负载调度而非 USB 枚举/内核错误。完整三流
配置已恢复并保持 `rgbd_enable=false`；稳定性保持 `PARTIAL_IN_SHARED_PROFILE`，详细对比见
`examples/mhs-landerpi/joystick-scheduler-fix-20260903.json` 和
`examples/mhs-landerpi/aurora-production-stability-post-joystick-fix-20260903.json`。
共享负载优化进一步在驱动中加入按订阅需求的点云转换：无点云订阅者时跳过昂贵的
`PointCloud2` 构造，但保留 `kPointCloud` SDK 流、topic 和完整点云能力；实际订阅仍取得
`width=256000` 的点云。绑核、整进程/单线程调优和移除二次限速均已做 A/B，其中无可重复收益
的方案全部回退。保留方案下 RGB/IR/Depth 仍持续可达且时间戳单调，驱动 timeout/disconnect/
publish failure 为 0；IR 共享配置连续性仍为 `PARTIAL`，进一步优化需要把 SDK 点云流拆分或动态
启停，而不能继续依靠进程级调度参数。证据见
`examples/mhs-landerpi/aurora-shared-load-optimization-20260903.json`。
基础标定窗口见 `examples/mhs-landerpi/aurora-stability-calibration-20260903.json`。USB、进程、内核和 ROS 日志及修复验证见
`examples/mhs-landerpi/aurora-diagnostic-20260903.json`。
急停/限位专项证据见 `examples/mhs-landerpi/estop-limits-evidence-20260903.json`。按用户现场约束，
本轮不执行急停/限位 proof-test；现场人员通过远程控制保障运行安全，该项作为操作前置条件记录，
不改变执行器写入仍需人工安全 owner 批准的 fail-closed gate。watchdog 明确作为未来客户交付项，
不纳入本轮 gate。

## 交付物

每个设备至少交付：

```text
discovery trace（source ref + 原始输出）
MHS manifest + manifest digest
driver/provider identity + digest
mhs://<device_id>/<capability> routes
RKB facts（observed_at/fresh_until/limitations）
identity resolution、channel 语义、command 限制（仅声明）
未解决映射和安全限制清单（severity、owner、next action）
```

所有交付物必须 machine-readable、带 schema/version，并可通过 deterministic canonicalization
重新计算相同 digest。RKB evidence 至少包含 `robot_id`、`target_host_fingerprint`、
`collector_id`、`deployment_mode`、`access=READ_ONLY`、`request_nonce`、`source_kind`、
`source_ref`、`observed_at`、`fresh_until`、`sha256`、manifest/driver digest、canonical route、
fact IDs 和 limitations。

## 分阶段交付与验收

| 阶段 | 范围 | 完成条件 |
|---|---|---|
| D0 | 范围、身份和 probe policy | 首批设备清单、owner、allowlist、权限和脱敏规则冻结 |
| D1 | inventory 与 trace | 每个节点有 source ref、collector、时间和 identity resolution |
| D2 | 具体设备识别 | USB/串口/I²C/SPI/GPIO/ROS 有设备级证据；未知项保持 UNKNOWN |
| D3 | MHS candidate/provider | schema、canonical digest、route、driver digest 验证通过 |
| D4 | RKB probe | 成功、断线、超时、越界、未知 channel、STALE 和错误均可追溯 |
| D5 | Gate readiness | digest/fingerprint/freshness/route 负测通过；未授权写请求 backend 调用为 0 |

最小负测包括：未批准地址、设备替换、重复 serial、path identity、fingerprint/digest 漂移、
过期 evidence、未知 channel、非法类型、NaN/越界值、transport timeout、断线和含 secret 的输出。

## 安全边界

本 TODO 不包含 reset、calibrate、setpoint、enable、power-cycle 或固件更新。真实执行器
写能力必须在 fake/simulation → 无负载台架 → 人工授权 canary 之后另行评审。
本需求不授予真实设备写权限，也不替代急停、碰撞检测、watchdog、功能安全控制器或硬件限位。
