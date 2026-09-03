# Linux MHS 只读抽象与 landerpi 观测记录

通用实现位于 [`src/rolo/mhs_hardware.py`](../../src/rolo/mhs_hardware.py) 和
[`src/rolo/mhs_adapters.py`](../../src/rolo/mhs_adapters.py)；Linux procfs/sysfs 只是一个
可替换环境适配器，Rolo 不捆绑 ROS 2 或其他环境 SDK。它不绑定 Raspberry Pi、网络
地址、厂商或凭据。该目录只保留 landerpi 的一次性观测记录，不是 landerpi 专用驱动。

## 设备事实

2026-09-02 通过局域网扫描记录：目标地址 `192.168.10.167/24`、网关 `192.168.10.1`，
设备为 `Raspberry Pi 5 Model B Rev 1.0`、aarch64 Debian 12。记录到 CPU thermal zone、
`/dev/i2c-1`、`/dev/spidev10.0`、5 个 GPIO chip 和多个 USB 设备。

## 本地验证

在仓库根目录执行：

```bash
PYTHONPATH=src python examples/mhs-linux/mhs_linux_canary.py
pytest tests/test_mhs_linux.py tests/test_mhs_hardware.py
```

## 真机 canary

目标机没有安装 Rolo/Pydantic，因此观测脚本只依赖 Python 标准库。使用 SSH 的
`ecdsa-sha2-nistp256` host-key 算法后，可对任意 Linux 目标执行：

```bash
ssh -o HostKeyAlgorithms=ecdsa-sha2-nistp256 pi@192.168.10.167 \
  'python3 /tmp/mhs_linux_canary.py'
```

随后将 payload 作为 observed evidence 输入 Rolo 的 `MhsDeviceProvider`；任何未知通道、
非有限值或越界值都会在 provider 边界拒绝。该 canary 不能提升 capability 到
`VERIFIED`，也不会开放写能力。

本次真机采样已脱敏保存为 [`canary-20260902.json`](canary-20260902.json)，其中仅包含
设备型号、稳定 serial、驱动摘要和只读数值，不包含账户或密码。

通用节点发现结果保存在 [`inventory-20260902.json`](inventory-20260902.json)。其中 3 个
I²C、1 个 SPI、5 个 GPIO、1 个 thermal zone 和 10 个 USB sysfs 节点都只是
`DISCOVERED_UNVERIFIED`，尚未代表已经绑定或验证的物理外设。

## LanderPi MHS 采样包

[`mhs-bundle-20260902.json`](mhs-bundle-20260902.json) 是基于本次只读观测生成的
`rolo-mhs-bundle/v1`。它为 Aurora 930 深度相机、LiDAR、ROS robot controller 和
servo actuator group 分别生成 `sensor`、`controller`、`actuator` manifest，并附带
证据引用、置信度、限制和下一步采样契约。

本次在 `MentorPi` ROS 2 Humble 容器内的只读 graph 记录见
[`ros-graph-20260902.json`](ros-graph-20260902.json)，已确认 Aurora 节点的图像/点云
topic、`/scan` 的 LaserScan topic，以及控制器的 joint/servo state topic；消息 payload
重启前曾未读取。重启后的有限窗口 payload 读取结果见
[`ros-payload-20260903.json`](ros-payload-20260903.json)，此前重启前的记录仍保留在
[`ros-payload-20260902.json`](ros-payload-20260902.json)。本次已通过只读 rclpy 订阅取得
LaserScan、Image、JointState 和 ServoStateList 的结构化摘要；条目仍不会自动提升为
`VERIFIED`。

2026-09-03 进一步使用 `reliable` 与 `best_effort` 两种只读 QoS 进行 6 秒有界读取，
并检查 `/scan_raw` 上游、ROS workspace overlay 和容器网络模式；结果见
[`ros-diagnostic-20260903.json`](ros-diagnostic-20260903.json)。重启后使用工作区 overlay
进行直接订阅，已确认运行时 payload 可达；此前的 QoS 回退失败记录保留用于对比。
结构化 fixture 见 [`ros-structured-fixture-20260903.json`](ros-structured-fixture-20260903.json)。

fixture 可通过 `examples/mhs-landerpi/evaluate_fixture.py` 加载到
`MhsReplayBackend`，再执行只读门禁评估；本次评估结果见
[`mhs-gate-20260903.json`](mhs-gate-20260903.json)。Aurora 930 已达到 `ELIGIBLE`，
但尚未 `VERIFIED`；LiDAR、控制器和舵机组仍因缺少稳定物理身份及安全绑定而被拒绝。

物理绑定阶段的只读证据见
[`physical-binding-20260903.json`](physical-binding-20260903.json)。其中记录了 Aurora
USB serial 与 ROS 进程的关联、LiDAR 的 `/dev/ldlidar -> /dev/ttyUSB0` 及 LD19 launch
配置、控制器的 `/dev/rrc -> /dev/ttyACM0` 稳定 by-id，以及逻辑 joint 到观测舵机 ID 的
配置映射。该 artifact 明确标注了 `PARTIAL_IDENTITY`、`PARTIAL_CHANNEL_MAPPING` 和
`init_finish=false` 等限制；它是安全评审和 conformance 的输入，不是移动执行器的授权。

安全门清单见 [`safety-review-20260903.json`](safety-review-20260903.json)，当前控制器与
舵机保持 `BLOCKED_FOR_WRITE_AND_VERIFIED`，急停、限位、watchdog 和 fault-clear 均未验证。
急停/限位的只读搜索结果见
[`estop-limits-evidence-20260903.json`](estop-limits-evidence-20260903.json)；发现的
`/enable`、`/hand_trajectory/stop` 等名称不具备安全权威性，未调用任何服务。
用户补充确认设备存在物理急停键和机械限位块；当前仅记录为声明，尚未完成回路、复位和
行程边界 proof-test。watchdog 延后为未来客户交付项，不作为本轮实现目标。
可重复的只读 conformance 检查由 `conformance_check.py` 执行，结果见
[`conformance-20260903.json`](conformance-20260903.json)；当前报告为 `PASS_READ_ONLY`。
RGB/IR 两个 65 字符摘要已按序列化纠正规则归一化，修复记录见
[`fixture-repair-20260903.json`](fixture-repair-20260903.json)。由于原始图像字节未保留，
后续仍应以重新采集的真实字节哈希替换它们，不能作为高保证证据使用。
本次按授权重启传感器节点后的重新采集记录见
[`ros-reacquisition-20260903.json`](ros-reacquisition-20260903.json)：节点进程存在，但
15 秒有界窗口仍无图像首帧，摘要保持待替换状态。

生成命令：

```bash
PYTHONPATH=src python examples/mhs-landerpi/generate_mhs.py
```

这四个条目全部保持 `DISCOVERED_UNVERIFIED`，且没有写命令。另一个工程可以直接
校验 bundle 后按采样契约补充 ROS topic、设备序列号、量程、故障/限位和急停证据；
只有证据充分时才应将条目提升为 `VERIFIED`，并另行提交经过安全评审的写适配器。
每个条目还带有 `owner`、`target_host`、`dependencies`、`stage`、`next_action` 和
machine-readable `sampling_plan`；采样动作仅允许 `inspect/status/read/read_structured`
等只读操作，后续项目可以据此调度采样，而不需要从自然语言重新推断权限。
