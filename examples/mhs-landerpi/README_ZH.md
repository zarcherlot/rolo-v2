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

本次通过 SSH 只读采集的 ROS graph 保存在
[`ros-graph-20260902.json`](ros-graph-20260902.json)。其中 `/joint_states`、`/imu`、`/scan`、
`/odom` 和 battery topic 是只读观测候选；`/cmd_vel`、motor/servo topic 以及 arm/gripper
trajectory action 仅记录为 `write-candidate/DISCOVERED_UNVERIFIED`。没有调用任何写 topic、
service 或 action，也没有由此生成可执行的 R1 MHS command。

## 已确认 manifest

[`mhs_manifests.py`](mhs_manifests.py) 生成 6 条带证据的记录：`landerpi-rrc` 为
`CONFIRMED_READ_ONLY`；`landerpi-arm` 为 `CONFIRMED_BOUND_WRITE_BLOCKED`，绑定
`landerpi-rrc:5b22016029:bus-servo:arm`、`joint1..joint5 -> servo ID 1..5` 和 R1
`stop_arm` command；`landerpi-gripper` 已绑定到 bus-servo ID 10 和 R1 `stop_gripper`，
但与 arm 一样保持写阻断；`landerpi-ld19`、`landerpi-base-drive` 和
`landerpi-aurora930` 仍为 `DISCOVERED_UNVERIFIED`。arm/gripper 的 external-estop、stop、
rollback、watchdog、no-load 证据仍未齐全，因此 manifest 明确禁止写入。确认记录要求来源
证据；“有 manifest”与“允许写入”仍是两个独立条件。

当前已观察到 Aurora 930 相机（USB `3251:1930`、`/dev/video19..37` 和 RGB/depth/IR
话题），但未观察到 USB serial，因此 `landerpi-aurora930` 仍是路径身份候选。LD19 的
`landerpi-ld19` 同样需稳定设备身份、驱动摘要和 `/scan` freshness 证据后才能升级。通用
Linux inventory 会在实际出现 `/dev/video*` 时生成 camera candidate，并保持
`DISCOVERED_UNVERIFIED`。

`src/rolo/mhs_watchdog.py` 提供厂商 watchdog 的只读 discovery/status 协议和无 I/O 的
`WatchdogTestFixture`。它用于验证 heartbeat 丢失、超时、trip 和 safe-state readback，
不代表真实 LanderPi 已安装独立 watchdog。
