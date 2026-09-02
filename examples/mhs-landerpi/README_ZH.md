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
