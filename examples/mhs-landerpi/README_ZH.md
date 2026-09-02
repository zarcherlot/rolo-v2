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
