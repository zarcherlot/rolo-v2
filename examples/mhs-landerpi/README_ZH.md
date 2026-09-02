# landerpi MHS 只读 canary

该目录把 `192.168.10.167` 上 Raspberry Pi 5 的 Linux 硬件观测接入 Rolo 的
`MhsDeviceProvider`。目前只开放 `inspect`、`status`、`read`，不触碰 GPIO/I²C/SPI，
也不包含 SSH 密码或其他 secret。

## 设备事实

2026-09-02 通过局域网扫描确认：`192.168.10.167/24`、网关 `192.168.10.1`，目标为
`Raspberry Pi 5 Model B Rev 1.0`，aarch64 Debian 12。目标上观察到 CPU thermal zone、
`/dev/i2c-1`、`/dev/spidev10.0`、5 个 GPIO chip 和多个 USB 设备。

## 本地验证

在仓库根目录执行：

```bash
PYTHONPATH=src python examples/mhs-landerpi/mhs_landerpi.py --json
pytest tests/test_mhs_landerpi.py tests/test_mhs_hardware.py
```

## 真机 canary

目标机没有安装 Rolo/Pydantic，因此 canary 脚本只依赖 Python 标准库，输出与 Rolo
provider 相同的只读事实边界。使用 SSH 的 `ecdsa-sha2-nistp256` host-key 算法后执行：

```bash
ssh -o HostKeyAlgorithms=ecdsa-sha2-nistp256 pi@192.168.10.167 \
  'python3 /tmp/mhs_landerpi.py --json'
```

随后将 payload 作为 observed evidence 输入 Rolo 的 `MhsDeviceProvider`；任何未知通道、
非有限值或越界值都会在 provider 边界拒绝。该 canary 不能提升 capability 到
`VERIFIED`，也不会开放写能力。

本次真机采样已脱敏保存为 [`canary-20260902.json`](canary-20260902.json)，其中仅包含
设备型号、稳定 serial、驱动摘要和只读数值，不包含账户或密码。
