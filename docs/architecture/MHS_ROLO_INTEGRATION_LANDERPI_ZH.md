<!-- status: canary; authority: implementation note; owner: rolo maintainers; last_reviewed: 2026-09-02 -->

# landerpi 的 MHS 接入 Rolo 设计

## 边界

`examples/mhs-landerpi/mhs_landerpi.py` 是 landerpi（Raspberry Pi 5）的只读 Linux
硬件 driver。它读取 procfs/sysfs 的 CPU 温度、内存占用、负载、设备型号/serial 和
transport presence；不执行 shell，不写 GPIO/I²C/SPI，不做 reset、setpoint、power-cycle
或固件更新。官方 MHS wire schema 尚未公开，因此发布标识为 **Rolo MHS-compatible
profile**，不是官方 conformance。

## 调用链

```text
Agent
  -> RKB typed query / MCP adapter
  -> Rolo session + capability gate
  -> MhsDeviceProvider (mhs://landerpi/{inspect,status,read})
  -> LanderPiBackend (bounded procfs/sysfs reads)
  -> landerpi hardware
```

`MhsDeviceManifest` 是 DECLARED/PROVIDER 证据；`status` 和 `read` 是目标 OBSERVED 证据。
Provider 注册成功只能得到 `DISCOVERED_UNVERIFIED`，不能直接得到 `ELIGIBLE` 或 `VERIFIED`。
要进入后续 gate，Probe 必须把以下字段写入 RKB evidence envelope：

- `robot_id`、target fingerprint、collector、deployment mode 和 request nonce；
- manifest canonical SHA-256、driver id/version/SHA-256；
- canonical route `mhs://landerpi/read`（以及 inspect/status）；
- `observed_at`、`fresh_until`、fact IDs 和 limitations；
- transport 与实际设备 identity（serial 优先于路径）。

Provider 的每个 `MhsResult` 已返回 manifest/driver 摘要、transport、route、观测时间和
5 分钟 freshness window；RKB 负责把这些结果绑定到目标 identity，并在过期或 fingerprint
不一致时拒绝消费。读数类型、非有限值、未知 channel 和上下限在 provider 边界 fail closed。

## 真机验证记录

2026-09-02 在局域网 `192.168.10.0/24` 扫描到目标 `192.168.10.167`（网关
`192.168.10.1`），通过 SSH `pi` 登录确认：Raspberry Pi 5 Model B Rev 1.0、Debian 12、
aarch64、serial `f96761a4f6b6d40e`。只读 canary 输出保存在
[`examples/mhs-landerpi/canary-20260902.json`](../../examples/mhs-landerpi/canary-20260902.json)。

目标机未安装 Rolo/Pydantic，故 canary 使用标准库采集原始 observed payload；在控制器侧
将相同 payload 喂入 `MhsDeviceProvider`，再由 RKB envelope 做身份、digest 和 freshness
校验。这避免在公开设备上安装依赖或留下凭据，同时仍验证真实硬件路径。

## 后续变更门槛

任何写能力都必须单独 RFC：稳定 `hardware_resource_id`、state/safety 前置条件、
quiescence/resource lock、短时人工授权、超时/取消、stop 和 compensation/rollback。
在这些证据和官方 schema/conformance 测试具备前，保持本 provider 只读并禁止 release gate
将 canary 解释为物理安全验证。
