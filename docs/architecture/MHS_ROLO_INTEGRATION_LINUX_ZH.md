<!-- status: canary; authority: implementation note; owner: rolo maintainers; last_reviewed: 2026-09-02 -->

# Linux MHS 接入 Rolo 设计（含 landerpi 观测）

## 边界

`src/rolo/mhs_hardware.py` 是硬件无关的 MHS device/provider 契约，`src/rolo/mhs_adapters.py`
是软件环境适配 SPI；`src/rolo/mhs_linux.py` 只是其中一个 procfs/sysfs 实现。相同的
manifest 和 `mhs://<device_id>/<capability>` route 可以由 native、ROS 2、serial/USB、HTTP
或 simulation adapter 提供。Linux adapter 读取 CPU 温度、内存占用、负载、设备
型号/serial 和 transport presence；不执行 shell，不写设备，不做 reset、setpoint、power-cycle
或固件更新。landerpi 只作为一次性观测样本保存，不构成专用实现。官方 MHS wire schema
尚未公开，因此发布标识为 **Rolo MHS-compatible profile**，不是官方 conformance。

## 调用链

```text
Agent
  -> RKB typed query / MCP adapter
  -> Rolo session + capability gate
  -> MhsDeviceProvider (mhs://<device_id>/{inspect,status,read})
  -> MhsAdapterRegistry -> selected environment adapter
  -> MhsBackend (bounded read/status)
  -> target hardware/software stack
```

`MhsDeviceManifest` 是 DECLARED/PROVIDER 证据；`status` 和 `read` 是目标 OBSERVED 证据。
Provider 注册成功只能得到 `DISCOVERED_UNVERIFIED`，不能直接得到 `ELIGIBLE` 或 `VERIFIED`。
要进入后续 gate，Probe 必须把以下字段写入 RKB evidence envelope：

- `robot_id`、target fingerprint、collector、deployment mode 和 request nonce；
- manifest canonical SHA-256、driver id/version/SHA-256；
- canonical route `mhs://<device_id>/read`（以及 inspect/status）；
- `observed_at`、`fresh_until`、fact IDs 和 limitations；
- transport 与实际设备 identity（serial 优先于路径）。

Provider 的每个 `MhsResult` 已返回 manifest/driver 摘要、transport、route、观测时间和
5 分钟 freshness window；RKB 负责把这些结果绑定到目标 identity，并在过期或 fingerprint
不一致时拒绝消费。读数类型、非有限值、未知 channel 和上下限在 provider 边界 fail closed。

软件环境适配器只负责把环境转换成 `MhsBackend.read/status`。环境 `kind` 是开放的
插件标识，不是 Rolo 内置枚举；下面只是可能的实现示例，并不表示 Rolo 捆绑这些 SDK：

| kind 示例 | 典型实现 | 设备身份/route |
|---|---|---|
| native | 厂商 SDK、系统 API | manifest 中的稳定 serial/resource |
| ros2（可选） | topic/service/action bridge（首版只读） | 同一 `mhs://<device_id>/...` |
| serial/USB | 有界帧协议 driver | USB serial/设备 reference |
| HTTP | TLS endpoint + schema 校验 | endpoint 不能代替 device identity |
| simulation | fake/replay backend | 明确标记 simulation，不得冒充 observed hardware |

因此硬件类型（sensor/controller/actuator 等）和软件环境是两个独立维度；更换任意
adapter 不会复制一套 RKB identity，也不会绕过同一个 provider safety gate。

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

## 写接口（simulation-first）

MHS manifest 可以声明强类型 write command，但普通 `MhsDeviceProvider.invoke()` 不能执行它。
写请求必须经过 Rolo-owned `MhsWriteController`：

```text
MhsWriteRequest + verified MhsWriteContext
  -> route/identity/digest/freshness/authorization/precondition
  -> process-local resource lock
  -> bounded input schema
  -> MhsWriteBackend.write (timeout -> optional stop)
  -> auditable MhsWriteResult
```

默认只允许 `fake`/`simulation` environment；native、ROS、serial、HTTP 等真实 adapter 即使
声明了 command 也会被拒绝。W3 台架还要求 external estop clear、watchdog healthy 和
resource quiescent，并支持短时人工授权引用。首轮实现和后续台架/真机门槛见
[`MHS_WRITE_CAPABILITY_DEVELOPMENT_PLAN_ZH.md`](../adapt/MHS_WRITE_CAPABILITY_DEVELOPMENT_PLAN_ZH.md)。

W4 实现 `MhsCanaryGate` admission preflight 和 `MhsCanaryRunner`：前者验证独立安全评审、R1
命令、目标指纹、人工批准、急停/stop/rollback 证据和有限次数 lease；后者默认关闭，只有部署方
显式启用并配置 controller 环境白名单后才执行，且把 lease ID 绑定到审计结果。两者都不会自行
发起网络或硬件 I/O。
