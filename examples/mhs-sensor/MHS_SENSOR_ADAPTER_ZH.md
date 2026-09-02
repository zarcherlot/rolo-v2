<!-- status: draft; authority: guide; owner: rolo maintainers; last_reviewed: 2026-09-02 -->

# MHS 物理硬件适配指南（传感器兼容实现）

本文保留原有传感器示例，但 MHS 在 Rolo v2 中的目标范围已经扩展到控制器、执行器、电源、
计算模块、总线、工具端和其他物理硬件。现有代码是传感器 compatibility seam，不是官方
MHS conformance 实现。

## 1. MHS 是什么

Anthropic 在 2026-08-27 公布的 **Model Hardware Standard（MHS）** 是一套
让 AI agent 发现、理解和安全操作物理设备的标准化方法。它目前是 research
preview，不应与已经稳定发布的 MCP 规范混为一谈。

公开描述的 MHS 由三部分组成：

1. **标准化 driver**：把厂商 SDK、串口、USB、ROS 或 HTTP 接口翻译成设备无关的
   `read` / `write` 原语；
2. **设备 reference/manifest**：描述设备身份、状态、可测量量、可调参数、物理
   约束和安全上限；
3. **控制通道**：MCP、CLI 和代码/API。MCP 是让 agent 调用 driver 的一种通道，
   不是 MHS 的全部。

因此，“实现传感器的 MHS”不是给传感器刷一个 MCP 固件，而是在传感器旁边提供
一个有界的 driver，并把设备能力和物理限制结构化暴露给 agent。

## 2. 传感器的最小架构

```text
┌──────────────┐   USB/串口/ROS/HTTP   ┌───────────────────┐
│ 真实传感器    │ ◄────────────────────► │ SensorBackend     │
└──────────────┘                         │ 厂商协议适配      │
                                         └─────────┬─────────┘
                                                   │ 有界 read/status/reset
                                         ┌─────────▼─────────┐
                                         │ MhsSensorProvider  │
                                         │ manifest + limits  │
                                         └─────────┬─────────┘
                                                   │ ProviderHost / MCP
                                         ┌─────────▼─────────┐
                                         │ Claude / 其他 Agent │
                                         └────────────────────┘
```

本仓库的兼容性原型位于 `examples/mhs-sensor/mhs_sensor.py`。它复用了目标 Provider SPI
的 `ProviderHost` 概念；由于当前 rolo-v2 基线尚未提供 `rolo.capabilities` 包，该原型暂不
属于生产运行链，写操作也不能据此宣称已接入 Runtime policy。

## 3. 设备 reference 示例

下面是一个温度和门磁传感器的最小 manifest。字段名是本项目的
`mhs-sensor-reference/v0-preview` 兼容层格式；官方 MHS 最终 schema 发布后，
只需增加一个转换器，不要把 agent 直接绑定到厂商字段。

```json
{
  "schema_version": "mhs-sensor-reference/v0-preview",
  "device_id": "cabinet-1",
  "name": "Cabinet environmental sensor",
  "vendor": "Example",
  "model": "ENV-1",
  "modality": "environmental",
  "channels": [
    {
      "id": "temperature",
      "name": "Temperature",
      "unit": "degC",
      "value_type": "number",
      "min_value": -20,
      "max_value": 80,
      "nominal_rate_hz": 1
    },
    {
      "id": "door_open",
      "name": "Door open",
      "unit": "bool",
      "value_type": "boolean"
    }
  ],
  "transport": {
    "kind": "serial",
    "properties": {"path": "/dev/ttyUSB0", "baudrate": 115200}
  },
  "safety_limits": [
    "read-only measurements",
    "reject non-finite numeric values",
    "reject values outside channel bounds"
  ]
}
```

Manifest 的关键原则：

- `device_id` 必须稳定且唯一，不要使用每次启动都会变化的地址；
- 每个通道都要有单位；
- 能定义的物理上限和下限都应写入 manifest，并在 driver 中再次强制检查；
- 不把串口密码、网络 token 或任意 shell 命令放入 manifest；
- 传感器只读能力与 reset/calibrate 等写能力分开声明。

## 4. 编写硬件 backend

硬件相关代码只实现三个有界方法：

```python
class MySensorBackend:
    def read(self) -> dict[str, float | bool]:
        # 在这里调用厂商 SDK/串口协议；返回 channel id -> value
        return {
            "temperature": vendor_sdk.read_temperature_c(),
            "door_open": vendor_sdk.read_door_switch(),
        }

    def status(self) -> dict[str, object]:
        return {
            "health": vendor_sdk.health(),
            "firmware": vendor_sdk.firmware_version(),
        }

    # 可选：只有真的需要远程复位时才实现，并保持为显式写能力
    def reset(self, profile_id: str) -> dict[str, object]:
        if profile_id not in {"soft"}:
            raise ValueError("unsupported reset profile")
        vendor_sdk.soft_reset()
        return {"change_id": uuid.uuid4().hex, "profile_id": profile_id}
```

`MhsSensorProvider` 会在 provider 边界完成以下检查：未知通道、类型错误、NaN/无穷
值、超出 manifest 安全范围的值都会变成 `UNAVAILABLE`，而不会送给 agent。

## 5. 注册到 Rolo ProviderHost

```python
from rolo.capabilities import ProviderHost
from rolo.mhs_sensor import MhsSensorProvider, SensorChannel, SensorManifest

provider = MhsSensorProvider(manifest, MySensorBackend())

with ProviderHost(timeout_s=3.0) as host:
    registration = host.register(provider)
    # registration.status == REGISTERED
    result = host.invoke(
        provider.provider_id,
        InvokeRequest(
            capability_id="sensor.read",
            route_ref="mhs://sensor/cabinet-1/read",
        ),
    )
```

自动声明的能力是：

| 能力 | 访问 | 风险 | 作用 |
|---|---|---|---|
| `sensor.inspect` | read | R0 | 返回设备 reference |
| `sensor.read` | read | R0 | 返回一次有界快照 |
| `sensor.status` | read | R0 | 返回健康和诊断信息 |
| `sensor.reset`（可选） | write | R2 | 复位；必须经过 Runtime policy |

当前实现是 request/response 快照，不是无限流。要做高频流式传感器，建议先在 driver
进程中做采样、降采样和背压，再以有界窗口（例如 1 秒或 100 个样本）交给 MCP，
不要让模型直接消费无限队列。

## 6. 与 MCP 的映射

MCP tool 名称可以保持语义稳定，而把设备地址放到受验证的 route 中：

```text
sensor.read   -> mhs://sensor/<device_id>/read
sensor.status -> mhs://sensor/<device_id>/status
sensor.reset  -> mhs://sensor/<device_id>/reset
```

MCP 层只负责协议和会话，不负责重新实现物理安全策略。调用链应保持：

```text
MCP tools/call
  -> ProviderHost 路由校验
  -> Runtime policy（写能力）
  -> MhsSensorProvider
  -> SensorBackend
```

## 7. 从 Sensor 扩展到通用 MHS Device

通用模型不应为每种硬件复制一套 Provider SPI。建议以一个 device reference/manifest
描述共同字段：device_id、device_class、vendor/model/serial、transport、resources、state、
commands、limits，以及 driver 的 provider_id、version 和 digest。

device_class 至少包括 sensor、controller、actuator、power、compute、bus、tool 和
end-effector。不同设备只是 capability 组合不同：

| 类别 | 读能力示例 | 写能力示例 | 典型风险 |
|---|---|---|---|
| sensor | inspect/read/status/calibration | reset/calibrate | R0/R2 |
| controller | status/faults/limits/mode | enable/mode/reset/configure | R0/R2–R3 |
| actuator | state/feedback/limits | bounded setpoint/stop/home | R0–R3 |
| power | rails/voltage/current/health | bounded power-cycle | R0/R3 |
| bus/compute | topology/health/firmware | scan/reset/update | R0/R2–R3 |
| tool/end-effector | presence/state/calibration | open/close/grasp | R0/R2–R3 |

route 统一为 `mhs://<device_id>/<capability_id>`。传感器 channel 的 min/max 不能直接
复用为执行器安全边界；通用 manifest 必须区分 measurement validity、operating limit、
hard stop 和 authorization limit，并给出各自的 authority/source。写能力还必须声明
timeout、cancel、idempotency、quiescence、resource lock、compensation/rollback 和
state_safety 前置条件。

## 8. 与 Rolo v2 Robot Knowledge Base 的绑定

MHS manifest 属于 DECLARED/PROVIDER 证据；driver probe、status、read，以及由独立 Write
Execution 层经 MHS Provider 调用产生的结果属于目标 OBSERVED 证据。每次结果必须带 robot_id、target fingerprint、Collector、
manifest/driver digest、route、observed_at、fresh_until、fact IDs 和 limitations。

本示例不是 RKB 写执行器。Probe 只读采集；实际 reset/calibrate 或其他写操作必须由 Rolo
Write Execution session 在授权、状态前置条件和审计约束下调用 Provider，执行前后证据再写回 RKB。

MCP、CLI、代码/API 只是同一 MHS route 的不同控制通道，不是新的事实来源。读写调用链应区分为：

```text
只读：Agent -> Probe/typed RKB query -> MHS Provider -> bounded driver -> physical device
受控写：Agent -> typed RKB query（资格/前置条件） -> Rolo Write Execution session/policy
       -> MHS Provider -> bounded driver -> physical device
```

`MhsSensorProvider` 的 `ProviderHost` 注册成功只代表本地 provider contract 可解析，不能
单独证明目标硬件已绑定、能力已验证或可以进入 release。通用 MHS Provider 应由 Probe
生成 evidence，再由 Rolo capability gate 产生 DISCOVERED_UNVERIFIED、ELIGIBLE、VERIFIED、
UNAVAILABLE 或 STALE 状态。

官方 MHS wire schema/conformance 尚未公开时，本仓库只能声明 Rolo 的 MHS-compatible profile。

## 9. 上线前检查清单

- 先在 Provider SPI 补齐后用 fake backend 跑 `examples/mhs-sensor/test_mhs_sensor.py`，再接真实设备；
- 为每个通道写类型、单位、范围和采样率测试；
- 测试断线、超时、重复读取、时间戳和设备重启；
- 对 reset/calibrate 保持人工确认或短时授权；
- 记录设备 ID、manifest digest、driver 版本和原始观测时间；
- 传感器的“读到一个数”不等于物理结果已经被验证，仍需独立的校准和验收证据；
- 等官方 MHS schema 和 conformance 测试开放后，再声明正式兼容。
