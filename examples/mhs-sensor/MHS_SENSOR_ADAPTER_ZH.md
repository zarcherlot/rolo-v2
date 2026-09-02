<!-- status: active; authority: guide; owner: rolo maintainers; last_reviewed: 2026-09-02 -->

# MHS 只读 Provider 示例

`src/rolo/mhs_hardware.py` 是 Rolo v2 的唯一 Provider SPI。它是 MHS-compatible profile，
不是对未公开 wire schema 的官方实现。示例适配器位于 `examples/mhs-sensor/`，不绕过
Rolo 的 RKB identity、digest 和 Gate。

## Manifest 与 backend

`MhsDeviceManifest` 统一描述 `device_id`、`device_class`、vendor/model/serial、channels、
transport、limits 以及 driver digest。backend 只提供两个有界、无副作用的方法：

```python
class SensorBackend:
    def read(self) -> dict[str, float | bool | str]: ...
    def status(self) -> dict[str, object]: ...
```

每个测量值都会经过 channel 类型、有限数值和 min/max 检查；未知 channel、超界值、NaN、
断线或超时都返回 `UNAVAILABLE`，不把异常对象或任意命令交给 Agent。

## 当前 v2 能力与 route

首个交付只暴露以下三个只读能力：

| capability | route | 结果 |
|---|---|---|
| `inspect` | `mhs://<device_id>/inspect` | manifest 快照 |
| `status` | `mhs://<device_id>/status` | 健康/连接状态 |
| `read` | `mhs://<device_id>/read` | 带时间戳的有界 samples |

`reset`、`calibrate`、`setpoint`、`stop`、`power-cycle` 以及任何未知 capability 均被
Provider 边界拒绝为 `UNAVAILABLE`。它们不属于当前 v2 release，也没有隐式 authorizer
旁路。每个成功结果携带 manifest/driver evidence IDs 和 canonical route；Provider 注册
成功本身不提升 capability 状态。

本示例不是 RKB 写执行器。Probe 只读采集；未来实际写操作必须由独立的 Rolo Write
Execution session 在授权、状态前置条件和审计约束下调用 Provider，执行前后证据再写回 RKB。

## 运行与测试

安装项目依赖后运行：

```bash
uv sync --locked --dev
uv run pytest tests/test_mhs_hardware.py examples/mhs-sensor/test_mhs_sensor.py
```

测试覆盖 fake backend、未知 channel、类型/NaN/范围拒绝和写能力拒绝。没有 pytest 或
运行时依赖时必须标记为 `BLOCKED`，不能把示例文件存在当作集成完成。
