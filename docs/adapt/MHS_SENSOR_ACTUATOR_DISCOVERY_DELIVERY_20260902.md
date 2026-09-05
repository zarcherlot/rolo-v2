<!-- status: active; authority: reference; owner: rolo maintainers; last_reviewed: 2026-09-02 -->

# MHS Sensor/Actuator Discovery D0-D5 交付与验收

## 交付范围

本轮在 `mhs-discovery-full` worktree 完成只读 discovery 基础链路。所有真实目标操作均为
ICMP/TCP 可达性检查和 SSH 只读查询；没有执行 GPIO、串口、CAN、I²C/SPI 写入、ROS 控制
调用、服务重启或执行器命令。

## 阶段台账

| 阶段 | 状态 | 交付 | 验收证据 |
|---|---|---|---|
| D0 | PASS | 范围、身份优先级、probe allowlist、禁止操作、脱敏规则 | `config/mhs-discovery-policy.json` |
| D1 | PASS | `DiscoveryTrace`、输出 digest、secret 脱敏、Linux snapshot probe runner | `src/rolo/mhs_discovery.py` |
| D2 | PASS（含 UNKNOWN） | USB/串口/sysfs bus/GPIO/thermal/software stack 设备级映射 | `examples/mhs-landerpi/discovery-20260902.json` |
| D3 | PASS | 保守 MHS candidate 投影、canonical manifest/route、固定 `DISCOVERED_UNVERIFIED` | `build_snapshot_candidates()` + tests |
| D4 | PASS | MHS result → RKB EvidenceEnvelope；成功、失败和 freshness 约束 | `mhs_evidence_envelope()`、`snapshot_evidence_envelope()` + tests |
| D5 | PASS（只读 gate readiness） | path identity 写拒绝、digest/fingerprint/freshness/类型/范围负测 | 全量 pytest、ruff、compileall |

## 目标机事实

- 地址：`192.168.10.167/24`，网关 `192.168.10.1`；本机采集地址为 `192.168.10.220`。
- Raspberry Pi 5 Model B Rev 1.0，Debian 12，aarch64，serial `f96761a4f6b6d40e`。
- I²C：`/dev/i2c-1/11/12`；SPI：`/dev/spidev10.0`；GPIO：5 个 gpiochip。
- USB serial：稳定 by-id 映射到 `/dev/ttyACM0` 和 `/dev/ttyUSB1`；另有 Aurora 930、CH340、USB HUB、USB 音频设备。
- 运行栈包含 ROS 2/DDS、`robot_api`、`servo_controller`、`joint_state_pub`、`ekf_node`、`aurora930_node` 等。

## 验收命令与结果

```text
PYTHONPATH=src python -m pytest -q       PASS（全量，无失败，1 skipped）
PYTHONPATH=src python -m ruff check ...  PASS
python -m compileall -q src tests examples PASS
```

## 未解决项与后续门槛

1. 目标机宿主 shell 未安装 Rolo/Pydantic，故 provider/RKB replay 在控制器 worktree 完成；不能据此宣称目标机已部署 Rolo。
2. 目标机没有通过本轮读取到 I²C/SPI 子设备地址或芯片 ID；当前只证明 bus presence，具体 identity 仍为 `UNKNOWN`。
3. ROS2 CLI 在宿主 shell 不可用；ROS/DDS 进程关系来自只读进程/socket 观察，尚未形成 topic/service/action 的 schema 证据。
4. Ed25519 SSH host-key 签名校验失败；本轮使用同一目标公布的 ECDSA host key，长期信任前必须独立确认指纹。
5. `VERIFIED` 和任何真实 actuator write 仍需独立 Rolo gate、安全评审、fake/simulation、无负载台架和人工授权 canary；本轮没有执行这些动作。
