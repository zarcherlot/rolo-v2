<!-- status: active; authority: TODO; owner: rolo maintainers; last_reviewed: 2026-09-02 -->

# 传感器与执行器 Discovery TODO

## 背景

当前 discovery 已确认 Linux 节点（I²C、SPI、GPIO、USB、thermal），但还没有完成：

```text
节点/总线 → 具体设备 → 稳定身份 → 协议/驱动 → MHS manifest → RKB evidence
```

因此最重要的传感器和执行器仍拿不到可用的 MHS。节点存在不等于设备身份、量程、命令
或安全限制已知；未知设备不能被猜测为可控设备。责任边界在 discovery：它负责追踪证据
和产出 candidate，不负责绕过安全 gate 执行控制。

## TODO（只读优先）

- [ ] **软件栈清点**：进程、systemd 服务、udev rules、内核 driver、ROS/DDS graph、
  串口/CAN/HTTP endpoint；记录 collector、时间和原始 source ref。
- [ ] **USB/串口追踪**：读取 VID/PID、接口、`/dev/serial/by-id`、serial 和 driver 绑定；
  将 CH340 等桥接节点追踪到上层协议，不凭 VID/PID 猜设备类别。
- [ ] **I²C/SPI 设备识别**：只对已批准地址执行无副作用的 identity probe；记录地址、芯片
  ID、bus、驱动和失败原因；禁止盲写寄存器。
- [ ] **GPIO 关系追踪**：读取 line name、consumer、chip/offset 和 device-tree/udev 来源；
  将 GPIO 线映射到传感器输入或执行器驱动，但不切换输出电平。
- [ ] **执行器控制链追踪**：从 driver/daemon/ROS service/action 找到 enable、stop、
  feedback、limit、mode 和 fault；首轮只读取状态和反馈。
- [ ] **稳定身份判定**：serial、device-tree、udev-by-id、controller resource ID 优先；
  只有路径的设备标记 `identity_stability=path`，禁止进入写能力或 VERIFIED。
- [ ] **生成 MHS candidate**：为每个具体 sensor/actuator 生成 manifest、route、channels、
  state、commands、limits、driver digest；状态固定为 `DISCOVERED_UNVERIFIED`。
- [ ] **只读 provider probe**：执行 `inspect/status/read`，校验类型、单位、范围、断线和
  freshness；结果写入 RKB Fact/EvidenceEnvelope。
- [ ] **Rolo gate 对接**：只有 identity、digest、observed evidence 和 safety 前置条件齐全，
  才允许 `ELIGIBLE/VERIFIED`；任何不确定性保留为 UNKNOWN/UNAVAILABLE。

## 交付物

每个设备至少交付：

```text
discovery trace（source ref + 原始输出）
MHS manifest + manifest digest
driver/provider identity + digest
mhs://<device_id>/<capability> routes
RKB facts（observed_at/fresh_until/limitations）
未解决映射和安全限制清单
```

## 安全边界

本 TODO 不包含 reset、calibrate、setpoint、enable、power-cycle 或固件更新。真实执行器
写能力必须在 fake/simulation → 无负载台架 → 人工授权 canary 之后另行评审。
