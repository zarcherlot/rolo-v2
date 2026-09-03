<!-- status: active; authority: plan; owner: rolo maintainers; last_reviewed: 2026-09-02 -->

# 传感器与执行器 Discovery 需求

## 背景

当前 discovery 已确认 Linux 节点（I²C、SPI、GPIO、USB、thermal），但还没有完成：

```text
节点/总线 → 具体设备 → 稳定身份 → 协议/驱动 → MHS manifest → RKB evidence
```

因此最重要的传感器和执行器仍拿不到可用的 MHS。节点存在不等于设备身份、量程、命令
或安全限制已知；未知设备不能被猜测为可控设备。责任边界在 discovery：它负责追踪证据
和产出 candidate，不负责绕过安全 gate 执行控制。

## 目标与范围

本需求的目标是把 Linux 节点或总线上的**具体设备**追踪为可审计的 MHS candidate，
并为后续 Rolo capability gate 提供目标绑定、可复现、只读的证据。

首批范围按以下优先级执行：

1. 已确认会影响安全或运动决策的 sensor/actuator；
2. 已存在稳定 serial、device-tree resource ID 或 controller resource ID 的设备；
3. 能从 driver、daemon 或 ROS/DDS graph 找到明确协议和反馈的设备；
4. 仅能证明节点存在、但无法解析具体设备身份的 bus/node，作为 presence-only candidate 保留。

每个设备必须有 owner、目标主机、依赖、当前阶段和下一步行动。未列入首批设备清单的对象不得以“最重要”作为完成依据。

## 状态与资格

Discovery 产生的 candidate 状态固定为 `DISCOVERED_UNVERIFIED`，不能因为 manifest
生成或 provider 注册而升级。状态转换必须按 capability 分别评估：

```text
DECLARED
  -> DISCOVERED_UNVERIFIED
  -> ELIGIBLE
  -> VERIFIED
  -> STALE / UNAVAILABLE
```

- `DECLARED`：静态配置或 manifest 声明，尚未有目标观测。
- `DISCOVERED_UNVERIFIED`：已发现并有 trace，但身份、协议或运行时证据仍未完成。
- `ELIGIBLE`：canonical route、provider、目标身份、manifest/driver digest 和有效运行时 evidence 齐全，且无未解决冲突。
- `VERIFIED`：通过 Rolo gate/conformance；不是 discovery 单独可以授予的状态。
- `STALE`：evidence 超过 freshness deadline；`UNAVAILABLE`：探测失败、设备断线或能力明确不可用。

只具备 path identity 的设备可以保留为只读 candidate；不得进入 `VERIFIED`，不得进入写 gate。
缺失或冲突的信息必须保留为 `UNKNOWN`，不得用静态声明填补。

## Discovery 工作包（只读）

- [ ] **软件栈清点**：进程、systemd 服务、udev rules、内核 driver、ROS/DDS graph、
  串口/CAN/HTTP endpoint；记录 collector、目标 identity、时间、命令/查询、退出码和原始 source ref。
  命令行、环境变量、配置和 URL 中的 secret 必须脱敏。
- [ ] **USB/串口追踪**：读取 VID/PID、接口、`/dev/serial/by-id`、serial 和 driver 绑定；
  将 CH340 等桥接节点追踪到上层协议，不凭 VID/PID 猜设备类别。首轮禁止发送串口数据；
  需要协议握手时必须另有批准的只读 probe、超时和重试预算。
- [ ] **I²C/SPI 设备识别**：只对已批准地址执行无副作用的 identity probe；记录地址、芯片
  ID、bus、驱动和失败原因；禁止盲写寄存器。批准地址、允许读取的寄存器/命令及审批引用
  必须作为 trace 的一部分保存；未批准地址一律不访问。
- [ ] **GPIO 关系追踪**：读取 line name、consumer、chip/offset 和 device-tree/udev 来源；
  将 GPIO 线映射到传感器输入或执行器驱动，但不切换输出电平。不得通过 sysfs、字符设备
  或任何 provider API 设置方向、电平、边沿或 debounce。
- [ ] **执行器控制链追踪**：从 driver/daemon/ROS service/action 找到 enable、stop、
  feedback、limit、mode 和 fault；首轮只读取状态和反馈。必须记录每个字段的权威来源、
  读操作是否可能触发副作用，以及 power domain、watchdog、interlock、急停和 resource ownership。
- [ ] **稳定身份判定**：serial、device-tree、udev-by-id、controller resource ID 优先；
  只有路径的设备标记 `identity_stability=path`。为每个设备生成 canonical identity tuple；
  多个来源冲突、重复 serial、重插后 resource 变化都必须标记为 `UNKNOWN` 并列入 unresolved list。
- [ ] **生成 MHS candidate**：为每个具体 sensor/actuator 生成 manifest、route、channels、
  state、commands、limits、driver digest；状态固定为 `DISCOVERED_UNVERIFIED`。声明 command
  不等于获得写权限；path identity 的 command 不得发布为可执行写能力。
- [ ] **只读 provider probe**：执行 `inspect/status/read`，校验类型、单位、范围、断线和
  freshness；结果写入 RKB Fact/EvidenceEnvelope。所有 transport 必须有 operation allowlist、
  timeout、retry/concurrency budget 和 no-write 约束；探测失败也必须生成可审计的 unavailable evidence。
- [ ] **Rolo gate 对接**：只有 identity、digest、observed evidence 和 safety 前置条件齐全，
  才允许按上面的状态机进入 `ELIGIBLE` 或 `VERIFIED`；discovery 不得代替 Rolo gate。
  任一 identity tuple、digest、freshness、route 或安全前置条件校验失败都必须 fail closed。

## 交付物

每个设备至少交付：

```text
discovery trace（source ref + 原始输出）
MHS manifest + manifest digest
driver/provider identity + digest
mhs://<device_id>/<capability> routes
RKB Fact/EvidenceEnvelope（identity tuple、source_kind、observed_at/fresh_until、sha256、limitations）
identity resolution（来源、优先级、冲突和 stability）
每个 channel 的类型、单位、量程、quality/错误语义和样本时间
每个 actuator command 的 resource、risk、schema、timeout、幂等性和前置条件（仅声明，不执行）
未解决映射和安全限制清单（severity、owner、next action）
```

所有交付物必须是 machine-readable、带 schema/version，并能通过 deterministic canonicalization
重新计算相同 digest。原始输出保存为受控 artifact；脱敏后的 source ref 才能进入 RKB、日志或 fixture。

RKB evidence 至少包含：`robot_id`、`target_host_fingerprint`、`collector_id`、
`deployment_mode`、`access=READ_ONLY`、`request_nonce`、`source_kind`、`source_ref`、
`observed_at`、`fresh_until`、`sha256`、manifest/driver digest、canonical route、
fact IDs 和 limitations。freshness deadline 按 capability 配置；时钟未同步或 evidence 过期时不得消费。

## 探测安全规则

- 默认只允许 `inspect`、`status`、`read` 以及明确列入 allowlist 的 identity probe。
- 禁止 reset、calibrate、setpoint、enable、stop、power-cycle、固件更新、寄存器写入、GPIO 输出切换和任意 shell。
- ROS service/action、串口/CAN/HTTP 请求即使名称为 status/read，也必须证明无副作用后才可加入 allowlist。
- 所有 probe 必须具备超时、有限重试、并发/速率限制和取消行为；无法证明安全时返回 `UNKNOWN/UNAVAILABLE`。
- 任何 secret、凭据、完整环境变量或带 token 的 URL 不得写入 RKB value、schema fixture 或日志。

## 分阶段交付与验收

| 阶段 | 范围 | 完成条件 |
|---|---|---|
| D0 | 范围、身份和 probe policy | 首批设备清单、owner、批准地址/操作 allowlist、权限和脱敏规则冻结 |
| D1 | 只读 inventory 与 trace | 每个节点有 source ref、collector、时间、identity resolution 和 machine-readable trace |
| D2 | 具体设备识别 | USB/串口/I²C/SPI/GPIO/ROS 映射有设备级证据；未知或冲突项保持 UNKNOWN |
| D3 | MHS candidate/provider | manifest schema、canonical digest、route、driver digest 和 `DISCOVERED_UNVERIFIED` 验证通过 |
| D4 | RKB probe | `inspect/status/read` 成功、断线、超时、越界、未知 channel、STALE 均有 evidence；错误结果也可追溯 |
| D5 | Gate readiness | identity/digest/freshness/route 负测通过；任何未授权写请求 backend 调用为 0 次；不得因 discovery 直接变为 VERIFIED |

最小负测集合：未批准地址、设备替换、重复 serial、path identity、fingerprint 不匹配、manifest/driver
digest 漂移、过期 evidence、未知 channel、非法类型、NaN/越界值、transport timeout、断线、含 secret 的原始输出。

当前仓库的 Linux 实现只覆盖 procfs/sysfs、thermal 和节点存在性候选；本需求中的具体协议识别、执行器
控制链和 RKB 写入属于后续阶段，不得以“代码已创建”替代上述验收。

## 安全边界

本需求不包含 reset、calibrate、setpoint、enable、power-cycle 或固件更新。真实执行器
写能力必须在 fake/simulation → 无负载台架 → 人工授权 canary 之后另行评审。
本需求不授予任何真实设备写权限，也不构成功能安全、急停、碰撞检测、watchdog 或硬件限位的替代品。
