<!-- status: draft; authority: guide; owner: rolo maintainers; last_reviewed: 2026-09-02 -->

# Agent 调试真实机器人所需的 Robot Knowledge Base

## 1. 目的和边界

Agent 调试真实机器人需要的是一个目标绑定、分层、带时间和证据来源的 Robot Knowledge Base（RKB），而不是把说明书、源码和一次 Probe 输出拼成一段上下文。RKB 必须让 Agent 区分：

~~~text
设计声明（DECLARED）
目标运行时观察（OBSERVED）
Rolo 独立验证（VERIFIED）
待验证推断（INFERRED / HYPOTHESIS）
用户或 Provider 决策（DECISION）
~~~

RKB 不替代急停、碰撞检测、功能安全控制器或人工授权，也不执行任何设备写操作。缺失证据表示 UNKNOWN，不表示安全；静态声明表示候选，不表示目标当前可用。实际写入必须由独立的 Rolo Write Execution 层完成，RKB 只提供资格、前置条件并保存执行证据。

## 2. 顶层结构

~~~text
Robot Knowledge Base
├── identity
├── hardware
├── os_runtime
├── middleware
├── application
├── capabilities
├── state_safety
├── episodes
└── provenance
~~~

权威内容由两类不可变制品组成：签名、目标绑定的 machine evidence，以及由 Rolo 根据 evidence 生成的 typed read models。可编辑 Wiki、Agent 输出和文档只作解释或候选输入。

## 3. 统一事实模型

每个 snapshot 和每条重要事实都必须可以独立追溯：

~~~json
{
  "fact_id": "fact-...",
  "robot_id": "rover-01",
  "target_host_fingerprint": "sha256...",
  "collector_id": "collector-...",
  "deployment_mode": "remote",
  "access": "READ_ONLY",
  "request_nonce": "0123456789abcdef0123456789abcdef",
  "source_kind": "TARGET_PROBE",
  "source_ref": "artifact://evidence/run-42/ros.json#/topics/3",
  "observed_at": "2026-09-02T08:00:00Z",
  "fresh_until": "2026-09-02T08:00:30Z",
  "value": {"endpoint": "/cmd_vel"},
  "sha256": "sha256...",
  "confidence": "HIGH",
  "limitations": []
}
~~~

Bundle 的签名和 payload digest 证明制品未被篡改；fact envelope 的 source_ref、sha256、observed_at 和 fresh_until 让下游 query 可以验证归属和新鲜度。任何 identity tuple 不一致都必须 fail-closed。

## 4. 分层内容

### 4.1 Identity

Identity 是所有事实的根，至少包含 robot_id、target_host_fingerprint、collector_id、deployment_mode、access、observed_at、fresh_until 和 identity_status。Agent 必须先验证 identity，再读取其他层。控制器自身的 hostname、PATH、Python 或设备列表不能自动归因给远端目标。

### 4.2 Hardware

覆盖主板/计算平台、CPU architecture、摄像头、IMU、Lidar、GNSS、串口/I2C/SPI/CAN、USB/PCI、驱动、设备路径、温度区、URDF hardware 和 Provider 事实。

声明与观察并列保存，并通过稳定 hardware_resource_id 关联：

~~~json
{
  "hardware_resource_id": "usb:vidpid:serial-or-topology",
  "name": "camera0",
  "declared": {"model": "...", "frame": "camera_link"},
  "observed": {"path": "/dev/video0", "driver": "uvcvideo"},
  "adopted": "observed",
  "identity_stability": "STABLE",
  "evidence_ids": ["fact-..."]
}
~~~

优先使用 serial、USB topology、I2C address、CAN node、udev by-id、设备树路径或供应商 Provider ID。只有易变路径时，身份必须标记 UNSTABLE，不能绑定写能力或长期 release。adopted 只能由确定性规则、Provider 或显式决策产生。

### 4.3 OS Runtime

记录 OS、kernel、architecture；Python interpreter 绝对路径/版本/hash/shebang；ROS setup/overlay 文件及 digest；RMW、Domain ID、allowlisted environment；基础 CLI 的绝对路径/hash/版本/help；结构化进程 PID/PPID/状态；容器、service、namespace、资源限制；目标应用 CLI 的路径、hash、解释器和启动上下文。

运行时字段必须来自同一次目标采集，secret 不得写入 RKB。

### 4.4 Middleware

ROS/DDS 至少需要 distro、RMW、Domain ID、nodes、topics、services、actions、接口类型和 schema digest、QoS、publisher/subscriber/server/client、provider、runtime revision、采样时间和稳定性。非 ROS 可用 MQTT、Zenoh、gRPC、CAN、Redis/NATS、TCP/UDP listener 和容器网络关系表达。

endpoint 与关系分开建模：

~~~json
{
  "route_id": "ros_topic:/cmd_vel",
  "kind": "ros_topic",
  "endpoint": "/cmd_vel",
  "interface_type": "geometry_msgs/msg/Twist",
  "interface_schema_sha256": "sha256...",
  "publishers": ["node:/teleop"],
  "subscribers": ["node:/base_controller"],
  "qos": [{"reliability": "RELIABLE", "durability": "VOLATILE"}],
  "provider_ids": ["node:/teleop"],
  "runtime_revision": "graph-revision-...",
  "stability": "STABLE",
  "observed_at": "..."
}
~~~

未观察到 /cmd_vel 只能表示当前 graph 中没有该 route，不能表示机器人安全停止。

### 4.5 Application

同时保存 workspace 声明和目标观察：CLI 名称、绝对路径、executable hash、help 摘要、参数和子命令；Python/C++/ROS package、build/install、source revision；launch/config digest；declared 与实际依赖；startup/shutdown sequence；应用进程与 ROS/device route 关联。

源码声明不能单独升级为目标可用。

### 4.6 Capabilities

Capability 是面向 Agent 的标准 Operation 投影。每条记录绑定 operation ID、input/output schema、route、provider/executable、hardware resource、evidence IDs、risk/access、observed_at/fresh_until 和 status。

建议状态机：

~~~text
DECLARED -> DISCOVERED_UNVERIFIED -> ELIGIBLE -> VERIFIED
                                      ├-> UNAVAILABLE
                                      └-> STALE
~~~

只有目标 route、接口、provider、runtime evidence 完整后才能 ELIGIBLE；只有 Rolo Gate/Conformance 通过才能 VERIFIED。

### 4.7 State & Safety

只接受目标已观察的 lifecycle、motion、enabled、急停、碰撞检测、模式、速度/角速度限制、设备占用、读写范围、风险和授权要求。缺失字段显式为 UNKNOWN。状态未知时，写操作和运动能力默认不可用。

### 4.8 Episodes

每次 Probe 和调试形成时间线：

~~~text
baseline -> observation -> hypothesis -> change -> smoke_test -> decision/rollback
~~~

Episode 保存 target fingerprint、evidence/discovery snapshot、Tool 输入输出、日志引用、变更前后配置 digest、结论、限制和回滚信息；历史不能覆盖当前 snapshot。

### 4.9 Provenance

每条事实定位到不可变 artifact 的 JSON pointer、行号或日志区间，并保存 hash、采集时间、Collector、限制、置信度和输入 fact IDs。

## 5. Agent 消费协议

启动上下文只返回摘要：

~~~text
identity + freshness
OS/runtime summary
middleware graph summary
application CLI summary
capability statuses + blockers
state/safety summary（UNKNOWN 明示）
~~~

深入信息通过带 identity/freshness 校验的只读 typed query 按需获取：

~~~text
robot.identity()
os.runtime.status()
hw.inventory.scan()
middleware.graph.snapshot(selector)
middleware.route.inspect(route_id)
app.executable.inspect(executable_id)
capability.get(operation_id)
state_safety.snapshot()
episode.timeline(episode_id)
~~~

每个 query 返回 evidence_ids、observed_at、fresh_until、limitations 和明确的 UNKNOWN/UNAVAILABLE/STALE。Agent 不能直接读取未校验的原始 bundle，也不能提交任意 shell 作为事实来源。

## 6. 信任和合并规则

~~~text
DECLARED + OBSERVED -> RECONCILED -> ADOPTED -> ELIGIBLE/VERIFIED
~~~

禁止用控制器环境填补远端事实、用静态声明覆盖观察、用 route 存在升级 VERIFIED、用缺失 route 推断安全停止，或在 fingerprint、Collector、digest、freshness 不一致时继续消费。

## 7. MHS 在 RKB 中的位置

MHS（Model Hardware Standard）应作为 RKB 的物理硬件 Provider 层，而不是一个只服务于
传感器的附加模块。它的公开概念可归纳为：标准化 driver、机器可读 device
reference/manifest，以及 MCP、CLI、代码/API 等控制通道。MCP 是传输方式之一，不是
物理安全策略或 RKB 的事实来源。

### 7.1 统一 MHS Device 模型

RKB 应把 sensor、controller、actuator、power、compute、bus、tool、end-effector 和
复合设备都表示成同一个 MHS Device 模型：

~~~json
{
  "device_id": "arm-controller-0",
  "device_class": "controller",
  "vendor": "Example",
  "model": "CTRL-1",
  "serial": "...",
  "manifest_schema": "mhs-device-reference/v1-compat",
  "transport": {"kind": "can", "properties": {"bus": "can0", "node_id": 12}},
  "resources": [{"id": "joint-1", "kind": "actuator", "unit": "rad"}],
  "state": {"read": ["health", "mode", "faults"]},
  "commands": [{"id": "enable", "access": "write", "requires": ["safety_approved"]}],
  "limits": {"max_velocity": {"value": 1.0, "unit": "rad/s", "authority": "DECLARED"}},
  "driver": {"provider_id": "mhs.controller.example", "version": "...", "sha256": "..."}
}
~~~

传感器的 channel、控制器的 state/command、执行器的 setpoint/feedback、总线的
scan/health 都是同一个模型的不同 capability 组合：

| 物理类别 | 典型只读能力 | 典型写能力 | 默认风险 |
|---|---|---|---|
| sensor | inspect、read、status、calibration status | reset、calibrate | R0 / R2 |
| controller | inspect、status、faults、limits | enable、mode、reset、configure | R0 / R2–R3 |
| actuator | inspect、state、feedback、limits | bounded setpoint、stop、home | R0–R1 / R3 |
| power | rails、voltage/current/health | bounded power-cycle | R0 / R3 |
| bus/compute | topology、health、firmware identity | scan/reset/update | R0 / R2–R3 |
| tool/end-effector | presence、state、calibration | open/close/grasp/tool command | R0 / R2–R3 |

写能力必须同时绑定目标 identity、稳定 hardware_resource_id、manifest/driver digest、
state_safety 前置条件、quiescence/resource lock、授权引用和可回滚/补偿语义。

### 7.2 MHS 与 RKB 的证据映射

MHS manifest 是 `DECLARED`/`PROVIDER` 证据；driver probe/status/read，以及 Write Execution
经 MHS Provider 调用产生的结果是目标 `OBSERVED` 证据；Rolo 对 manifest、driver、route、schema、
状态和授权的独立检查才可产生 `ELIGIBLE` 或 `VERIFIED`。每次 MHS inspect/read 或 Write
Execution 的结果都要带 RKB fact IDs、
observed_at、fresh_until、manifest digest、driver version 和 transport route。

RKB 不调用 MHS Provider、不生成物理命令；Write Execution 读取 RKB 的写资格和新鲜前置条件，
通过固定的 Provider adapter 执行后，再把 pre/post state、结果和审计事件作为 RKB 事实写回。

建议 route 统一为：

~~~text
mhs://<device_id>/<capability_id>
~~~

MCP、CLI 和 API 只做 adapter，读写链路必须区分：

~~~text
只读：Agent -> Probe/typed RKB query -> MHS Provider -> bounded driver -> physical device
受控写：Agent -> typed RKB query（资格/前置条件） -> Rolo Write Execution session/policy
       -> MHS Provider -> bounded driver -> physical device
~~~

当前附件中的 `examples/mhs-sensor/mhs_sensor.py` 仅是传感器兼容原型；待 Rolo Provider SPI
和 RKB identity/freshness 契约冻结后，再迁移到通用 `MhsDeviceManifest`/`MhsDeviceProvider`。
在官方 MHS wire schema 和 conformance 测试公开前，只能声明 Rolo 的 MHS-compatible profile，
不能声明官方合规。

审计结论已归并到[开发计划评审](../review/ROLO_V2_RKB_DEVELOPMENT_PLAN_REVIEW_ZH.md)，落地顺序
见[可执行开发计划](ROLO_V2_RKB_EXECUTION_PLAN_ZH.md)。
