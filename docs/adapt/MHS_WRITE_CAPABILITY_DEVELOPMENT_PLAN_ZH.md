<!-- status: active; authority: plan; owner: rolo maintainers; last_reviewed: 2026-09-02 -->

# MHS 写能力需求与开发计划

## 1. 目标与职责边界

MHS 可以声明并实现有界写命令；是否允许某次写操作由 Rolo 决定。设备固件、独立安全
控制器和硬件限位仍拥有不可被 Rolo/MHS 覆盖的最终保护权。

```text
Agent -> Rolo typed write -> identity/freshness/safety/authorization gate
      -> resource lock -> bounded MHS command -> adapter -> device hard limits
```

首轮只支持 fake/simulation backend，不连接真实执行器，不修改 LanderPi。急停、碰撞检测、
功能安全 PLC、watchdog 和硬件限位不属于本功能的替代范围。

## 2. 必须需求

### Manifest command

每个命令必须声明：稳定 `hardware_resource_id`、风险等级、输入 schema、超时、幂等性、
前置条件、取消能力和补偿能力。缺少稳定资源身份或限制的写命令不得注册。

### Rolo write request/context

请求必须 pin：device/command/route、manifest digest、driver digest、idempotency key；Rolo
上下文必须携带 robot/target identity、短时 authorization、resource-lock ref、已验证 safety
前置条件、evidence IDs 和 freshness deadline。

### Gate

按 fail-closed 顺序检查：命令存在且为 write、canonical route、digest pin、target identity、
freshness、authorization、safety 前置条件、resource lock、参数 schema。任一步失败都不得调用
backend。

### Result/evidence

结果必须带 event ID、请求/目标/route、manifest/driver digest、时间、状态、evidence IDs 和
limitations；成功和失败都要可审计。W2 使用内存 append-only hash-chained event store，
并通过 `PersistentMhsWriteEventStore` 提供 JSONL 持久化、重启恢复和链校验；生产环境仍需
接入由 RKB 管理的不可变存储和访问审计。

## 3. 分阶段开发

| 阶段 | 内容 | Exit Gate |
|---|---|---|
| MHS-W0 | typed command/request/context/result | schema、route、digest 和缺字段负测通过 |
| MHS-W1 | Rolo write gate、authorizer、进程内 resource lock | 未授权/过期/身份不符/锁冲突均不触发 backend |
| MHS-W2 | fake/simulation backend 与 RKB write event | 成功、拒绝、backend fault、幂等重试可审计 |
| MHS-W3 | 无负载台架单一低风险命令 | 人工授权、stop/timeout、外部急停验证 |
| MHS-W4 | 限定真实设备 canary | 独立安全评审后单独批准；默认关闭 |

### W3 当前实现（simulation bench + fixture seam）

W3 已在无负载 fake/simulation 台架完成首轮实现：

- `MhsWriteContext` 要求显式提供 `external_estop_clear`、`watchdog_ok` 和 `quiescent`；任一为假时，Rolo 在调用 backend 前拒绝请求。
- 台架 authorizer 可要求 `human:<approval-id>` 形式的人工授权引用；授权引用不由 MHS 自行生成。
- backend 写入在命令声明的 `timeout_s` 内执行；超时后 Rolo 调用可选的 `stop(resource, reason)`，并以失败结果记录 stop 结果。
- 超时、急停拒绝和人工授权拒绝均写入 W2 的 hash-chained audit event；锁在所有路径释放。

这组实现只证明 Rolo/MHS 交互面的控制顺序和失败闭环，不代表真实执行器安全认证，也不改变
W4 的独立安全评审和默认关闭要求。

`rolo.mhs_watchdog` 增加了厂商 watchdog 的只读 discovery/status 接口和无 I/O 的
`WatchdogTestFixture`。fixture 可以注入 heartbeat 丢失并验证 timeout、trip count 和
safe-state readback；它不代表 LanderPi 已具备硬件 watchdog。

`rolo.mhs_fixture.MhsBenchFixture` 提供无负载台架的证据记录器，默认将 external-estop、
stop、rollback、watchdog、no-load 全部置为 `NOT_OBSERVED`，只有明确记录测试结果后才会
更新状态；它不会直接驱动 GPIO、串口或 ROS 执行器。

### W4 当前进度（canary admission only）

已增加无 I/O 的 `MhsCanaryGate` 和 `MhsCanaryRunner`：真实 canary 必须绑定 `human:` 批准引用、独立安全评审、
目标指纹、设备/命令、软件环境、R1 风险等级，并具备 external-estop、stop 和 rollback 的
证据；同时受 1--3 次 attempt budget 约束。当前 LanderPi arm 已有稳定资源
`landerpi-rrc:5b22016029:bus-servo:arm` 和 R1 `stop_arm` 命令声明，但仍是
`CONFIRMED_BOUND_WRITE_BLOCKED`。`enabled` 默认为 `false`，校验成功后只发放一次
有界 lease。Runner 只有在部署方显式设置 `real_execution_enabled` 且配置 controller 环境白名单后，
才会将 lease ID 绑定到 `MhsWriteResult` 并调用 adapter；本仓库当前不连接 LanderPi 的写入口。

厂商 watchdog 若要注册为 Rolo 工具，必须通过独立 source、heartbeat freshness、timeout
动作和 safe-state readback 证明；ROS 应用层 heartbeat、`/diagnostics` 或 systemd restart
不能自动升级为独立安全 watchdog。

## 4. 首轮验收矩阵

| 场景 | 预期 |
|---|---|
| 无 authorization | 拒绝，backend 调用 0 次 |
| manifest/driver digest 漂移 | 拒绝 |
| target fingerprint 不匹配 | 拒绝 |
| safety freshness 过期 | 拒绝 |
| precondition 缺失 | 拒绝 |
| resource lock 冲突 | 拒绝 |
| 参数缺失、未知或越界 | 拒绝 |
| fake backend 成功 | 返回审计 event，释放锁 |
| backend 异常 | 返回失败 event，释放锁 |
| 任意真实 adapter | 首轮禁止注册到写 controller |

相机和 LiDAR discovery 属于只读路径：Linux inventory 会把 `/dev/video*` 建模为
`DISCOVERED_UNVERIFIED` camera candidate；LanderPi 的 LD19 仍需稳定身份、驱动摘要和
`/scan` freshness 证据后才能升级为 `CONFIRMED_READ_ONLY`。

## 5. 暂不实现

- 不在真实机器人或 LanderPi 上执行写命令；
- 不把 MHS/RKB 当成功能安全系统；
- 不开放任意 shell、任意寄存器或无限流写入；
- 不允许 MCP/CLI 绕过 Rolo write controller；
- 不在官方 MHS wire schema/conformance 未发布时宣称官方兼容。
