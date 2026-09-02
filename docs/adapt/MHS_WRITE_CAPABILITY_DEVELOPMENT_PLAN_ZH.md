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
limitations；成功和失败都要可审计。首轮只返回事件对象，后续再接 immutable RKB event store。

## 3. 分阶段开发

| 阶段 | 内容 | Exit Gate |
|---|---|---|
| MHS-W0 | typed command/request/context/result | schema、route、digest 和缺字段负测通过 |
| MHS-W1 | Rolo write gate、authorizer、进程内 resource lock | 未授权/过期/身份不符/锁冲突均不触发 backend |
| MHS-W2 | fake/simulation backend 与 RKB write event | 成功、拒绝、backend fault、幂等重试可审计 |
| MHS-W3 | 无负载台架单一低风险命令 | 人工授权、stop/timeout、外部急停验证 |
| MHS-W4 | 限定真实设备 canary | 独立安全评审后单独批准；默认关闭 |

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

## 5. 暂不实现

- 不在真实机器人或 LanderPi 上执行写命令；
- 不把 MHS/RKB 当成功能安全系统；
- 不开放任意 shell、任意寄存器或无限流写入；
- 不允许 MCP/CLI 绕过 Rolo write controller；
- 不在官方 MHS wire schema/conformance 未发布时宣称官方兼容。
