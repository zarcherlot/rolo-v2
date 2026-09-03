<!-- status: active; authority: reference; owner: rolo maintainers; last_reviewed: 2026-09-03 -->

# RKB-1 后续工程待办

RKB-1 已交付 Evidence Envelope、`robot-snapshot/v1` 和旧 Probe/Bundle/DiscoveryReport
兼容读取，并在开发机与 Raspberry Pi 真机完成回归验证。本文件只记录 RKB-1 明确保留的
工程边界，不改变当前只读、证据优先的产品承诺。

## P1：Episode 持久化与可审计读取

- [ ] 定义 Episode/Run 的持久化 schema，关联 `snapshot_id`、采集时间、目标身份、来源和验证结果。
- [ ] 实现 append-only 写入、保留策略、幂等键和故障恢复，禁止覆盖原始 artifact。
- [ ] 为 Episode 增加按 identity、source、freshness、status 的只读查询与分页读取。
- [ ] 补充跨进程/重启后的 digest 校验、损坏 artifact 隔离和审计日志测试。

## P1：生产签名与信任边界

- [ ] 将当前可选 HMAC 接入受控密钥存储、密钥轮换、吊销和审计策略；禁止在日志或 envelope 中写入密钥材料。
- [x] 为 `verified_bundle_to_snapshot()` 建立生产入口，明确未验证 Bundle 的拒绝策略，并保留旧投影的兼容边界。
- [ ] 固化静态声明、运行时观察、硬件拓扑和推断事实的信任等级、来源约束及冲突解决规则。
- [ ] 增加时钟漂移、重放、跨目标 identity 混用和签名算法升级的安全回归用例。

## P2：Schema 与兼容生命周期

- [ ] 建立 `robot-snapshot/v1` 的版本迁移注册表、兼容窗口和弃用公告流程。
- [x] 为 envelope/snapshot schema 增加 CI 结构校验、样例 artifact 和跨版本 round-trip 测试。
- [ ] 明确旧 `TargetEvidenceBundle`、`ProbeResult`、`DiscoveryReport` 投影的最终保留期限与删除条件。

## P2：产品集成与运行证据

- [ ] 将 Snapshot 接入 RKB read model、CLI/API 查询和目标发现流水线，保持只读权限边界。
- [x] 增加 bounded latest/freshness canary；真实 ROS/Linux/硬件 provider 的定期采集仍依赖目标机调度。
- [x] 增加 digest/freshness/HMAC 拒绝指标和损坏 artifact 指标；结构化告警阈值仍待产品接入。
- [x] 评估单目标 artifact 大小、读写吞吐及存储成本，并形成容量测试基线。

## 完成标准

每项待办都必须同时具备：版本化契约、拒绝路径测试、至少一个可复现的离线或真机证据，
并在 `docs/reference/ENGINEERING_STATUS.md` 中同步证据等级后，才可从本文件移除。

## RKB-3 后续工程项（不阻塞 RKB-4）

- [ ] 为常见厂商 MHS 设备补充只读 provider manifest/driver，并为每类目标机补充 canary artifact。
- [ ] 将 Linux observer 的热度、I2C、SPI、GPIO 和 USB 发现结果与厂商 serial/topology 做稳定绑定。
- [ ] 在真实目标机调度中周期采集 MHS freshness/断线指标；保持 reset、calibrate、setpoint、stop、power-cycle、firmware 未开放。
- [ ] wheel 安装后导入验证属于发布工程，单独建立发布 artifact 和回归矩阵，不回写本阶段 gate。

## RKB-4 工程项

- [x] 将每次 Probe run 的 Episode metadata 接入正式 Probe orchestration，并保留旧 bundle/report 双读路径。
- [x] 为 Episode latest 指针接入跨进程故障恢复、损坏隔离和审计指标。
- [x] 为 Episode 增加按 identity、source、freshness、status 的只读分页查询、幂等 Probe run 和 retention。
- [x] 在固定目标机完成 identity → runtime → graph → app 的只读 smoke 后，记录灰度放量决策；LanderPi graph/app 已补充 Docker 内 ROS2 route presence 观察，灰度仍仅限 metadata-only 只读。
- [x] 增加跨进程并发发布、指标增量合并、digest 损坏 record 隔离和 latest 恢复 fault canary。
- [x] 在 LanderPi 上执行跨进程并发、latest 恢复和损坏 record 隔离 canary，并记录目标机 artifact；使用合成 snapshot，不替代 MHS provider 证据。
- [x] 增加并在 LanderPi 执行迁移式新旧 Episode 发布、父 digest 绑定和 rollback 指针切换 canary；使用合成 snapshot，不替代真实 MHS 迁移证据。
- [x] 在操作员重启后的 LanderPi 上重跑 MHS → snapshot → Episode 只读 smoke，并记录 boot id、启动时间、ROS2 graph/service/topic 计数。
- [ ] 将 Episode 证据等级从 `PARTIAL/E3` 提升前，补齐 Episode 进程 `kill -9` 后的重启恢复与持久化证据（本项待最后维护窗口执行）。
- [x] 增加 freshness/断线/digest mismatch/容量水位的结构化告警策略；生产通知 transport、周期 cadence 和部署接线仍需落地。
- [x] 固化 Episode schema 迁移注册表、旧 bundle/report 兼容窗口和发布弃用策略；最终公告与删除动作仍需发布流程接线。
- [x] 增加受控 HMAC keyring 的轮换、吊销、时间窗口和重放拒绝策略；生产 vault 持久化与目标机密钥演练仍需维护窗口。
