<!-- status: active; authority: reference; owner: rolo maintainers; last_reviewed: 2026-09-02 -->

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
