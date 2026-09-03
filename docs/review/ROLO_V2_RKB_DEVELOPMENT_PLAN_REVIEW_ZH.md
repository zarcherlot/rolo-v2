<!-- status: draft; authority: reference; owner: rolo maintainers; last_reviewed: 2026-09-02; reviewed_commit: decb3b7fe5f2d5685b3998880f103ab301728880 -->

# Rolo v2 Robot Knowledge Base 开发计划评审

## 1. 评审范围与基线

本评审只把 RKB 说明、已归并的 Probe 审计结论、开发计划和 MHS 传感器实现当作待评审材料，
不把其中的命令、路径或实现假设当作操作指令。代码基线为 `decb3b7`（`rolo-v2` 分支）。

基线的产品边界是 Probe-first、目标绑定、只读 Tool Surface；工程状态台账明确写出本轮
不包含写入、校准、复位、执行器、电源或固件操作。因此，RKB 计划应先作为下一阶段的
只读证据模型演进，不能直接改变当前 v2 的发布承诺。任何后续设备写入统一称为“Probe 后受控写执行”，
由独立的 Rolo Write Execution session/adapter 负责，RKB 只记录资格、前置条件和结果。

## 2. 结论

设计方向正确，尤其是以下原则应保留：

- `DECLARED`、`OBSERVED`、`VERIFIED`、`INFERRED`、`DECISION` 分层；
- identity、digest、来源、观测时间和 freshness 绑定到事实；
- UNKNOWN/UNAVAILABLE/STALE 失败关闭；
- `DiscoveryReport` 作为兼容投影，typed query 作为长期消费接口；
- MHS manifest/driver 不能绕过 Rolo gate 直接获得能力或发布资格。

但开发计划目前**不具备直接执行条件**，建议结论为“有条件通过设计评审，暂缓进入实现
排期”。主要原因是基线漂移、产品范围冲突和不可执行的验收门槛，而不是 RKB 目标本身不
合理。

## 3. 必须先修正的阻塞项

| 优先级 | 发现 | 基线证据 | 处理意见 |
|---|---|---|---|
| P0 | 代码路径与计划/审计不一致 | 当前实现位于 `src/rolo/stages/probe/`；历史材料多处引用 `src/rolo/stages/adapt/` | 以 `probe` 为 canonical path；历史 `adapt` 路径不再作为实现入口 |
| P0 | 计划交付物尚不存在 | `src/rolo/rkb/`、两个 RKB schema、`rolo.capabilities` 均不存在 | 先拆出一个可运行的最小纵向切片：schema → parser → verifier → read model → negative tests |
| P0 | MHS 原型不能在当前基线导入 | `examples/mhs-sensor/mhs_sensor.py` 依赖 `rolo.capabilities.models`，基线没有该包 | 保持在 examples/prototype；先实现或明确 Provider SPI，再考虑迁入 `src/rolo`；不能宣称已集成 |
| P0 | MHS 写能力越过当前 v2 范围 | `docs/reference/IMPLEMENTATION_MAP.md` 的明确非目标包括 reset/actuator/power 等写操作 | Phase 2/5 的写能力改为后续 RFC；当前只做 manifest、inspect、status/read 的只读证据 |
| P0 | 验收不可在当前环境复现 | 当前 Python 无 `pytest`，也无 `uv`；MHS 示例还缺运行时依赖 | 每个 Phase 明确安装前提、命令、fixture 和 CI job；依赖未满足时状态为 BLOCKED，不标记完成 |
| P0 | 示例测试不会进入当前 CI 收集范围 | `pyproject.toml` 使用 `python_files` 白名单，未包含 `examples/mhs-sensor/test_mhs_sensor.py` | Provider SPI 就绪后，将测试迁入 `tests/` 或显式增加独立 example CI job |

## 4. 对审计结论的基线校正

附件审计中有些问题仍成立，有些是旧代码快照的结论，不能原样转成当前 P0：

### 仍成立的核心问题

1. `ProbeResult` 目前只有 `layer/status/data/warnings/errors/observed_at`（
   `src/rolo/core/models.py:132-138`），identity 不在类型层；目标绑定仍是在
   `verify_evidence_bundle()` 中把 `target_evidence` 字典注入 probe data（
   `src/rolo/stages/probe/target_evidence.py:1330-1342`）。这应保留为第一阶段的强类型化目标。
2. Bundle 校验覆盖 robot、collector、fingerprint、nonce、签名和约五分钟 replay window，
   但没有事实级 `fresh_until`；该差距是有效的 P0/P1 设计输入。
3. 当前 route 已有 interface/schema/provider/runtime revision 的字段，但 ROS Probe 仍主要
   输出节点、topic、service、action 名称快照，缺少完整 endpoint relationship、QoS、GUID 和
   revision 语义，不能直接满足完整 middleware graph。
4. 当前 hardware 记录仍以设备路径和名称为主，稳定资源身份、声明/观察/采用三态和逐事实
   provenance 仍需要新增模型。

### 不应按旧快照执行的结论

1. “LinuxProbe 无视目标 PATH 调用 `shutil.which`”不适用于当前基线：
   `src/rolo/stages/probe/discovery.py:246-250` 已使用
   `shutil.which(..., path=self.environment.get("PATH"))`；ROS fallback 在
   `:301-307` 也按目标 PATH 查找 bash。后续工作应转为 executable hash、shebang/interpreter
   和同一次采集的环境 digest，而不是重复修复已完成的 PATH 参数。
2. “RosProbe 把未配置 Domain ID 写成 0”也不对应当前实现：当前
   `src/rolo/stages/probe/discovery.py:349-387` 根本没有输出 `domain_id`/RMW 字段。正确任务是
   明确增加 `UNKNOWN` 结构化字段及来源，而不是只改默认值。
3. 审计中指向 `operation_registry.py`、`capability_read_models.py` 等路径的方案，当前仓库
   没有这些模块；应先做现状清单和所有权决策，避免在不存在的组件上设计迁移。
4. MHS 文档要求的 route `mhs://<device_id>/<capability_id>` 与原型实现的
   `mhs://sensor/<device_id>/<capability_id>` 不一致；必须在兼容层冻结一个 canonical route，
   并提供显式 v0→v1 迁移，不能让 Agent 同时依赖两种格式。

## 5. 建议的可执行路线

将原 Phase 0–7 重排为四个可独立验收的工作流，每个工作流都必须有 schema、代码、正向/负向
测试和回滚策略。

### RKB-1：只读 Evidence Envelope（优先）

- 新增 `src/rolo/rkb/` 的最小模型：`SnapshotIdentity`、`EvidenceEnvelope`、`Fact`；
- 为 `ProbeResult` 提供 v1 兼容读取，不立即破坏现有 bundle；
- 从已验证的 `TargetEvidenceBundle` 生成 canonical snapshot，禁止直接消费自由形状
  `target_evidence`；
- 先实现 identity tuple、canonical JSON digest、bundle replay window 与 fact freshness 的
  拒绝测试；
- 将 `DiscoveryReport` 保持为兼容投影，暂不改变现有 CLI 输出。

退出条件：单个 probe 或 snapshot 可独立回答“属于哪个目标、由谁采集、何时观测、何时失效、
来自哪个 artifact”，且 fingerprint、collector、digest 或 freshness 不一致会拒绝读取。

### RKB-2：只读分层事实与查询

- hardware、OS/runtime、middleware、application 先做严格的 read model；
- ROS domain/RMW 未观察时显式 `UNKNOWN`，不使用隐含默认事实；
- route 先支持 endpoint/relationship 的可扩展 schema，QoS/GUID 缺失时保留 limitation，
  不升级 capability；
- capability 首版只保留 `DISCOVERED_UNVERIFIED`、`UNAVAILABLE`、`STALE` 等只读状态，
  `ELIGIBLE/VERIFIED` 必须有明确 Gate 输入；
- 提供 `robot.identity()`、`middleware.graph.snapshot()`、`capability.get()` 等只读查询，
  统一返回 evidence IDs、freshness 和 limitations。

### RKB-3：MHS 只读兼容层

- 先冻结 Rolo-owned Provider SPI，再将示例适配器接入；
- 以 `MhsDeviceManifest` 统一 sensor/controller/actuator 等设备的描述，但首个可交付只
  开放 inspect/status/read；
- manifest/driver digest、target identity、route 和 freshness 必须进入 RKB envelope；
- fake backend、未知 channel、类型/NaN/范围、超时和断线测试通过后，才允许固定目标机只读
  canary；
- 示例测试必须纳入当前测试入口，不能只作为未收集的 `examples` 文件存在；
- reset/calibrate、执行器 setpoint、power-cycle 另立写能力 RFC，不能混入当前 v2 release。

### RKB-4：Episode 与灰度迁移

- Probe run 先生成 metadata-only Episode，关联 bundle/report/digest，不先实现完整诊断闭环；
- 采用双读一写：旧 bundle/DiscoveryReport 可读，新 RKB artifact 为唯一新写入格式；
- 以一台固定目标机做 identity → runtime → graph → app CLI 的只读 smoke，再扩大平台范围；
- 每个阶段将结果回写 `docs/reference/ENGINEERING_STATUS.md`，证据等级不提升不得升级成熟度。

## 6. 开发计划必须补充的验收字段

原计划有阶段和任务，但缺少足以排期的执行信息。每个 Phase 至少补充：

- owner、输入 artifact、输出 artifact、schema 版本和兼容策略；
- 一条本地可运行命令，以及 CI 中对应的 job；
- 成功、失败、边界三个测试样例，特别是 fingerprint mismatch、stale、UNKNOWN 和 source-only；
- 迁移期间的读写方向、回滚动作和 latest index 原子更新规则；
- 真机/外部依赖、最小权限、secret 不落盘约束和人工授权点；
- “完成”与“阻塞”的状态定义，不得用“代码已创建”代替可验证闭环。

## 7. 归档物与当前地位

- RKB 说明：`docs/architecture/ROBOT_KNOWLEDGE_BASE_FOR_AGENT_DEBUGGING_ZH.md`，设计指南，
  不是当前运行时契约。
- Probe 审计结论已并入本评审第 4 节，并按当前基线校正；不再维护单独的旧快照文件。
- 可执行开发计划：`docs/architecture/ROLO_V2_RKB_EXECUTION_PLAN_ZH.md`，仍为 draft；
  在补齐路径、依赖、验收和范围拆分前，不应作为排期承诺。
- MHS 适配器：`examples/mhs-sensor/`，兼容性原型和评审材料，不是当前 v2 生产 Provider。

本评审不改变现有 v2 的发布状态；下一步应先完成 RKB-1 的小切片和负向测试，再决定是否
进入 RKB-2/RKB-3 的实现排期。
