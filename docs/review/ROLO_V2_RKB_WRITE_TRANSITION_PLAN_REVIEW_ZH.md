<!-- status: draft; authority: reference; owner: rolo maintainers; last_reviewed: 2026-09-02; reviewed_commit: decb3b7; reviewed_plan: ../architecture/ROLO_V2_RKB_WRITE_TRANSITION_PLAN_ZH.md -->

# Rolo v2 Probe 后受控写执行计划复评

## 1. 复评范围与结论先行

复评对象：

- [RKB 可执行开发计划](../architecture/ROLO_V2_RKB_EXECUTION_PLAN_ZH.md)；
- [Probe 后受控写执行计划（RKB 只读前置）](../architecture/ROLO_V2_RKB_WRITE_TRANSITION_PLAN_ZH.md)；
- [RKB 架构说明](../architecture/ROBOT_KNOWLEDGE_BASE_FOR_AGENT_DEBUGGING_ZH.md)；
- `docs/reference/ENGINEERING_STATUS.md`、`pyproject.toml` 和当前 v2 源码/测试布局。

当前基线提交为 `decb3b7`。复评不把计划中的 artifact、测试或真机证据视为已经存在的事实。

**结论：设计方向有条件通过；只读当前仍应判为 `READ_ONLY_BLOCKED`，不可进入 W1，也不应
对外宣称支持 Probe 之后的受控写执行。RKB 本身不承担写操作。**

### 1.1 术语校正

本次复评将“RKB 可写转型”统一改称为“Probe 后受控写执行”。Probe 是只读观察入口，RKB 是
事实、资格和证据记录层；实际设备写入必须由独立的 Rolo Write Execution session/adapter 在
授权、状态前置条件和审计约束下完成。Write Execution 可以把执行前后证据写回 RKB，但这不代表
RKB 获得设备写权限。

计划已经补上了 W0 完工审计、SafetyDeclaration、QuiescenceLease、WriteAdapterBundle、
WriteToolSession、dry-run 和单目标单 operation 试点，这些边界是正确的。但仍有几个会阻止
实际排期的缺口，必须在计划进入实现前修订。

## 2. 只读是否已经完成

没有。当前仓库仍缺少前置计划要求的：

- `src/rolo/rkb/` 及其 Evidence Envelope/typed snapshot 实现；
- `schemas/RobotEvidenceEnvelope.schema.json`、`schemas/RobotKnowledgeBase.schema.json`；
- RKB → typed query → DiscoveryReport 的离线闭环；
- `read-only-completion.json` 和六类硬门的审计 artifact；
- MHS 只读 Provider SPI 与固定目标机 canary 证据。

工程状态台账目前只确认 Probe-first 的目标证据和只读 Tool Surface；它没有 RKB 完工记录，且
仍明确写着当前 v2 不包含写入、校准、复位、执行器、电源和固件操作。因此，转型计划中的
`current_state: BLOCKED_BY_READ_ONLY_PRECONDITIONS` 是符合基线的判断。

## 3. 必须修正的问题

| 优先级 | 问题 | 证据与影响 | 修订要求 |
|---|---|---|---|
| P0 | 新增 RKB 测试不会被 CI 收集 | `pyproject.toml` 的 `python_files` 只列出固定文件名，不包含计划中的 `tests/test_rkb_*.py` | W0 必须先修改测试入口并增加收集断言；未收集的测试不得作为完工证据 |
| P0 | 没有可执行的首个 R1 pilot | `docs/probe/APPLICATION_OPERATION_V1_INVENTORY.md` 的 60 个写操作全部为 23 个 R2 + 35 个 R3；计划要求 W4 必须是 R1 | W1 增加“pilot 选择/批准”任务：明确 operation、设备、route、参数、后置观察、补偿和 owner；在选定前保持 BLOCKED，不得把 R2 降级伪装成 R1 |
| P0 | 写请求的 replay 防护不完整 | `WriteRequest` 使用 `request_nonce`，但计划没有定义由谁签发写入挑战、一次性消费和与 WriteToolSession 的绑定 | 新增 `write_session_id`、controller-issued one-time challenge、消费记录和 target-side compare；不能复用只读 Bundle nonce 作为唯一写授权 |
| P1 | W0 的“两次采集一致”判据过宽且未定义 | middleware graph、状态和 route 本身可能合法变化；计划未定义独立采集的时间窗、允许变化字段和 invariant | 只比较 identity、schema/digest、资源绑定和 freshness policy 等不变量；动态 graph 用 revision/差异解释，不要求 route 列表逐字相同 |
| P1 | dry-run 无副作用的证明不足 | 只比较 process/daemon、graph revision 和设备摘要，不能覆盖文件、网络、驱动内部或隐藏设备副作用 | 为每个 adapter 增加 transport/argv allowlist、driver audit hook 或目标侧写调用计数；无法证明时必须保持 `BLOCKED` |
| P1 | W5 扩展没有可执行阈值 | 仅写“在预先批准的阈值内”，未定义样本量、窗口、失败率、UNKNOWN、补偿失败和自动撤销条件 | 在 W1 冻结默认阈值；至少要求 0 安全事件、0 未解释 UNKNOWN、0 补偿失败，并定义最小样本数和回滚触发器 |
| P1 | SafetyDeclaration 的信任根未定义 | `principal`、`authorization_ref` 和 `acknowledgement_text` 只是字段，未定义身份认证、签发者、范围签名和撤销 | 明确 authorization issuer、签名/引用校验、operation/resource/argument scope、过期和撤销；用户文本不能单独授予权限 |
| P1 | 状态/契约没有机器可读持久化规范 | 计划给出 phase/decision 枚举和 JSON 输出，但没有对应 schema、版本和兼容策略 | W0 输出 `read-only-completion.schema.json`；W1 输出 write-state schema；phase 与 decision 分列存储并版本化 |
| P2 | R3 物理计划只是占位符 | `R3_PHYSICAL_CANARY_PLAN` 在当前工作树中不存在，且没有 owner/前置输入/验收入口 | 明确为外部阻塞依赖，创建独立计划后才可讨论 zero-stop、bounded motion、global navigation；本计划不得引用其“完成”作为自身 DoD |

## 4. 对现有阶段设计的评价

### W0：方向正确，但需变成可审计清单

六类硬门 A–F 覆盖了契约、身份、freshness、只读行为、恢复和目标证据，结构合理。需要补充：

- 每个 gate 的唯一 artifact 类型、schema 版本、采集命令和责任人；
- `PASS/FAIL/BLOCKED` 的机器可读枚举和审核人；
- 动态字段与不变量的比较规则；
- “P0/P1 缺陷为零”的缺陷清单来源和冻结日期。

### W1：安全模型完整，但缺 pilot 选择机制

SafetyDeclaration、QuiescenceLease、state revision、manifest/driver digest 和后置观察都应
保留。问题在于计划要求一个 R1 pilot，却没有说明从当前 operation inventory 产生或批准它。
建议先新增一个非物理、单资源、可幂等的具体 operation contract；如果产品上不存在这样的
操作，应承认“本阶段没有可写 pilot”，而不是为了推进 W2/W4 修改风险等级。

### W2/W3：离线和 shadow 分层正确

独立 WriteToolSession、不放宽只读 NativeToolSession、provider-owned argv builder、fake
backend 和 dry-run 是合理的。dry-run 还需要更强的副作用观测或明确降低承诺，否则“未观察到
变化”会被误读为“证明没有变化”。

### W4/W5：可控，但必须补量化撤销条件

单目标、单资源、单 operation、短授权窗口是合适的第一步。扩展前必须冻结样本量、观察窗口、
失败率、超时率、UNKNOWN、补偿失败和自动撤销阈值；只写“预先批准”不足以排期或复现。

## 5. 建议的批准顺序

```text
修正 pytest 收集入口与 schema
  → 完成 RKB-0/RKB-4 产物盘点
  → W0 只读完工审计
  ├─ BLOCKED/CONDITIONAL：回到只读整改
  └─ READ_ONLY_COMPLETE
       → 选定并批准一个真实 R1 pilot
       → W1 冻结 write contract / challenge / safety / lease
       → W2 fake simulation
       → W3 target dry-run
       → W4 one-target-one-operation
       → W5 按阈值扩展
```

在 `READ_ONLY_COMPLETE` 之前，任何写入口都必须不存在或明确返回 `READ_ONLY_REQUIRED`；在
W4 之前，真实目标机只允许读和 dry-run；R2/R3 不从本计划继承资格。

## 6. 复评决定

| 项目 | 当前决定 |
|---|---|
| 只读 RKB | `READ_ONLY_BLOCKED`，尚无完工证据 |
| Probe 后受控写执行计划 | 最终版条款已补齐；实现排期仍需先通过 W0 |
| W1 | `BLOCKED`，直到有明确 R1 pilot、写挑战模型及其 schema/artifact |
| W2/W3 | 可在契约冻结后开发，但默认关闭，不连接物理写入口 |
| W4/W5 | 未批准，不得执行真实写入或扩大范围 |
| R3 物理动作 | 独立计划、独立安全评审，不属于本计划 DoD |

## 7. 验证记录

- 文档链接与元数据检查：`python scripts/check_docs.py` 通过；
- 代码/测试执行：本次为计划复评，未宣称运行时测试通过；当前环境仍缺少 `pytest`/`uv`；
- 当前基线中不存在 RKB schema、RKB package、Write Execution session 或 `read-only-completion.json`，这与
  上述 `READ_ONLY_BLOCKED` 判断一致。

## 8. 最终版修订闭环

上述 P0/P1 要求已落实到[Probe 后受控写执行计划最终版](../architecture/ROLO_V2_RKB_WRITE_TRANSITION_PLAN_ZH.md)：

- 增加 pytest 收集入口和 schema 校验作为 W0/W1 前置；
- 要求具体 R1 pilot 选择，明确无合格 pilot 时保持 `BLOCKED`；
- 将写入 challenge 与只读 Bundle nonce 分离，并加入 state revision 原子前置条件；
- 将动态 graph 与稳定不变量分开判定；
- 增加 dry-run 的 transport/argv allowlist、driver audit 或目标侧写计数要求；
- 冻结批次样本量、0 安全事件、0 未解释 `UNKNOWN`、0 补偿失败和超时率阈值；
- 明确 authorization issuer、范围、签发和撤销信任根；
- 将 R3 物理动作声明为外部阻塞依赖。

最终版仍保持 `current_state: BLOCKED_BY_READ_ONLY_PRECONDITIONS`。这些条款完善了计划的可执行
性，但不等于 RKB 已实现或只读已完工；完成状态必须由 W0 的机器可读审计 artifact 证明。
