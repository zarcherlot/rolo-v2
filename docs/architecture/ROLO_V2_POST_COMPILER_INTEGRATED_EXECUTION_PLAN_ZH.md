<!-- status: draft; authority: plan; owner: rolo maintainers; last_reviewed: 2026-09-07; prerequisite: ROLO_V2_DSL_COMPILER_DEVELOPMENT_PLAN_ZH.md G7 -->

# Rolo v2 Compiler 后端到端整合开发计划

## 1. 定位、范围与使用方式

本文把 Compiler G7 之后分散在产品路线、互补开发、LanderPi MVP、targetd、发布兼容和
RKB 待办中的工作合并为一个排期与验收入口。它回答“下一件要做什么、依赖什么、怎样才算
完成”，不重新定义 DSL、IR、Probe/Trace/Certify 阶段语义或安全边界。

产品闭环固定为：

    安装与绑定目标
      → 只读 Bootstrap Probe
      → Compile Context / Capability Candidate Index
      → 用户意图与证据充分性判断
      → 必要时的 bounded Probe
      → Mapping DSL / Compiler
      → targetd 目标绑定与 T1～T4 Conformance
      → immutable Tool Release
      → Trace 或用户显式请求的 Certify
      → artifact index、回放和现场发布

本计划中的权威顺序如下。发生冲突时，较高层级优先：

| 顺序 | 资料 | 用途 |
|---|---|---|
| 1 | Probe/Trace/Certify 规范、Compiler 技术方案、已发布 schema | 产品语义、权限边界与接口契约 |
| 2 | 代码、schema、测试和固定证据 | 当前可验证实现事实 |
| 3 | ENGINEERING_STATUS | 成熟度和证据等级的台账 |
| 4 | 本文 | 工作顺序、集成门和完成判定 |

本计划不包含下列事项：

- 修改 Compiler parser、Canonical IR、Bundle Plan 或 DSL 语义；
- 让 Agent 直接使用 SSH、目标 shell、targetd 或 Tool Catalog；
- 将未观测到的 Probe 信息、vendor MHS 定义或推测能力写成事实；
- 在用户未明确要求时运行 Certify；
- 将物理运动、驱动改动或无人值守写入作为默认验收手段。

## 2. 实施前的基线纪律

当前工作树中的未提交实现和文档只能视为候选基线。每个切片须先完成对应测试、离线回放与
可审查提交，才可在本计划中从“已有离线切片”升级为已完成。不得用修改 fixture、跳过现场
失败或降低 digest 校验来获得门禁通过。

每项任务开始前必须记录：

1. 输入 schema、依赖的 digest、目标范围和权限模式；
2. 成功、拒绝、环境漂移和中断恢复的预期结果；
3. 产物目录、artifact index 条目和负责维护的文档；
4. 其对旧 Release、旧 current 及回滚路径的影响。

每项任务完成前必须同时具备：代码或配置、版本化契约、正反测试、可复现离线或真机证据、
文档状态更新。没有新增证据等级时，不得把 PARTIAL 改写为 STABLE。

## 3. 当前基线与开放门

下表以工程状态台账为准；“离线可用”不等同于“已完成真实产品闭环”。

| 产品域 | 当前可用基线 | 仍未关闭的门 |
|---|---|---|
| Compiler 与交接 | Compiler standalone G7、Context adapter、candidate/proposal/digest 及消费者已有 E2 切片 | 跨组件版本、canonical digest、diagnostics 与 capability negotiation 必须冻结并持续在 CI 中共同验证 |
| Bootstrap / Candidate | observed Context 到 Candidate Index、分层 digest 与离线查询已实现 | 安装后真实 Bootstrap、真实目标回放、增量 dirty namespace 采集和 rolo-vis 展示尚未形成闭环 |
| Agent Mapping | Mapping Request、repair loop、bounded follow-up、proposal 契约已有离线实现 | skill 安装/preflight、真实 Agent 诊断修复、用户确认 UI 和超限后的可解释 BLOCKED 仍待接线 |
| targetd Compile | DSL 协议、服务、ROS2 runtime snapshot/resolver、离线目标编译已有切片 | 真机 provider/runtime、T1～T4、取消/恢复和签名 Bundle 的真实目标验收尚未完成 |
| Release | immutable release、current、stale、rollback、只读 release model 已有 E2 切片 | 生产 Catalog、UI 关联、真实 target 发布/回滚和跨版本升级演练待完成 |
| Trace / Certify | release-bound 离线 replay、观测与保留策略存在；旋转 Trace 有 E3 现场证据 | 自然语言意图到已发布 Tool、十用例 Certify、完整事件/取消/恢复和真实 Episode 证据链未闭环 |
| LanderPi | ROS2、odom、EKF 与一次受监督旋转已有现场资料 | Bootstrap→Mapping→Release→Trace/Certify 的同一真实 journey 尚未通过；多 cmd_vel 发布者、诊断用户与重复 canary 仍是安全门 |
| Field Release | installer、兼容策略、离线 runbook/回放已存在 | 现场安装升级回滚、指标后端、告警传输、运维演练及可重复 acceptance pack 待完成 |

## 4. 产品里程碑与完成门

| 门 | 用户可感知结果 | 前置条件 | 退出条件 |
|---|---|---|---|
| G0 / P0 Contract Handoff | 所有消费方理解同一 Compiler 资产 | Compiler G7 | schema、canonical bytes、digest、diagnostics、backend negotiation 与跨组件 CI 全部冻结 |
| G1 / P1 Bootstrap-Candidate | 绑定目标后可看到有证据的候选能力 | G0 | Bootstrap 只读完成；候选含 evidence、freshness、confidence、gap；未知信息不进入 observed |
| G2 / P2 Intent Mapping | Agent 先查候选，只在必要时补探测 | G0、G1 | 充分性判断、bounded follow-up、DSL 修复、proposal/确认及 BLOCKED 策略可回放 |
| G3 / P3 Target Compile | Bundle Plan 变成目标绑定 Tool | G1、G2 | session、cache、runtime resolver、T1～T4、取消与恢复在真实目标通过；业务工作区无写入 |
| G4 / P4 Tool Release | 通过门禁的 Tool 可安全消费 | G3 | immutable release、原子 current、stale、pin、rollback、read model 和完整关联索引齐备 |
| G5 / P5 Trace | 一句用户意图可调用已发布 Tool 并留下诊断证据 | G4 | intent plan、事件、有限重试、取消/恢复和 Episode evidence 可复核 |
| G6 / P6 Certify | 用户指定套件后可得到逐例报告 | G4 | 同一 Release 的十用例执行、expected/actual/status/evidence、失败策略和历史留存齐备 |
| G7 / P7 LanderPi MVP | 现场跑通一条受控用户旅程 | G1～G6 的离线门 | 真机完成 Probe→Mapping→Release→Trace；Certify 作为显式第二路径完成 |
| G8 / P8 Field Release | 可安装、升级、诊断、回放和恢复 | G7 | CI 分层、现场 runbook、观测/留存、兼容窗口和回滚演练通过 |

P5 与 P6 只消费 G4 的已发布 Release，可并行；P7 不能以单项旋转 canary、fake target
或离线 replay 替代。G8 是产品发布门，不得提前把 E2/E3 证据描述成全平台能力。

## 5. 可执行工作包

### WP0 — Contract Handoff（P0，最高优先级）

| ID | 待办 | 交付物 | 验收 |
|---|---|---|---|
| P0-1 | 盘点并冻结 DSL、Context、IR、Plan、Result、Release Binding、Journey Result 与 frame schema 版本 | schema manifest、兼容矩阵 | 任一不兼容版本统一返回 BLOCKED，禁止私有旁路格式 |
| P0-2 | 统一 canonical bytes、排序和所有 digest 输入 | 跨语言 digest fixture | 等价 YAML/JSON、字段重排和重复构建得到同一 digest |
| P0-3 | 固定 diagnostics catalog 与 Agent 可消费的 code/path/severity 格式 | diagnostics fixture、负向样例 | 诊断可稳定回放，Agent 不依赖文本猜测错误类型 |
| P0-4 | 固定 backend capability negotiation | capability matrix | 缺少 backend/provider 时不得产生 COMPILED 或 PUBLISHED |
| P0-5 | 将上述 fixture 放入跨组件 CI | contract CI job、失败说明 | Compiler、adapter、targetd、release consumer 共同消费同一 fixture |

开始 P1～P8 前，P0-1 至 P0-5 必须先以一次可追溯审计关闭；已有离线实现需要补齐
版本拒绝和跨组件回归，不能只证明单模块单测通过。

### WP1 — Bootstrap、Context 与 Candidate（P1）

| ID | 待办 | 交付物 | 验收 |
|---|---|---|---|
| P1-1 | 将 TargetEvidenceBundle、RKB read model、MHS 引用和已发布 Tool 投影为 Compile Context | context builder、compile-context artifact | identity、observed_at、route/schema/MHS/release/freshness 与 Compiler digest 正确绑定 |
| P1-2 | 规范化 route、resource、消息 schema、limitation、UNKNOWN/warning/error | normalized resource model | 只复制实际观测；信息不全时保留缺口而非静默补齐 |
| P1-3 | 建立 Bootstrap profile 与 discovery session | bootstrap evidence bundle、receipt | 安装/绑定后只读运行；不能执行自由 shell 或写业务工作区 |
| P1-4 | 生成 Candidate Index 并按意图查询 | index/read model、查询 API | 每条候选含 candidate_id、evidence、freshness、confidence、missing_evidence 与允许的 Probe 模板 |
| P1-5 | 接入 target/runtime/surface/evidence 分层 digest 与 dirty evaluator | change report、namespace policy | 新软件只使受影响 namespace DIRTY；无关 current 继续可用 |
| P1-6 | 建立 bounded follow-up 和离线/真实 LanderPi replay fixture | request/receipt、replay bundle、rolo-dsl bootstrap-verify | 只执行已注册模板；轮数、时间、artifact、scope 达上限时返回 BLOCKED；落盘产物可只读校验 |
| P1-7 | 接入 rolo-vis 的候选、freshness、gap 和证据只读视图 | read-model contract、截图/交互测试 | UI 不能把 candidate 呈现为已发布可调用 Tool |

P1 的关键现实门是“真实采集产生真实 Context”。当前离线 Candidate Index 只能作为实现
基础，不能跳过 P1-3、P1-6 和 P1-7。

### WP2 — Intent-driven Mapping（P2）

| ID | 待办 | 交付物 | 验收 |
|---|---|---|---|
| P2-1 | 完成 rolo skill 安装、本地 preflight、profile 选择和 targetd bootstrap 规则 | skill、operator runbook | Agent 只通过受控入口提交意图、DSL 和 typed follow-up |
| P2-2 | 实现意图→Candidate 查询与证据充分性判定 | resolver、sufficiency report | 证据充分时零额外 Probe；不足或不支持时给出具体 gap |
| P2-3 | 构建 Mapping Request 与四类 Operation 的 prompt fixture | request envelope、prompt fixtures | OBSERVE、COMPOSE、INVOKE、EXECUTE 均能生成合法 DSL；EXECUTE 另有 implementation contract |
| P2-4 | 接入 diagnostics repair loop 与 bounded Probe 分支 | repair receipts、negative tests | DSL 错误仅修 DSL；Context 缺失仅产生结构化 Probe 请求；超限必为 BLOCKED |
| P2-5 | 将 Mapping Proposal、风险、未知项和显式确认接到只读 UI/API | proposal persistence、confirmation receipt | 确认前不得发布或执行，取消后保留审计记录 |
| P2-6 | 验证 Agent 越权负路径 | policy fixtures | Agent 不可直接 SSH、改 Context、改 Catalog、扩大 Probe scope 或规避发布门 |

### WP3 — Target Compile 与 Conformance（P3）

| ID | 待办 | 交付物 | 验收 |
|---|---|---|---|
| P3-1 | 为一个 journey_session 建立、复用并恢复一条 SSH stdio 通道 | session transport、lease/resume receipt | Probe、Trace、Certify 可复用；断线用 session_id 与 idempotency_key 恢复而不重复执行 |
| P3-2 | 完成 DSL/IR/Plan 的 typed frame、签名校验、digest cache 与幂等传输 | cache receipts、负向矩阵 | partial upload、错误签名、target mismatch、重复 PUT 均 fail-closed 或安全幂等 |
| P3-3 | 接入真实 ROS/Middleware/MHS/CLI provider resolver | backend adapter、runtime evidence | 只绑定目标已观测、已注册的入口；缺依赖为 UNKNOWN 或 BLOCKED |
| P3-4 | 完成 OBSERVE、COMPOSE、INVOKE 的目标绑定，以及 EXECUTE source-bundle loader | generated bundle manifest、implementation contract | 只使用受声明依赖；目标业务 workspace 无写入 |
| P3-5 | 以真实目标执行 T1 Resolve、T2 Bundle Build、T3 Runtime Behavior、T4 Release Integrity | conformance report、canary artifacts | 任一失败均不产生 PUBLISHED release；成功可离线复核所有 digest |
| P3-6 | 完成 cancel、stop、timeout、lease、UNKNOWN 与 worker 故障恢复 | receipts/events、恢复测试 | 长任务可取消；断线和进程故障不会触发不安全重发 |

LanderPi 的 ROS2 用户隔离、EKF 语义、多个 cmd_vel 发布者和进程树清理是 P3-3/P3-6
的明确负向场景，不是可以在验收中忽略的环境噪声。

### WP4 — Tool Release 与产品读模型（P4）

| ID | 待办 | 交付物 | 验收 |
|---|---|---|---|
| P4-1 | 生成 immutable Tool Release manifest 与 artifact index 关联 | release manifest、binding | 必含 DSL、Context、IR、Bundle、compiler、target、Conformance digest |
| P4-2 | 完成 Catalog current 的原子发布、pin 与 rollback | catalog API、rollback receipt | 失败不覆盖旧 current；不可跨 target 隐式复用 |
| P4-3 | 落实 stale/dirty policy | stale evaluator、状态转换测试 | runtime/surface/evidence 漂移只影响相应 Release；重新 Conformance 后再切换 |
| P4-4 | 发布 Candidate→Proposal→Release 的只读 read model | API/schema、rolo-vis contract | 用户可追溯每一步证据、门禁和失败原因；状态不得混淆 |
| P4-5 | 做真实目标发布、回滚与跨版本升级演练 | acceptance pack、兼容记录 | 新旧版本、回滚窗口及恢复过程都有现场证据 |

### WP5 — Trace 运行路径（P5）

| ID | 待办 | 交付物 | 验收 |
|---|---|---|---|
| P5-1 | 将用户意图解析为只引用 PUBLISHED Release 的 Trace plan | intent/plan contract | 不存在、STALE 或 digest 不匹配的 Release 不可调用 |
| P5-2 | 统一 invocation、事件流、结果和 idempotency 模型 | invoke/event API、事件 fixture | 每次调用绑定 release/session/call digest |
| P5-3 | 实现受边界约束的诊断与有限重试 | diagnosis evidence、retry policy | 不生成新能力、不扩大权限；失败可解释 |
| P5-4 | 完成取消、断线恢复、UNKNOWN 与进程树清理 | resume/cancel flow、负向 canary | 物理或长运行任务不因断线自动重放 |
| P5-5 | 固化 Episode/evidence archive | episode index、保留策略 | 可复核 plan、调用、事件、诊断和最终结果，原始 artifact append-only |

### WP6 — Certify 显式测试路径（P6）

| ID | 待办 | 交付物 | 验收 |
|---|---|---|---|
| P6-1 | 固定 suite、路径输入、十用例和报告输出契约 | test suite schema、样例套件 | 用户明确指定后才启动，默认不会随 Trace 运行 |
| P6-2 | 按例加载同一 PUBLISHED Release | certify runner、per-case receipt | 每例都记录 release、Context、target digest 和 idempotency |
| P6-3 | 固定 expected/actual/status/evidence 比较语义 | case result schema | PASS、FAIL、BLOCKED、NOT_RUN 可稳定回放 |
| P6-4 | 实现事件、取消、失败即停/继续策略 | run control API、负向测试 | 策略由用户选择并写入报告 |
| P6-5 | 输出不可覆盖的 JSON、Markdown/HTML 报告与回归结论 | report、artifact index | 历史结果可查询并可与 Trace 证据关联 |

### WP7 — LanderPi MVP 集成（P7）

WP7 只消耗已通过离线门的组件，并以一个小而受控的建图或只读运行时目标作为首条旅程。
任何涉及物理行为的步骤都需要另行取得现场授权和停止条件。

| ID | 待办 | 验收 |
|---|---|---|
| P7-1 | 按 skill 完成本地 Rolo、targetd 和 profile preflight | Agent 未直接操作 SSH；bootstrap transcript 可复核 |
| P7-2 | 创建 discovery session 并执行真实 Bootstrap Probe | UI/API 显示真实 evidence 与 Candidate Index |
| P7-3 | 以“完成建图”等明确意图查询候选和充分性 | 命中时不执行无关 Probe |
| P7-4 | 证据不足时仅运行 namespace 范围内 bounded Probe | Context revision、receipt 和上限均可复核 |
| P7-5 | 生成 DSL、Compile、target bind 与用户确认 | 确认前不发布、不执行写操作 |
| P7-6 | T1～T4 通过后发布、pin、stale/rollback 验证 | Catalog 仅显示正确的 PUBLISHED release |
| P7-7 | Trace 调用并留下诊断与 Episode evidence | 成功完成目标，或给出可解释、可恢复的失败 |
| P7-8 | 用户显式要求时用同一 Release 执行十用例 Certify | 每例报告和安全停止条件完整 |
| P7-9 | 固化端到端 replay 与人工 acceptance pack | 可由 artifact index 串起 Bootstrap 至 Trace/Certify 的全部 digest |

### WP8 — Field Release 与运维闭环（P8）

| ID | 待办 | 交付物 | 验收 |
|---|---|---|---|
| P8-1 | 完成 targetd 安装、health、升级、卸载与恢复 | installer、field runbook | 新目标机可重复 bootstrap，失败可安全恢复 |
| P8-2 | 建立 PR、夜间回放、fake target 与真机 canary 的分层 CI | CI matrix、gate artifacts | 快速门不伪装现场通过；真机门失败不阻塞取证 |
| P8-3 | 接入 journey 指标、日志脱敏、artifact retention 与告警传输 | observability backend、retention proof | 可定位 session/compile/release/trace/certify 故障且无敏感泄露 |
| P8-4 | 固化故障分类、升级/回滚 runbook 和 operator training | operator guide、演练记录 | 工程师能区分 Context、Mapping、Compile、Runtime 与安全阻塞 |
| P8-5 | 执行版本发布、兼容窗口、弃用和回滚演练 | release notes、compatibility record | 旧 Release 行为、迁移期限和撤回策略明确 |

## 6. 并行组织与依赖

推荐使用以下工作流，避免把真实目标机占用在尚未闭合的离线契约上：

    P0 Contract
      ├─ W1：P1 Bootstrap / Context / Candidate
      ├─ W2：P2 Skill / Intent / Mapping（可先用冻结 fixture）
      ├─ W3：P3 Session / targetd / cache（可先用 fake target）
      └─ W4：P4 Release read model / stale / rollback skeleton

    W1 + W2 → P3 runtime 与 T1～T4 → P4 Release
                                             ├─ P5 Trace
                                             └─ P6 Certify
    P1～P6 的离线门 → P7 LanderPi MVP → P8 Field Release

工作流交接规则：

- W1 先交付真实且可脱敏的 Context fixture；W2/W3 只能引用该 fixture，不能各自扩展 schema。
- W4 可先实现状态机和 read model，但不得凭 fake Conformance 宣布 Tool 可调用。
- P5/P6 不得改写 Compiler 或 targetd 的 DSL 语义；只使用 P4 绑定的 PUBLISHED Release。
- 真实目标失败必须新增 evidence、receipt 和负向用例；不得回写成“fixture 正确”的结论。
- 目标机预约应只在 P1-3、P3-5、P5-4、P6-4、P7、P8 的现场门使用。

## 7. RKB、可信存储与 Rust 的并行轨

### 7.1 RKB 与 Episode 可信度轨

RKB-4 的 Episode metadata、只读查询、恢复、迁移和若干 LanderPi canary 已有实现，但以下
事项仍须作为产品化待办持续追踪：

| 优先级 | 待办 | 与主链的关系 |
|---|---|---|
| 高 | 在受控 vault 中演练 HMAC/签名密钥轮换、吊销、时间窗和目标机恢复 | G4/G8 发布可信度门 |
| 高 | 保持 Episode/Run append-only、跨进程恢复、损坏隔离和审计查询 | G5/G6 证据链门 |
| 中 | 接入真实 MHS provider、serial/topology 绑定和定期 freshness/断线采集 | P1 Context 质量与 Field Release 可信度 |
| 中 | 接通结构化告警的生产 transport、cadence 与部署 | P8 运维门 |
| 中 | 执行旧 TargetEvidence/ProbeResult/DiscoveryReport 的兼容公告和删除演练 | P8 兼容与弃用门 |

这些工作不得放宽现有只读边界；在没有真实 provider 证据时，MHS 或 hardware 信息必须保留
UNKNOWN/limitation。

### 7.2 Rust 执行平面迁移轨

Rust 重构保持为独立的执行平面迁移，不改变 P0～P8 的产品语义，也不阻塞以现有兼容后端
完成首个 LanderPi MVP。它可在 P0 后并行开展，但只有通过与 Python 后端的等价门后才可
成为默认路径：

| Rust 门 | 工作 | 与主计划的关系 |
|---|---|---|
| R0 | 固定 frame、bundle、session、cancel/resume 等价契约 | 复用 P0；必须先完成 |
| R1-R2 | fake target 的 targetd skeleton、SSH gateway、签名 Bundle/cache | 可与 P1/P2/P3 的离线工作并行 |
| R3 | Python Controller 双后端、session 恢复和等价 artifact index | 不替换现有默认路径 |
| R4-R5 | 真实 provider、T1～T4、Release/Trace/Certify 接入 | 复用 P3～P7 的现场门，不重复造证据 |
| R6 | WASM/现场发布与默认切换 | 只能在 P8、回滚窗口和双后端等价测试通过后进行 |

系统 OpenSSH 继续作为初期实现；native SSH library、WASM 默认执行和全量 Rust 化均不是
首个产品闭环的前置条件。

## 8. 验证矩阵、风险与决策点

### 8.1 分层验证矩阵

| 层 | 触发时机 | 必测内容 | 产物 |
|---|---|---|---|
| PR | 每个变更 | schema、canonical digest、负向契约、单元/组件测试 | CI report、fixture digest |
| 离线集成 | 合并前或夜间 | fake target journey、release lifecycle、Trace/Certify replay、artifact index | replay bundle |
| 固定目标 | 相关 runtime 变更后 | Bootstrap、runtime resolver、T1～T4、cancel/resume、stale/rollback | target evidence、conformance report |
| 受监督现场 | P7/P8 或物理行为变更 | 明确目标、停止条件、操作者、环境检查、重复 canary | acceptance pack、operator sign-off |

每层均至少覆盖成功、缺失证据、版本/digest 漂移、目标不匹配、取消/断线恢复和权限拒绝。

### 8.2 必须在开发前作出的决策

| 决策 | 最晚时间 | 默认建议 |
|---|---|---|
| 首条 P7 旅程的具体用户意图与可接受的“可解释失败” | P1 完成前 | 选择只读或有明确人工停止条件的最小建图切片 |
| Bootstrap 的采集预算、允许模板与隐私脱敏规则 | P1-3 前 | allowlist、最小 scope、bounded artifact，默认拒绝自由命令 |
| 用户确认所在界面和 confirmation receipt 的保留期 | P2-5 前 | 提案只读展示；确认与发布/执行分离 |
| targetd 的 signer/keyring、cache 目录和回滚责任人 | P3-2/P4-2 前 | 受控密钥、业务 workspace 外目录、旧 current 保留 |
| LanderPi 运动与 Certify 的安全停止条件 | P7 前 | 单独书面授权；断线不重放，异常立即 BLOCKED |
| Rust 是否进入默认执行后端 | R6 前 | 仅在双后端等价、P8 现场演练与回滚窗口通过后决定 |

## 9. 第一轮执行清单

按依赖与风险排序，下一轮应只启动以下事项：

1. 审计 P0 schema/digest/diagnostics/capability matrix，补齐一个跨组件 contract CI 门。
2. 将一份真实且脱敏的 Probe evidence 稳定投影为 Compile Context，并保留 replay fixture。
3. 用该 fixture 打通 Bootstrap → Candidate Index → sufficiency report 的只读路径和 UI read model。
4. 让 skill 只通过 Mapping Request、repair loop 和 bounded follow-up 提交映射，补齐越权负测。
5. 在 fake target 完成 session/cache/cancel/resume 的完整负向矩阵，再预约真实目标的 T1/T2。
6. 为首个只读 runtime/provider 完成真实 T1～T4，失败时验证旧 current 保持不变。
7. 接通 Candidate→Proposal→Release 的 read model、pin/stale/rollback，并完成一次真实回滚演练。
8. 在已发布 Release 上并行完成 Trace 的 Episode 证据链和 Certify 的十用例报告。
9. 仅在上述离线门全部通过后执行一次受监督 LanderPi 全链路 acceptance pack。
10. 将通过的现场证据、限制、兼容窗口和 runbook 进入 P8 发布材料；未通过项继续保持 PARTIAL/BLOCKED。

## 10. 总完成定义

本计划完成不以“代码存在”或“单次 canary 成功”为准。只有满足以下全部条件时，才可以宣布
Compiler 后产品闭环与 Field Release 完成：

1. P0～P8 的退出条件都已满足，所有状态转换可由 schema 和 artifact index 复核；
2. Candidate、Proposal、PUBLISHED Release、STALE 和 BLOCKED 的权限与展示彼此清晰；
3. Agent 从未获得 SSH/shell/Catalog 越权能力，目标业务 workspace 未被 Bundle 写入；
4. 全链路既能在 fake target 离线回放，也有对应的真实 LanderPi acceptance pack；
5. Trace 与显式 Certify 都只消费同一 digest-bound PUBLISHED Release；
6. 安装、升级、取消、断线恢复、stale、rollback、密钥轮换和保留策略均有负向证据；
7. ENGINEERING_STATUS、兼容矩阵、runbook、release notes 与本计划同步更新。

## 11. 关联资料

- Compiler 技术方案：ROLO_V2_DSL_COMPILER_DEVELOPMENT_PLAN_ZH.md
- 互补开发计划：ROLO_V2_DSL_POST_COMPILER_REMAINING_DEVELOPMENT_PLAN_ZH.md
- 产品路线与任务拆解：ROLO_V2_POST_COMPILER_PRODUCT_ROADMAP_ZH.md
- targetd / SSH 计划：ROLO_V2_SSH_SIGNED_BUNDLE_TARGETD_PLAN_ZH.md
- LanderPi MVP 计划：ROLO_V2_LANDERPI_AGENT_JOURNEY_MVP_PLAN_ZH.md
- Rust 执行平面计划：ROLO_V2_RUST_REFACTOR_PLAN_ZH.md
- 发布兼容策略：ROLO_V2_RELEASE_COMPATIBILITY_POLICY_ZH.md
- 工程状态台账：../reference/ENGINEERING_STATUS.md
- RKB 待办：../TODO.md
