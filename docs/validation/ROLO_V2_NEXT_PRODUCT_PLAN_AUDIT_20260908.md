<!-- status: active; authority: reference; owner: rolo maintainers; last_reviewed: 2026-09-09; baseline: origin/main@390bad38ce0d84f4772d203423929e2a0ebc4a50 -->

# Rolo v2 下一阶段产品开发计划审计（2026-09-08）

## 审计范围与结论

本次审计将外部计划 `ROLO_V2_NEXT_PRODUCT_DEVELOPMENT_PLAN_ZH.md` 的基线
`f74fc229189743963701a0c2fdefc23703fc5d8f` 与 2026-09-08 拉取的
`origin/main@390bad38ce0d84f4772d203423929e2a0ebc4a50` 对照，并复核实现、测试、状态台账、
现场记录和一轮 LanderPi 零运动状态采集。开发分支为 `codex/next-product-plan`。

计划的里程碑顺序和证据分级仍然适用，但计划中的“当前基线”已经落后于代码：本分支不仅关闭了
plain Release 发布、空 Release Certify 和无目标 authority 的通用 CALL 等成功路径，还在固定
LanderPi 上完成了严格零运动的 R0 targetd 全链 canary。2026-09-09 的后续 run 又把正式
`ReleaseBoundCertify`、逐例 v2 CallReceipt sidecar、CertificationReport/events/release-binding 与
artifact index 接入同一 pinned session，并以 10/10 PASS 提升 N6 fixed-target R0 证据。该 E3 仍只覆盖
fixture authority 下的 `OBSERVE/read/R0` `/odom` 路径，不能外推为生产 Admission、正式 Trace 或
实体运动验收；N0～N7 因而仍未全部完成，N7 physical motion 继续 `BLOCKED`。

## N0～N8 复核

| 里程碑 | 当前判定 | 已有证据 | 未满足的退出条件 |
|---|---|---|---|
| N0 Contract Handoff | `PARTIAL / E2` | Python 内已有版本化模型/canonical digest、独立 ExecutionBundle 签名、typed BundlePlan v2 method scaffold 和离线 matrix；targetd 可在同进程独立编译，并由 journey 比对 bundle digest | Backend negotiation 尚未严格拒绝错误 SPI version；release/跨进程仍未从受信资产重算完整 Plan；跨语言 canonical fixture、统一结构化 diagnostics 和完整 CI matrix 缺失 |
| N1 Bootstrap-Candidate | `PARTIAL / E2`，底层 Probe 已有 E3/E4 | Probe、Context adapter、Candidate、分层 dirty digest 均有实现 | 未由同一真实 Bootstrap 产出并回放 Context/Candidate；freshness 缺失可误判 READY；RKB/MHS/Catalog 联合投影、增量重探和 UI 缺失 |
| N2 Intent Mapping | `PARTIAL / E2` | 除 fixture receipt 外，已新增 production operator assertion、issuer-bound ACL、三角色 trust policy、双 ledger、challenged external CAS head、pending/reconcile；TargetdService、TargetdDslService 与 ReleaseConsumer 可注入 production gate，慢验签/anchor/head expiry、尾删/旧 head 重放/重复 ACL/bad-signature cancel 均 fail-closed | 仓库不内置生产私钥或 adapter；真实 IdP/JWKS/KMS、单调 anchor、可信时钟、OS owner/ACL、signed cancel transport、foundation/current-head resolver 与唯一 derived scope 尚未部署。compiler、probe registration、ReleasePublisher、product CLI、journey/default daemon 仍未接 production composition，CLI fixture 不构成真实认证 |
| N3 Target Compile | `PARTIAL / E3`，仅 fixed-target R0 | 新 session `n7-r0-20260908T161029Z-7cda2170` 在一条 pinned SSH stdio channel 内贯通 fresh snapshot→DSL 五阶段→T1～T4→target-owned Release/authority→Trace→正式 Certify；ExecutionRequest/CallReceipt 绑定 Mapping、Release、Context、Catalog/current authority、fence/provider，response sequence/run/request/call mismatch 会 poison channel 且不重发 | E3 只覆盖 fixture authority 与固定 `/odom` `ros2-readonly`；DSL PUT 仍为进程内状态，BundlePlan→ExecutionBundle 是 canary 专用 bridge；lease + opt-in OS-process/duplex 仍是未接默认 daemon 的实验 R0 seam，generic upload 尚未接 targetd，target-signed durable receipt 和非 R0 process provider 尚未闭合 |
| N4 Tool Release | `PARTIAL / E2`；scoped target path E3 | 新增跨进程 CAS 的 append-only Catalog、signature-required transaction-log mode、由日志推导/校验的 snapshot crash recovery、no-replace immutable publish、前进式 rollback、外部 typed target signature verifier，以及 32 MiB 内容寻址分片上传/恢复/篡改检测；R0 targetd 仍从自身 cache 重建并激活 current Release | compatibility ReleasePublisher 仍显式使用 unsigned Catalog；真实 target signer/trust provider、跨主机 head policy、targetd 通用上传/commit wiring、可信 target artifact reload 与 Windows 目录 fsync 仍缺；外部 verifier 不得由 caller payload 替代 |
| N5 Trace | `PARTIAL / E2`；target-call substrate E3 | 离线诊断/有限恢复、receipt-gated post-compiler journey 和清理前历史 mapping Trace 可审计；R0 canary 在 verified Release/current authority 下执行 1 次真实 `/odom` generic CALL | 本次 `trace-01` 是 canary direct CALL，不是 `ReleaseBoundTrace` 的 canonical TracePlan、durable session/event/artifact journey；正式路径仍缺 call digest、targetd receipt bridge、重启对账和 Episode |
| N6 Certify | `PARTIAL / E3`，fixed-target R0 | 正式 `ReleaseBoundCertify` 经 targetd adapter 在 LanderPi 同一 current Release/Context/target authority 下运行 10/10；10 个唯一 key/immutable v2 receipt sidecar、report、events、binding 与 16-entry index 已逐项验 digest，targetd CALL counter 连同 Trace 为 11，post-cancel 不增 | 仍是 fixture operator/partial authority，且只覆盖 `/odom` R0；跨进程 durable request store、resume/reconcile、Episode/list/download/history 和其他 provider/风险等级未闭合 |
| N7 LanderPi MVP | `PARTIAL / E3`，zero-motion R0；physical motion `BLOCKED` | 正式 run 使用单一 pinned SSH stdio：T3 1、Trace 1、formal Certify 10，10/10 PASS；raw 未持久化，同通道 `/dev/shm` cleanup residual 0/no fallback，另行只读确认 stage 不存在。磁盘从历史 97%/1.9 GiB 改善为 76%/约 13.1 GiB，可关闭容量门 | `operator_auth=FIXTURE`、`authority_partial=true`；现场仍有 6 个 `/controller/cmd_vel` publisher、2 个 direct-motor publisher，无已验证独立急停、现场操作员、安全区、target-owned live fence/stop ack。现有 OS-process/duplex 只读 seam 未接 service/daemon，缺临界点实时 graph/fence CAS，代码继续无条件拒绝所有 physical v3；本证据不是 motion acceptance |
| N8 Field Release | `BLOCKED`；局部组件 E2 | installer/runbook、日志脱敏、retention 和兼容策略有局部实现或设计证据 | N5～N7 未过门；上述组件未串成 Field Release，且生产持久化、升级/回滚、密钥轮换/吊销、监控告警、客户机演练和 operator sign-off 缺失 |

这里的判定以计划的退出条件为准，刻意严于 `ENGINEERING_STATUS.md` 中部分 feature 的局部
成熟度。局部 E4 Probe 或单次 E3 provider canary 不能外推为整条产品 journey 的 E4。

## P0 待办（发布或再次运动前必须关闭）

### P0-A：统一 Contract Pack 与真实 Bundle identity

- 冻结 DSL、Context、IR、BundlePlan、Compile Result、Target Conformance、Release、Journey 的
  schema/version/canonical bytes；缺 version 必须拒绝。原五字段 `rolo-bundle-plan/v1` 与新完整契约
  必须作显式版本/迁移决策，推荐完整契约升为 v2；旧 v1 只能显式迁移或重编，不得进入
  release/provider，也不得静默补默认。
- Backend SPI 若将 `compile(ir, output_dir)` 改为要求额外 identity 参数，也必须升级 SPI 版本并拒绝
  v1，或提供显式 v1 adapter；不得在同一个 `rolo-backend-spi/v1` 下破坏调用契约。
- Bundle digest 必须覆盖 DSL、IR、backend/version/capability、target fingerprint、binding、runtime
  context 和稳定排序的 artifact manifest（至少 path/sha256/size/role），不能等同于 `ir_digest`，
  也不能从 IR 伪造缺失的 DSL/target identity。
- diagnostics 统一为 `code/path/severity/message/details` typed 结构；provider 未运行或能力未知时只能
  `UNKNOWN/BLOCKED`，provider 已运行且断言失败时为 `FAIL`。
- 由 compiler、adapter、targetd、release consumer 共同运行正向、篡改、旧版本、错 target、错
  signature 和跨语言 canonical fixture。

验收：任一 identity 字段变化都改变相应 digest；四个组件对同一 fixture 得到相同 bytes/digest；
缺失或不兼容字段在进入 provider/Catalog 前 fail-closed。

### P0-B：Confirmed Mapping Admission / Authority v1

- confirmation receipt 必须绑定 candidate/proposal/DSL/context/evidence/target/catalog/derived scope、
  authenticated operator、decision、时间和有效期。确认写端与 Agent verifier 必须权限隔离；CLI
  的调用方字符串不能被当作已认证身份，ledger root 也不能由不受信请求任意选择。
- Proposal、Context、Candidate、foundation evidence 和 Catalog current head 必须从受信 store/resolver
  独立加载；禁止把 receipt 或 caller payload 中的值复制出来，再与同一份输入比较而形成自认证。
- ledger 除 API 层 hash chain 外，还必须具有受保护或签名、外部锚定的单调 head，能检测删除完整
  末尾 `CANCELLED` 记录的后缀回滚。确认服务必须拒绝未来时间，验证与提交必须在锁内使用可信当前
  时间。本轮 production substrate 已加入 challenged fresh head/CAS、三用途 pinned role policy，并在
  慢 verifier、anchor CAS 和副作用 callback 的边界重新采样可信时间；跨 expiry 时零写/零 callback，
  anchor 已提交时返回唯一 receipt 且重试不重复推进。
- 以唯一 `derive_scope()` 从 DSL、operation、provider 与 COMPOSE 依赖闭包推导 access/risk/operations，
  并要求与 Proposal/receipt exact equality；禁止将 EXECUTE 低报为 read/R0 或遗漏子操作。
- `compile/register/release/execute` 的每个最低副作用边界都必须自行重验 active receipt 与 current
  heads。公共 compiler 已在 frontend/backend 前拒绝缺失 admission，并通过 staging、独立
  artifact/identity 复核及 admission-locked atomic commit 关闭 cancel→落盘窗口；固定 R0 targetd
  provider 又以 Mapping ledger、Catalog current、authority current 与 receipt state 的嵌套锁线性化
  最低调用边界。probe registration、通用 Catalog/provider 和缓存后 descriptor/use 仍须采用同级围栏。
- foundation evidence 必须先落盘并验 digest，Proposal 才能引用；取消、过期、改参、跨 target、
  authority head 更新和 scope 扩大均返回 `BLOCKED`。

验收：无真实 operator 身份、无受信 Proposal/current heads、ledger 后缀回滚、未确认、篡改、未来、
过期、取消、跨目标、旧 Context 和低报 scope 的请求均在 frontend/provider/持久化前被拒；确认与取消
并发只有一个可线性化结果，相同受信输入和确认可确定性回放。

本轮已落地该项的离线 foundation：Proposal v2 固定为不可变 `PROPOSED` 事实；fixture API ledger 与
production store 明确分离。production store 要求外部签名 operator assertion、issuer-bound ACL、
`OPERATOR_ASSERTION`/`ACL_DECISION`/`LEDGER_HEAD` 三用途 issuer/key/trust-root 互斥且逐用途 pin、双
ledger、challenged external head、pending/reconcile 和可信时间；尾删、历史 head 重放、bad signature、
重复 ACL、慢验签过期、慢 anchor 与 stale-head callback 均 fail-closed。只有 `TargetdService`、
`TargetdDslService` 和 `ReleaseConsumer` 已支持注入 production gate；compiler、probe registration、
ReleasePublisher、product CLI、post-compiler journey 与默认 daemon 仍实例化 base/fixture gate。公共
compiler 的 artifact commit 与取消在其 ledger lock 下线性化，但这不等于生产身份。该状态仍为
`PARTIAL / E2`：真实 IdP/JWKS/KMS、ACL/head adapter、可信时钟和 OS owner/ACL 尚未部署；
Proposal/Context/Candidate/Catalog/foundation 的 current-head resolver、唯一 derived scope、
verified-prefix cache/总验签预算和真实操作员 UI 也未完成。固定目标 E3 仍使用 fixture authority，
不能升级 N2。

### P0-C：统一 targetd 传输与安全恢复

- DSL PUT/CHECK/RESOLVE/COMPILE/T1～T4 已通过 `DSL_REQUEST` 与 generic CALL 复用同一 session/SSH
  stdio channel；targetd 会从自身 compile/conformance cache 重建 scoped verified Release，再执行
  Catalog CAS provision 与 target-owned authority activation，而不是接受 controller 自报 current head。
- ExecutionRequest v2 与 CallReceipt v2 已绑定完整 canonical request、`(session_id, idempotency_key)`、
  Mapping receipt、Release/Context、Catalog/authority current head、fence epoch、provider/operation/mode；
  targetd 在 ACCEPTED、STARTED 和紧邻 provider 的边界重验。公开 `open_session` 已使用 create-only
  语义拒绝同 id 覆盖；已有 OPEN/RESUME 仍要求 resume token，in-flight 重放进入 QUERY/reconcile。
- 固定 `/odom` `ros2-readonly` provider 只接受空参数 `odom.sample`，结果只保留 status/digest/size；
  Mapping cancel 后使用新 key 的 CALL 已在 provider 前拒绝。该结论仅覆盖已结束的 R0 调用，不能代替
  active call 的抢占式 cancel 或实体运动 stop acknowledgement。
- worker lifecycle substrate 已实现 durable lease/heartbeat、按 target/session/key/request digest 唯一的
  supervisor incarnation、显式 cancel/stop request 与 worker ack 分离，以及 deadline/clock rollback/
  crash/restart/thread exit 的 `UNKNOWN` 对账。新增 opt-in `LeasedProcessWorkerRuntime` 只允许 exact
  `/odom` R0，使用 spawn 进程、有界 JSON duplex IPC、WORK_STARTED 顺序门和 worker-held token ack；
  它尚未接 TargetdService/default daemon，也没有 target-owned START receipt + live graph/fence CAS、
  production sealed adapter、OS sandbox 或 durable result/receipt 两阶段提交，因此不是 production worker，
  更不是实体运动 stop 证据。
- Release 分片上传层已有 chunk/resume/digest verify/atomic commit/脏上传清理，但尚未接 generic targetd
  transport；DSL PUT 也需 durable resume。T1～T4 proof、CallReceipt 和 authority head 还需受信目标签名/
  外部锚定；EXECUTE
  仍需签名 loader、依赖 allowlist、最小权限隔离和业务 workspace no-write sentinel。

验收：断连/重发/改参重用 key/worker crash/超时/取消矩阵无重复物理调用；错误签名、target、
surface、binding、run 或 digest 均在 provider 前拒绝。

### P0-D：ReleaseCatalog transaction v1

- 公共 `publish()` 已改为无条件拒绝，所有 callable Release 必须经过 `publish_verified()`；固定 R0
  目标又增加 targetd 自身 cache 重建、ExecutionBundle exact match、Catalog CAS provision 与 current
  authority activation。Target Conformance 仍需进一步由 target 签名或进入受信持久化后才可泛化。
- `publish_verified()` 必须自行从受信 artifact store 重载并重算完整 lineage，不能接受调用方构造的
  PASS model 自证；`OFFLINE/SIMULATED` conformance 只能进入独立、不可调用的目录。
- consumer 必须重算完整 manifest digest，而非只检查 `sha256:` 前缀。
- 先排他持久化 immutable artifacts、失败记录和完整
  Candidate→confirmed Proposal/receipt→CompileResult/Bundle→TargetConformance→Release lineage，再用
  CAS 切换 current；失败 attempt 也必须 append-only 入链。
- 锁/CAS 覆盖整个 Catalog read-modify-write（包括不同 tool 并发），使用唯一 temp、文件与目录 fsync；
  实现 pin、fail-closed stale、同 target/freshness rollback 和 append-only transition history。历史
  STALE 不得被 rollback 洗白；pin 只能阻止 promotion，不能绕过 freshness/callability。
- 发布调用直接返回其提交的 digest/revision；旧 current 在任何中途失败、并发冲突或崩溃时不变。
- `current()` 和 read model 必须重验 Mapping authority/freshness；rollback 也必须经过同一 authority、
  target 与 freshness gate，不能恢复已取消或过期确认下的 callable release。

本轮已新增 append-only transaction log、可强制目标签名的 Catalog mode、由日志推导/校验的 snapshot、
跨进程 CAS、crash-tail recovery、no-replace immutable publish、前进式 rollback、typed external
target-signature verifier，以及 32 MiB/1 MiB×64 的内容寻址断点上传和篡改检测。Catalog 事务锁不再按
mtime 窃取仍活跃的慢 verifier 临界区。它们关闭了本地 transaction substrate，但 compatibility
`ReleasePublisher` 仍显式构造 unsigned Catalog；真实 target signer/trust provider、跨主机 head policy、
targetd 通用上传/commit wiring、可信 artifact reload、rollback/current 的完整 authority/freshness 重验与
Windows 目录 fsync 仍未完成，所以 N4 继续是 `PARTIAL / E2`。

验收：故障注入、同 tool/不同 tool 并发发布、pin、历史 STALE/过期证据 rollback、跨 target
rollback、manifest 篡改和 lineage 重建测试全部通过；plain Catalog 不能进入 Trace/Certify。

### P0-E：Release-bound Trace/Certify

- 冻结 TracePlan 和 call digest，强制 scope、预算、权限和 exactly-one current PUBLISHED Release；
  session/event/case/receipt 均携带相同 release/context/target identity。
- consumer 必须从权威 ReleaseCatalog 按 digest resolve/load，不接受 caller-supplied manifest 自证；
  普通 TargetCatalog 与 ReleaseCatalog 必须合并为单一真相源或确定性只读投影。
- 将普通只读 Catalog 与可执行 Catalog 分离；禁止默认 invoker 把无 provider 调用伪装为成功。
- Trace 状态、事件和 receipt 持久化，启动时与 targetd 对账；接入 append-only Episode，cancel 必须
  等到 provider/stop acknowledgement。
- `CertificationSuite`、`CertificationReport`、core、HTTP 和 release-bound 入口已统一强制恰好十例、
  单 tool、同一 Release/Context/target，9/11 例、空 Release、multi-release 和 identity 漂移均拒绝；
  JSON Schema 与运行时模型已对齐。
- fixed-target R0 已用正式 `ReleaseBoundCertify` 驱动十例；每例唯一 idempotency key、完整
  TargetdCallReceipt v2 sidecar、expected/actual/evidence/ref、report/events/release-binding 和 artifact
  index 均不可覆盖并逐项验 digest。该结果把 N6 的 `/odom` R0 证据提升到 E3，但 fixture operator、
  partial authority、跨进程 durable request/resume/reconcile、Episode/list/download/history 与其他
  provider/risk 仍未闭合。
- 统一持久化/read-model namespace，支持重启回放、list/download/history、append-only Episode 和
  rolo-vis 时间线/逐例视图；cancel 必须与 targetd 对账，有运动时还须等待 stop acknowledgement。

验收：plain/stale/mismatch/multi-release 全部在 provider 前拒绝；断连恢复不重放；十例报告可由
artifact index 离线重建且每例 release digest 相同。

### P0-F：测试、文档与现场安全门

- 修复 pytest 文件 allowlist，保证新增测试会被收集；CI 对新代码执行 schema、Ruff、完整 pytest、
  replay 和 docs gate。全仓 Ruff 的历史债务单独建账，不能掩盖本次增量。
- [N7 只读预检](./LANDERPI_N7_READONLY_PREFLIGHT_20260908.json) 保留根分区 97%/约 1.9 GiB 的历史
  快照；后续 [motion gate 重检](./LANDERPI_N7_MOTION_GATE_RECHECK_20260909.json) 已观察到 76%/约
  13.1 GiB 可用，容量门可重新判为通过。R0 canary 仍坚持 `/dev/shm` 容量回执、32 MiB 包/128 MiB
  展开上限和 exact-root 零残留清理；容量改善不解除身份、实时控制和实体安全门。
- 任何 `mapping.run`、旋转或 Certify 运动必须再次取得现场操作员、独立急停和安全区确认，并隔离或
  fence 现存 6 个 `/controller/cmd_vel` 发布者及 2 个 `/ros_robot_controller/set_motor` 直接电机发布者；
  还须验证 target-owned stop acknowledgement 与独立物理停止，状态采集不得表述为运动验收。
- 将 `app.mapping.status` 与写操作拆权：它应是 OBSERVE/read scope，零运动 `--status-only` 不应要求
  伪造 `safety_confirmed`，也不应把 run/stop/save 的 R3 权限一并放入同一可调用 scope。

## P1 与 P2

P1 聚焦产品闭环：修复 Candidate freshness 缺失时的 READY 误判和全局 warning 污染；接入真实签名
Bootstrap/RKB/MHS/Catalog 联合投影；按 operation/provider matrix 补齐 ROS、Middleware、MHS、CLI
的 OBSERVE/COMPOSE/INVOKE/EXECUTE resolver；统一
artifact/list/download API；实现 Candidate、Proposal、Compile、Release、Trace、Certify 的 rolo-vis
只读视图和 UI contract tests。

P2 聚焦 N8：生产 Catalog/metrics backend、installer 升级/卸载/恢复、日志与证据留存、兼容窗口、
密钥轮换/吊销、告警、runbook、operator training，以及新装、升级、回滚、断连和旧 Release 恢复的
固定目标/现场演练。

## 已启动的开发切片

本分支已推进以下零运动改动：

1. typed BundlePlan v2 与 canonical `bundle_plan_digest` 已绑定 DSL/Context/IR、backend/capability 和
   artifact manifest；targetd 会独立编译并在 T1～T4 比较 identity，旧 v1 不得进入 provider；
2. `DSL_REQUEST` 已把 DSL PUT/CHECK/RESOLVE/COMPILE/T1～T4 放入 generic journey 的同一 SSH stdio
   channel；统一 daemon 会装载 ROS2 resolver/registry，固定 R0 provider 只能读取 `/odom`；
3. ExecutionRequest/CallReceipt v2、targetd verified Release provision、Catalog current CAS、target-owned
   authority/fence epoch 与 Mapping cancel 已贯通。新的 CALL key 在 cancel 后被 provider 前拒绝，
   现有 OPEN 也已改为 create-only，不能无授权覆盖 session；
4. legacy Release `publish()` 已关闭；ReleaseCatalog transaction、typed target signature receipt 与
   resumable upload substrate 已加入；Certify 模型、schema、core、HTTP 与 release-bound 入口已收紧为
   恰好十例、单 tool 和完整同一 Release/Context/target identity；
5. production Mapping Authority substrate 已加入 signed operator assertion、issuer-bound ACL、三角色
   trust policy、双 ledger、challenged external head、pending/reconcile 与 product gate 注入；真实 adapter
   composition 尚未部署，fixture 入口不构成生产认证；
6. worker lifecycle 已加入 durable lease/heartbeat、唯一 incarnation、interrupt/ack 和 crash/restart/
   deadline 对账；另有显式 opt-in 的 exact `/odom` R0 spawn-process + bounded duplex IPC seam，但尚未
   接 TargetdService/default daemon，也没有 production adapter/OS sandbox/durable result 两阶段提交；
7. ExecutionRequest v3 与 motion-safety evaluator 已冻结安全证据绑定。由于生产调用仍缺 target-owned
   START receipt、authenticated daemon duplex STOP 与 provider 临界点 live graph/fence CAS，
   TargetdService 对全部 physical v1/v2/v3 请求均无条件在 provider 前拒绝；离线 `ADMITTED` 不代表可执行；
8. `scripts/landerpi_n7_r0_canary.py` 已在一条 pinned channel 内完成 T3 1、Trace 1 与正式
   ReleaseBoundCertify 10/10，取消后 provider 计数不增，并清理临时 `/dev/shm` stage。

这些改动把 N3 的 fixed-target R0 证据和 N7 的 zero-motion R0 切片提升到 E3，但不等于 P0-A～P0-F
整体完成。下一切片应优先把现有局部 E3 产品化：接入真实 operator authentication/ACL/ledger-head
adapter 与可信 Context/Candidate/Proposal/Catalog/foundation resolver、唯一 derived scope；将
BundlePlan→ExecutionBundle bridge、Release/Catalog authority、target signature 与通用上传接入
targetd；再把正式 ReleaseBoundTrace 接到 TargetdCallReceipt/artifact index。

并行把现有 opt-in OS-process R0 seam 接入 TargetdService 与 authenticated daemon duplex control，完成
target-owned START、实时 cancel/STOP、临界点 graph/fence CAS、durable result/receipt commit 和 crash
reconcile。旧 in-flight receipt 进入
`UNKNOWN/reconciliation required` 只防止自动重复 CALL，不证明 provider 已停止。以上缺口关闭前，
R0 只读调试可按相同严格边界重复，实体运动仍不得启动。

## 本轮 LanderPi 清理与零运动检查

- 清理前的历史状态回归曾通过固定 host key 和 key-only SSH，在 `MentorPi` 容器内以 `ubuntu` 用户
  只读确认 `/scan`、`/odom`、`/map` 在线，并执行
  `OPEN → BOOTSTRAP → HANDOFF → TRACE → CALL → CLOSE` 的 `app.mapping.status`：约 4.012 秒内
  观察到 scan 39、odom 107、map 8 个样本，`motion_started=false`。该记录的
  `target_fingerprint=UNKNOWN`、`release_digest=null`、`compile_context_digest=null`，只构成
  transport/provider E3 历史摘要；其远端 session、地图、脚本和结果随后已删除，不能回放，也不是
  N5/N7 digest-bound acceptance。
- 用户明确授权后，已不可恢复地删除 host 与 `MentorPi` 容器内所有经精确枚举、解析并确认属于
  Rolo/RKB 的工程/部署目录、tarball、state/cache、临时构建与运行产物，旧 trace/canary/probe
  脚本及结果、ROS `.bak-rolo` 备份，以及仅包含 Rolo editable package 的 uv archive cache。删除后
  在 host 的 `/root`、`/home`、`/tmp`、`/var/tmp`、`/opt`、`/var/lib`（含 Docker overlay）和容器的
  `/tmp`、`/var/tmp`、`/home/ubuntu`、`/root` 复核，明确 Rolo/RKB 名称边界命中为 0，相关进程与
  Docker 命名资源也为 0。未修改 `/home/pi/robot_pi`、ROS 当前文件或其他非 Rolo 数据。清理后
  该时点根分区仍约 97% 使用率、约 1.9 GiB 可用；用于继续开发调试的 key-only SSH 公钥授权暂时保留。
- 后续不可变的 [N7 只读预检](./LANDERPI_N7_READONLY_PREFLIGHT_20260908.json) 确认 host 和容器健康、
  ROS 2 Humble graph 为 60 topics/32 nodes、targetd 未部署、明确 Rolo/RKB/targetd 残留为 0；同时记录
  系统依赖不满足完整项目环境，持久调试应使用专用 venv。该快照时点根盘仍为 97%，因此持久部署/采集继续
  `BLOCKED`。该快照还发现 `/controller/cmd_vel` 有 6 个发布者、direct motor topic 有 2 个发布者，
  它们构成独立的 physical-motion blocker。
- 清理后又以该次 canary 当时打包的 163 个 Python 源文件部署只读 admission canary；本地与目标源码 digest 均为
  `sha256:e6dcfa6da1e5b978359dedc44a5aee7053a691562f35199c2873934e82aaa758`。现场观察到 60 个 topic、
  32 个 node，并通过真实 ROS provider 只读取一次 `/odom`（`nav_msgs/msg/Odometry`）；原始 payload
  未持久化。Proposal→confirm→targetd compile→Target Conformance 为 `PASS`。公共 compiler 的
  frontend/backend 前 gate、同盘 staging、独立复核及 ledger-lock `commit_if_active` 原子提升均在
  目标环境通过，staging 残留为 0。
- 随后于同一目标取消同一 live receipt；相同 compile/conformance 请求均以
  `MAPPING_CONFIRMATION_CANCELLED` 返回 `BLOCKED`，continuation provider 调用保持 0→0，compiler
  commit 保持 1→1。全过程未 publish、未调用 ROS publish/service/action、未 INVOKE/EXECUTE、未
  执行 `mapping.run`、旋转或 Certify，因而没有物理运动。canary 临时目录已从 host/container 删除，
  最终明确 Rolo/RKB 残留仍为 0；详见
  [LanderPi Mapping Admission Canary](./LANDERPI_MAPPING_ADMISSION_CANARY_20260908.json)。
- canary 使用已固定 known_hosts 的专用 SSH key；没有使用、写入或持久化用户提供的密码。目标 host
  为 aarch64/Python 3.11.2，`MentorPi` 容器为 Python 3.10.12/ROS 2 Humble。
- N3/N6/N7 R0 调试保留了四次不可变的 fail-closed 现场尝试：
  [attempt 1](./LANDERPI_N3_N6_N7_R0_CANARY_20260908_ATTEMPT1_BLOCKED.json) 为协议帧无效且通过受限
  fallback 清理，
  [attempt 2](./LANDERPI_N3_N6_N7_R0_CANARY_20260908_ATTEMPT2_BLOCKED.json) 与
  [attempt 4](./LANDERPI_N3_N6_N7_R0_CANARY_20260908_ATTEMPT4_BLOCKED.json) 在 T1～T4 阶段阻塞，
  [attempt 3](./LANDERPI_N3_N6_N7_R0_CANARY_20260908_ATTEMPT3_BLOCKED.json) 在 read-only CALL 阶段阻塞；
  四次都清理到 residual 0，未被成功结果覆盖。
- 早期 [N3/N6/N7 R0 LIVE canary](./LANDERPI_N3_N6_N7_R0_CANARY_20260908.json) 在 session
  `n7-r0-20260908T133113Z-ea821eea` 通过：同一 pinned SSH stdio channel 内完成 fresh `/odom`
  snapshot、DSL 五阶段、verified Release provision/authority activation、T3 proof 1 次、Trace CALL
  1 次和 direct Certify CALL 10 次。targetd 的 CALL 单调计数为 11，取消 Mapping 后新 key 仍为 11；
  T3 由独立 conformance proof 计 1，二者没有伪装成同一计数器。原始 ROS payload 未持久化，正常
  同通道 `/dev/shm` 清理 residual 为 0 且没有 fallback。该次使用 `operator_auth=FIXTURE`、
  `authority_partial=true`，只构成 target-call substrate 历史证据，不构成正式 N2、N5、N6 或实体运动验收。
- 随后的 [正式 N6 R0 run](./landerpi_n6_formal_r0_20260909/) 在新 session
  `n7-r0-20260908T161029Z-7cda2170` 上把 10 次调用接入 `ReleaseBoundCertify`：10/10 PASS、10 个唯一
  idempotency key 与不可覆盖 CallReceipt v2 sidecar、report/events/release-binding、16-entry artifact
  index 全部交叉验 digest。连同同 session Trace，targetd provider count 为 11；Mapping cancel 后新 key
  被拒且仍为 11。原始 ROS payload 未持久化，敏感扫描为 0，同通道 cleanup residual 为 0/no fallback，
  远端 stage 又经独立只读检查确认不存在。该 run 仍是 fixture operator/partial authority，只提升
  fixed-target `/odom` R0 的 N6 E3，不是生产认证或运动验收。
- 最新 [motion gate 重检](./LANDERPI_N7_MOTION_GATE_RECHECK_20260909.json) 将容量状态更新为 76%/约
  13.1 GiB 可用；同时再次确认 6 个 `/controller/cmd_vel` publisher、2 个 direct-motor publisher，且
  没有独立急停、现场操作员、安全区或 exact-call stop acknowledgement，因此 physical motion 仍
  `BLOCKED`，本轮没有 ROS publish/service/action 或电机命令。

## 验证基线与后续门禁

审计启动时，main 的配置内测试集为 `451 passed, 1 skipped`；本分支先后记录过
`469 passed, 1 skipped` 和 `597 passed, 1 skipped` 的中间检查点。本轮将 DSL API/service digest、
BundlePlan、Mapping Admission、resolver/replay/release、probe registration、LanderPi mapping runtime 与
N7 R0 canary 测试显式加入 pytest allowlist，避免“测试存在但未运行”。收口完整回归为
`955 passed, 5 skipped, 2 warnings in 52.11s`；225 份 schema JSON、79 份 Markdown、
`run_release_check()`、MVP gate、post-compiler replay、增量 Ruff 和 diff-check 全部 `PASS`。全仓 Ruff
的历史问题仍需单独治理；两个只读 LanderPi canary 均不能替代运动验收。

zero-motion R0 调试可在 fresh snapshot、固定 `/odom`、tmpfs 容量、single-channel、exact cleanup 和
provider-count 门内继续；要进入 N7 受监督 physical-motion acceptance，仍须关闭 P0-A～P0-F 的相关
拒绝矩阵和 N1～N6 的生产门，使 Release/Trace/Certify identity 贯穿 artifact index，并重新确认真实
operator、独立急停、安全区、磁盘余量、6 个 velocity 发布者与 2 个 direct-motor 发布者的隔离以及
target-owned stop acknowledgement。N8 保持 `BLOCKED`，直至 N7 physical-motion 关闭。
