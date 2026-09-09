<!-- status: active; authority: normative; owner: rolo maintainers; last_reviewed: 2026-09-09 -->

# Rolo DSL 交接兼容矩阵

该矩阵记录互补组件消费的冻结 Compiler 契约。适配层只能转换输入，不能重新定义语义、状态或 digest。

| 资产 | 版本 | 生产者 | 消费者 | 校验 |
|---|---|---|---|---|
| DSL | `rolo-dsl/v1` | Coding Agent | Compiler、targetd | schema + canonical digest |
| Compile Context | `rolo-compile-context/v1` | Probe Context adapter | Compiler、targetd | target fingerprint、freshness、digest |
| Canonical IR | `rolo-canonical-ir/v1` | Compiler | targetd、release publisher | IR digest |
| Bundle Plan | `rolo-bundle-plan/v2` | Compiler | targetd runtime | DSL/Context/IR、target、backend、capability 与 artifact manifest digest；v1 必须重编 |
| Compile Request | `rolo-dsl-compile-request/v2` | controller、CLI | Compiler | journey + active Mapping receipt + DSL/Context/target digest；v1 拒绝 |
| Compile Result | `rolo-dsl-compile-result/v2` | Compiler | Agent、targetd、CI | status + diagnostics + Mapping receipt lineage |
| Mapping Request | `rolo-adapter-mapping-request/v1` | Rolo controller | Coding Agent | journey + Context/Catalog digest |
| Mapping Proposal | `rolo-mapping-proposal/v2` | Mapping loop | confirmation authority | Candidate/DSL/Context/evidence/target/Catalog/scope canonical digest；仅 `PROPOSED` |
| Mapping Confirmation Receipt | `rolo-mapping-confirmation-receipt/v1` | confirmation authority | Compiler、targetd、registry、Release、Trace/Certify | fixture API 的 hash-chain ledger；actor/decision/time/expiry 与完整 Mapping identity；不得当作生产身份 |
| Operator Assertion / ACL Decision / Ledger Head | `rolo-operator-assertion/v1`, `rolo-acl-decision/v1`, `rolo-ledger-head/v1` | 外部 IdP、ACL verifier、单调 anchor | production Mapping authority | 签名 verification receipt、purpose/issuer/key/algorithm/trust-root 分权、challenge/expiry/CAS；仓库仅提供 SPI，真实 adapter 未部署 |
| Mapping Authority Command / Receipt / Pending | `rolo-mapping-authority-command/v1`, `rolo-mapping-authority-receipt/v1`, `rolo-mapping-authority-pending/v1` | production Mapping authority | Compiler、targetd、Release consumers、reconcile | operator + ACL + Mapping identity、双 ledger、外部 head、pending reconciliation；生产 composition 尚未接线 |
| Probe Follow-up | `rolo-probe-follow-up-request/v1` | Mapping loop | Probe controller | bounded item list + Context digest |
| targetd Compile | `rolo-targetd-dsl-compile/v2` | controller | targetd | `schema_version` 必填；journey + active Mapping receipt + compile identity；v1/缺失拒绝 |
| Target Conformance | `rolo-target-conformance/v3` | targetd | Release Publisher | `schema_version` 必填；T1～T4 独立 proof + tool/kind/target/evidence/DSL/Context/IR/Bundle/artifact/compiler/backend/journey/receipt/idempotency exact match；v1/v2/缺失拒绝 |
| Execution Bundle | `rolo-execution-bundle/v1` | Release/CALL bridge | targetd cache、provider | source signature/digest + binding/tool/release/limits；与 verified Release 的 generated Bundle identity 显式 bridge |
| Verified Release Provision | `rolo-targetd-verified-release-provision/v1` | controller selector | targetd | targetd 从 compile/conformance cache 重建 Release，重验 active Mapping、Execution Bundle/provider，并以 Catalog head CAS 提升 current |
| Authority Activation | `rolo-targetd-authority-activation/v1` | controller selector | targetd | 只提交 tool/release/bundle/current selector；targetd 重载 Catalog/Bundle 并生成单调 fence epoch |
| Execution Authority | `rolo-targetd-execution-authority/v1` | targetd | ExecutionRequest、provider fence | Mapping/Release/Context/Catalog/Bundle/binding/surface/provider/mode/fence exact identity + authority head digest |
| Execution Request | `rolo-execution-request/v2` | Trace/Certify adapter | targetd | session/run/key + complete authority exact match + deadline；v1 不得由 daemon 隐式迁移；仅非 physical 路径 |
| Physical Execution Request | `rolo-execution-request/v3` | 未来受监督运动 controller | targetd | 绑定 motion-safety evidence；当前 service 对全部 physical v1/v2/v3 无条件在 provider 前拒绝，v3 schema 存在不代表可执行 |
| Motion Safety Admission | `rolo-targetd-motion-safety-admission/v1` | 独立安全证据收集器 | 离线 evaluator、未来 targetd gate | operator/presence/safe-zone/E-stop/实时 ROS graph/direct-motor fence/stop ack exact binding；`ADMITTED` 仅表示静态证据内部一致，不是运动授权 |
| Mapping Cancel | `rolo-targetd-mapping-cancel/v1` | controller selector | targetd | current authority/confirmation head exact match，targetd 自行生成 CANCELLED tombstone；后续新 key provider 前拒绝 |
| Call Receipt | `rolo-targetd-call-receipt/v2` | targetd | Trace/Certify、reconcile | canonical request、Release/Context、authority/fence、provider fence、status/time/evidence/artifact refs；按 `(session_id, idempotency_key)` 隔离 |
| Release Binding | `rolo-release-binding/v1` | release-bound consumers | Trace、Certify、replay | current release + target/context/evidence digest |
| Certify Targetd Receipt Sidecar | `rolo-certify-targetd-call-receipt-sidecar/v1` | targetd-backed Certify adapter | Certify report/index、reconcile | 每例绑定 suite/case/request/idempotency key、完整 v2 CallReceipt 及 canonical digest；不可覆盖 |
| Certification Suite / Report | `rolo-mvp-certification-suite/v1`, `rolo-mvp-certification-report/v1` | Certify runner | operator、CI、rolo-vis | 恰好 10 例、单 tool、同一 Release/Context/target；fixed-target R0 已正式接线，其他 provider/risk 仍未闭合 |
| Journey Result | `rolo-post-compiler-journey-result/v2` | post-compiler journey | CI、rolo-vis、operator | phase status + Proposal/receipt lineage + artifact index；v1 不具备准入身份 |
| Release Catalog Transaction | `rolo-release-catalog-transaction/v1` | transactional Release Catalog | Release consumers、审计/recovery | append-only transaction log、signature-required mode、日志推导/校验 snapshot、跨进程 CAS、no-replace publish、forward rollback；compatibility ReleasePublisher 仍 unsigned，真实 target signer/跨主机 head 未部署 |
| Target Release Signature / Verification | `rolo-target-release-signature/v1`, `rolo-target-signature-verification/v1` | target signer、外部 verifier | Release publisher/Catalog | typed verification receipt；caller payload 不能充当 verifier，仓库不内置生产 trust provider |
| Release Upload Chunk / Status / Commit | `rolo-release-chunk-upload/v1`, `rolo-release-upload-status/v1`, `rolo-release-upload-commit/v1` | Release uploader | target artifact store | 32 MiB 上限、1 MiB×64 内容寻址分片、断点恢复、digest/size/atomic commit；尚未接 generic targetd transport |
| Release Read Model | `rolo-release-read-model/v1` | Release Publisher API | rolo-vis、Agent | current digest + status + callable flag |
| Diagnostics | catalog referenced by Compiler | Compiler | Agent、Trace、Certify | stable code and path |
| Trace Odom/EKF Diagnosis | `rolo-trace-diagnostic-plan/v1`, `rolo-landerpi-odom-trace/v1`, `rolo-odom-ekf-observation/v1`, `rolo-odom-ekf-diagnosis/v1` | Trace Agent | field operator、Certify | OS user、graph/receipt consistency、autonomous command source、odom/IMU semantics、yaw offset/rate consistency、calibration/initial heading、reset survival、bringup environment |
| Backend SPI | `rolo-backend-spi/v2` | backend registry | Compiler、targetd | `compile_v2` + BundlePlan v2 identity 已落地；registry 级严格版本协商仍待完成，v1 Bundle 必须重编 |

## 交接规则

- targetd Compile 与 Target Conformance 的 schema 版本缺失或不匹配时返回 `BLOCKED`，不得静默降级；其余公共契约仍需逐项完成同等级 missing-version 审计。
- `check`、Candidate、Proposal 和有界修复可发生在确认前；公共 compiler 已要求从 ledger 解析仍有效的 `CONFIRMED` receipt，并逐字段重验当前输入，不能接受调用方自带 receipt JSON。固定 R0 targetd execute 已接入 Catalog current、authority current 与原子 provider 围栏；register、host 通用 Release/Catalog 和其他 provider 尚未全部达到同级可信 resolver/transaction。
- 对话中的同意、Proposal 的本地状态修改或手写 `REGISTERED` 文件都不构成确认；取消、过期、跨 journey、跨 target、DSL/Context/evidence/scope 漂移必须在写 artifact 或调用 provider 前拒绝。
- Compiler 后端只写同盘 staging；BundlePlan 和全部 artifact 独立复验后，在 admission ledger 同一锁内原子提升，因此取消先于提交时不会留下调用方可见 Bundle。固定 R0 targetd 又用 Mapping、Catalog、authority 和 receipt state 的嵌套锁围栏 provider；该保证尚未泛化到 registry、host Catalog、generic partial upload、非 R0 provider 或 active-call stop。
- 任一 digest 不匹配时拒绝编译或发布，并保留失败 artifact。
- `ProbeContext` 只包含 Probe 实际观察到的 routes、schemas 和 MHS 引用。
- Context、route、MHS、target fingerprint 或 Compiler version 变化时，旧 Release 标记为 `STALE`。
- Trace/Certify 必须读取 `PUBLISHED` 且仍为 Catalog current 的 Release Binding；漂移统一返回 `BLOCKED`。
- Journey artifact index 必须覆盖 DSL、Context、Mapping Proposal、已提交 receipt、Compiler conformance、Bundle、targetd conformance、Release 和消费结果。
- 适配器不得写入机器人业务工作区、执行自由 shell 或访问未声明网络地址。
- worker lease/heartbeat/interrupt/ack 另有显式 opt-in 的 exact `/odom` R0 spawn-process seam，使用有界 JSON duplex IPC 和 WORK_STARTED 顺序门；它未接 TargetdService/default daemon，缺 target-owned START/live fence CAS、production adapter、OS sandbox 与 durable result commit。所有 physical request 继续 fail-closed，不能把该实验 lease/ack 当作实体停止证据。

当前离线 `offline_replay` 已贯通 Compile→targetd T1～T4→Release→Trace/Certify；LIVE session
`n7-r0-20260908T161029Z-7cda2170` 又通过 `DSL_REQUEST` 与 generic CALL 在同一 pinned SSH stdio
channel 上完成固定 `/odom` `OBSERVE/read/R0`：T3 独立 proof 1 次、Trace 1 次，以及正式
`ReleaseBoundCertify` 10/10。十个唯一 key 对应十份不可覆盖 v2 receipt sidecar；targetd CALL 单调
计数为 11，Mapping cancel 后新 key 被 provider 前拒绝且计数仍为 11，同通道 tmpfs cleanup residual
为 0/no fallback。证据见 [正式 N6 R0 目录](../validation/landerpi_n6_formal_r0_20260909/)；早期
[direct CALL canary](../validation/LANDERPI_N3_N6_N7_R0_CANARY_20260908.json) 仅保留为历史证据。

该 E3 只属于 scoped target-call 与 fixed-target R0 Certify：确认仍为 `FIXTURE` 且
`authority_partial=true`。P0 仍包括生产 Admission Authority 的真实 composition（IdP/JWKS/KMS、ACL、
外部单调 head、可信 Context/Candidate/Proposal/Catalog head、唯一 derived scope）、通用
Release/Catalog targetd wiring、DSL PUT 的 durable resume、process seam 的 service/daemon/authenticated
duplex 接线，以及实体运动临界点的 live graph/fence CAS、target-owned stop acknowledgement 和独立停止证据。
