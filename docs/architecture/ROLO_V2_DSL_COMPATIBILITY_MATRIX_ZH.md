<!-- status: active; authority: normative; owner: rolo maintainers; last_reviewed: 2026-09-06 -->

# Rolo DSL 交接兼容矩阵

该矩阵记录互补组件消费的冻结 Compiler 契约。适配层只能转换输入，不能重新定义语义、状态或 digest。

| 资产 | 版本 | 生产者 | 消费者 | 校验 |
|---|---|---|---|---|
| DSL | `rolo-dsl/v1` | Coding Agent | Compiler、targetd | schema + canonical digest |
| Compile Context | `rolo-compile-context/v1` | Probe Context adapter | Compiler、targetd | target fingerprint、freshness、digest |
| Canonical IR | `rolo-canonical-ir/v1` | Compiler | targetd、release publisher | IR digest |
| Bundle Plan | `rolo-bundle-plan/v1` | Compiler | targetd runtime | plan digest + backend version |
| Compile Result | `rolo-dsl-compile-result/v1` | Compiler | Agent、targetd、CI | status + diagnostics |
| Mapping Request | `rolo-adapter-mapping-request/v1` | Rolo controller | Coding Agent | journey + Context/Catalog digest |
| Probe Follow-up | `rolo-probe-follow-up-request/v1` | Mapping loop | Probe controller | bounded item list + Context digest |
| Target Conformance | `rolo-target-conformance/v1` | targetd | Release Publisher | T1～T4 all `PASS` |
| Release Binding | `rolo-release-binding/v1` | release-bound consumers | Trace、Certify、replay | current release + target/context/evidence digest |
| Journey Result | `rolo-post-compiler-journey-result/v1` | post-compiler journey | CI、rolo-vis、operator | phase status + artifact index |
| Release Read Model | `rolo-release-read-model/v1` | Release Publisher API | rolo-vis、Agent | current digest + status + callable flag |
| Diagnostics | catalog referenced by Compiler | Compiler | Agent、Trace、Certify | stable code and path |
| Trace Odom/EKF Diagnosis | `rolo-trace-diagnostic-plan/v1`, `rolo-landerpi-odom-trace/v1`, `rolo-odom-ekf-observation/v1`, `rolo-odom-ekf-diagnosis/v1` | Trace Agent | field operator、Certify | OS user、graph/receipt consistency、autonomous command source、odom/IMU semantics、yaw offset/rate consistency、calibration/initial heading、reset survival、bringup environment |
| Backend SPI | repository backend version | backend registry | Compiler、targetd | capability negotiation |

## 交接规则

- 输入 schema 版本不匹配时返回 `BLOCKED`，不得静默降级。
- 任一 digest 不匹配时拒绝编译或发布，并保留失败 artifact。
- `ProbeContext` 只包含 Probe 实际观察到的 routes、schemas 和 MHS 引用。
- Context、route、MHS、target fingerprint 或 Compiler version 变化时，旧 Release 标记为 `STALE`。
- Trace/Certify 必须读取 `PUBLISHED` 且仍为 Catalog current 的 Release Binding；漂移统一返回 `BLOCKED`。
- Journey artifact index 必须覆盖 DSL、Context、Compiler conformance、Bundle、targetd conformance、Release 和消费结果。
- 适配器不得写入机器人业务工作区、执行自由 shell 或访问未声明网络地址。
