<!-- status: active; authority: normative; owner: rolo maintainers; last_reviewed: 2026-09-06 -->

# Rolo v2 发布与兼容窗口策略

本文定义 Compiler standalone 和互补层的发布边界。版本策略只约束可验证的 schema、
digest 和 provider 能力，不承诺目标机未观测到的行为兼容。

## 1. 兼容单元

一次可消费发布由以下 digest 绑定：

```text
DSL → Compile Context → Canonical IR → Bundle Plan → target Bundle → Tool Release
```

Release 只有在 Compiler C1～C4、targetd T1～T4、target fingerprint 和 evidence digest
全部一致时才可标记 `PUBLISHED`。Trace/Certify 只能消费同一 target 上当前且未过期的
Release。

| 资产 | 当前版本 | 兼容规则 |
|---|---|---|
| DSL | `rolo-dsl/v1` | major 不同直接 `BLOCKED`；同一 major 的新增可选字段必须由 strict consumer 明确支持 |
| Compile Context | `rolo-compile-context/v1` | target identity、fingerprint、runtime revision 和 observed time 必须可验证 |
| Bundle Plan | `rolo-bundle-plan/v1` | 只能由匹配 Compiler version 和 DSL/Context digest 的 targetd 接收 |
| targetd protocol | `rolo-targetd/v1` | frame、backend capability 或 implementation contract 不兼容时拒绝编译 |
| Tool Release | immutable digest | 不跨 target fingerprint 复用；旧版本可保留并回滚 |

## 2. 升级窗口

升级按以下顺序执行：

1. 在独立目录安装新 targetd，并写入 `rolo-targetd-install-manifest/v1`；
2. 执行只读 health、协议 capability 和 ROS/Middleware runtime snapshot；
3. 对受影响 namespace 标记 `DIRTY`，重新执行 bounded Probe、Mapping 和 T1～T4；
4. 新 Release 通过全部门禁后原子切换 catalog current；
5. 保留旧目录、旧 Release 和旧 artifact index，直到窗口结束。

软件升级不会自动重探无关能力，也不会把旧 Release 静默升级为新行为。若 runtime、route、
MHS、schema、compiler version 或 target fingerprint 变化，受影响 Release 进入 `STALE`。

## 3. 回滚窗口

回滚只能指向同一 target fingerprint 下已验证的 immutable Release。回滚动作必须留下
新的 catalog/index 记录，且不能删除当前故障的诊断 artifact。若旧 Release 的 evidence
已过期或 target fingerprint 已变化，状态保持 `STALE`，需重新 Conformance 后才能发布。

## 4. 现场验收

现场 runbook 位于 `docs/validation/TARGETD_FIELD_RELEASE_RUNBOOK_ZH.md`。版本发布前至少
要有离线 replay、fake target 和真实目标 canary 三类证据；真实底盘行为仍需安全人员在场，
并且必须有实时反馈（例如 `/odom`）才能进入运动测试。无反馈时只能记录 `BLOCKED`，不得
通过定时速度或修改 fixture 宣称兼容。
