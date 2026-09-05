<!-- status: draft; authority: plan; owner: rolo-vis-v2 team; last_reviewed: 2026-09-04 -->

# rolo-vis-v2 开发交接计划

本文供 rolo-vis-v2 团队直接实施。目标是为 Rolo v2 的 Probe、Trace 和 Certify 提供只读观测面，
当前 MVP 场景为 LanderPi 底盘旋转。UI 展示状态、事件、证据和报告，不拥有写权限，也不绕过
Rolo API 调用目标机。

## 产品边界

调用方向固定为：

```text
用户 / Agent Harness → Rolo API → rolo-vis-v2 只读视图
```

rolo-vis-v2 不执行 Shell、SSH、ROS topic、任意 argv 或未注册 Tool。所有执行动作由 Rolo 的
Trace session、Tool registration、binding、参数边界、超时、停止/取消和审计机制决定。

当前产品口径：

- Probe 负责目标身份、证据、Tool Surface 和 Harness proposal。
- Trace 负责已注册 Tool 的任务执行、事件流、诊断和结果 artifact。
- Certify 负责固定测试套件、逐例 expected/actual、报告和 artifact digest。
- 当前真机 MVP 是旋转；10 条真机 Certify、真机恢复和非 ROS 实机 provider 暂延期。
- MHS 只是可选上下文来源，不是 UI 执行入口，也不定义 `app.base.rotate` 语义。
- 目标连接使用普通 SSH profile；UI 不显示、不管理 SSH key 或 Probe runner credential。

## 已有后端接口

Rolo loopback API 的基础目录接口：

```http
GET /v1/features
GET /v1/robots
GET /v1/robots/{robot_id}/tools
GET /v1/robots/{robot_id}/rkb
GET /v1/robots/{robot_id}/mhs
GET /v1/robots/{robot_id}/episodes
```

当前 MVP Trace 接口：

```http
POST /v1/mvp/trace/sessions
POST /v1/mvp/trace/sessions/{session_id}/execute?target_id={target_id}
GET  /v1/mvp/trace/sessions/{session_id}?target_id={target_id}
GET  /v1/mvp/trace/sessions/{session_id}/events?target_id={target_id}
POST /v1/mvp/trace/sessions/{session_id}/cancel?target_id={target_id}
POST /v1/mvp/trace/sessions/{session_id}/stop?target_id={target_id}
GET  /v1/mvp/runs/{run_id}?target_id={target_id}
```

Trace 创建请求必须携带 `target_id`、`catalog_digest`、`task`、`mode`、`ttl_s` 和 `max_calls`。
`SUPERVISED_FIELD_DEBUG` 还必须有 `safety_confirmed=true`。UI 只提交用户已经明确提供的值，
不得自行补全安全确认或扩大 TTL/预算。

## 页面与组件

### 1. Target overview

展示：

- `robot_id`、目标 fingerprint、Probe snapshot digest；
- catalog freshness：`fresh`、`stale`、`unknown`；
- 最近一次 Probe 时间和限制说明；
- Tool、RKB、MHS 数量及各自 evidence 状态。

交互：点击 Tool 或 evidence 进入详情；不提供执行按钮。

### 2. Tool catalog

每个 Tool 卡片展示：

- `tool_id`、family、access、risk、state；
- descriptor digest、evidence IDs、参数 schema；
- binding provider kind、command endpoint 的脱敏显示；
- 是否 `experimental_write`；
- limitations。

写 Tool 只能显示“需要 Trace supervised field debug”，不得在 Tool 卡片直接触发动作。

### 3. Probe proposal view

展示 Harness 生成的 proposal：

- target/tool/evidence identity；
- descriptor 输入契约和 observation 输出契约；
- codegen artifact ref、source digest、binding digest；
- proposal 当前状态：`PROPOSED`、`REGISTERED` 或 `BLOCKED`；
- Rolo 返回的拒绝原因和下一步。

UI 不重新编辑 proposal，也不创建未观测 route。需要修改时，由 Agent Harness 重新生成并提交。

### 4. Trace timeline

使用 `/events` 接口按 `sequence` 展示：

- `SESSION_CREATED`、`PLAN_ACCEPTED`；
- `TOOL_CALL` 和经过脱敏的 arguments；
- `TOOL_RESULT`、evidence IDs、错误码；
- `DIAGNOSING`、`RECOVERY_ATTEMPT`、`RECOVERY_FAILED`；
- `SESSION_COMPLETED`、`SESSION_CANCELLED`、`SESSION_STOPPED`、`BLOCKED`、`UNKNOWN`。

事件流必须保留原始 sequence，不按前端时间重新排序。敏感字段由后端脱敏后再显示。

### 5. Certify report

当前后端已有离线 `CertificationRunner` 和报告模型。UI 先实现报告读取和展示：

- suite digest、snapshot digest；
- 每个 case 的 expected、actual、status、failure class；
- operation IDs、evidence IDs、artifact digests；
- 总结论：`PASS`、`CONDITIONAL` 或 `BLOCKED`。

Certify 真机执行入口属于后续后端工作，UI 不得伪造“运行完成”。未找到报告时显示明确的
`CERTIFY_UNAVAILABLE`。

### 6. Artifact detail

展示 artifact index、文件名、sha256、生成时间和关联 run/session。支持复制 artifact ref 和
打开 JSON 内容；不支持前端修改、删除或覆盖 artifact。签名字段存在但无法验证时，状态显示
`SIGNATURE_UNVERIFIED`，不能显示为可信。

## 前端状态模型

前端只允许渲染后端返回的状态，不自行推导成功：

| 后端状态 | UI 颜色/标签 | 可用动作 |
|---|---|---|
| `READY` / `CALLABLE` | 可用 | 查看详情 |
| `PROPOSED` | 待注册 | 查看 proposal |
| `REGISTERED` | 已注册 | 查看 Tool/Trace |
| `STALE` / `UNKNOWN` | 数据不可用 | 查看限制、重新 Probe |
| `BLOCKED` | 已阻塞 | 查看错误和证据 |
| `COMPLETED` | 已完成 | 查看 timeline/artifact |
| `CANCELLED` / `STOPPED` | 已停止 | 查看停止事件 |

刷新和断线重连后必须重新读取后端状态。浏览器本地状态不能作为事实来源。

## 必须实现的交付项

1. Workbench plugin package，复用现有 `/workbench/` host 和 `/rolo-api/*` 同源适配。
2. Target overview、Tool catalog、Probe proposal、Trace timeline、Certify report、Artifact detail 六个只读视图。
3. API client 对所有响应执行 schema/version 校验；未知字段保留，未知状态降级为 `UNKNOWN`。
4. Trace timeline 支持轮询和手动刷新，按 session digest/target ID 隔离数据。
5. 所有网络错误、404、409、`*_BLOCKED` 和 `*_UNAVAILABLE` 都显示结构化 error code 与 limitation。
6. 前端测试覆盖 stale catalog、proposal blocked、Trace failure/recovery、cancel/stop 和空报告。
7. 截图验收：旋转 MVP 的 Probe → proposal → Trace timeline → artifact detail 完整链路。

## 明确不做

- 不实现 SSH、Probe runner、Rolo runtime 或 ROS 客户端。
- 不在浏览器执行 Harness source，不在浏览器拼接 transport payload。
- 不提供“确认后直接旋转”的 UI 按钮；执行仍由 Agent Harness 调用 Rolo。
- 不把 route presence、MHS manifest 或 UI 状态升级成 VERIFIED capability。
- 不实现延期的 10-case 真机 Certify、真机恢复和非 ROS 实机 provider。

## 验收标准

- 未注册 `app.base.rotate` 时，Tool catalog 显示 `BLOCKED` 或未注册状态，不出现执行控件。
- Trace session 创建后，timeline 能显示完整事件序列和 evidence IDs。
- Trace 被 cancel/stop 后，刷新页面仍显示最终状态和对应事件。
- catalog digest 或 target ID 不匹配时，UI 显示后端 `TRACE_BLOCKED`，不展示旧 session 的数据。
- artifact index 中任一 sha256 不匹配时，UI 显示校验失败，不显示“可信”。
- 所有页面在后端不可用时仍能显示结构化错误，不显示假数据或成功状态。

## 后端依赖与联调顺序

1. 先用 fixture catalog、Trace session、events 和 report 完成页面与组件测试。
2. 接入 `/v1/mvp` API，验证 target/session/digest 隔离。
3. 接入 Probe proposal 与 registered Tool artifact。
4. 使用旋转 MVP 的离线 Trace fixture 做端到端截图验收。
5. 等待后端正式 artifact 签名/回滚和 Certify 入口完成后，再接入对应状态展示。

rolo-vis-v2 的完成只代表观测链路可用，不代表旋转真机 release gate 自动通过。
