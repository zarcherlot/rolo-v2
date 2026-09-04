<!-- status: active; authority: guide; owner: rolo maintainers; last_reviewed: 2026-09-04 -->

# Probe 人工验收确认交互

本文定义客户使用 Rolo 时如何确认一次 Probe 只读验收。确认是对证据批次的
**不可变收据**，不是设备授权，也不会触发 Trace、Tool 或任何设备调用。

## 1. 客户看到什么

Rolo 先运行 Probe 并打开验收摘要。摘要固定显示：

- robot ID、目标 URI、pinned host-key fingerprint；
- target host fingerprint、collector、observed/fresh-until；
- evidence/RKB snapshot digest；
- `VENDOR_MANIFEST`、`OBSERVED_RUNTIME`、`PROVISIONAL_TEST_FIXTURE` 三列来源；
- Tool surface、negative tests、no-write audit；
- 所有限制：`UNKNOWN`、`STALE`、`UNAVAILABLE`、`PROVISIONAL` 和缺失签名。

摘要中的所有 digest 都可点击展开到本地 artifact；不会展示私钥、verification secret
或原始凭据。

## 2. 确认前的确定性检查

Rolo 在展示按钮前重新计算批次 index digest，并检查：

1. profile、目标指纹、collector 和 evidence digest 一致；
2. evidence freshness 未过期；
3. MHS 仅为发现/引用，不含写能力；
4. association 只能是 `PROPOSED`、`UNKNOWN` 或 `UNSUPPORTED`；
5. 全部 HTTP/tool surface 为 GET/read-only，write count 为 0；
6. 失败、冲突、vendor manifest 缺失和 fixture 都保持 fail-closed。

任一检查失败时，只显示“查看问题”和“拒绝/暂缓”，不显示“通过”。

## 3. 客户操作

CLI 和 rolo-vis 使用同一流程：

```text
rolo probe acceptance review --batch <batch-dir>
  → 展示摘要和限制
  → 客户输入目标指纹末 8 位 + artifact digest 末 8 位
  → 选择 APPROVE_WITH_LIMITATIONS / APPROVE / REJECT / DEFER
  → 再次显示将写入的收据字段
  → 客户确认
```

输入短指纹和 digest 是防止客户在错误目标/错误批次上误确认的二次校验，不是密码，
也不产生设备权限。

建议决策语义：

| 决策 | 允许条件 | 结果 |
|---|---|---|
| `APPROVE` | 所有硬门通过，含可验证签名 evidence bundle | `READ_ONLY_COMPLETE` |
| `APPROVE_WITH_LIMITATIONS` | 只读链路通过，但存在明确、可接受的限制 | `PROVISIONAL`，不得升级写权限 |
| `DEFER` | 需要补充证据或等待维护窗口 | `PENDING_REVIEW` |
| `REJECT` | 指纹、digest、freshness 或边界不可信 | `REJECTED` |

当前 LanderPi 批次应使用 `APPROVE_WITH_LIMITATIONS`：真实只读链路通过，但 vendor
manifest、签名 bundle 和设备侧审计仍有明确限制。

## 4. 收据内容与副作用

确认只生成独立的 `probe-human-review-receipt/v1` artifact，至少包含：

```json
{
  "decision": "APPROVE_WITH_LIMITATIONS",
  "robot_id": "landerpi",
  "target_host_fingerprint": "<64 hex>",
  "batch_index_sha256": "<64 hex>",
  "snapshot_digest": "<64 hex>",
  "reviewer": "<authenticated user id>",
  "reviewed_at": "<UTC timestamp>",
  "limitations": ["..."],
  "access": "READ_ONLY",
  "write_requests": 0
}
```

收据必须追加写入 immutable review ledger；重复提交同一 decision 返回原收据，不能
覆盖原始 Probe evidence。`APPROVE` 也不会直接调用设备；任何后续 Trace/Write 流程
必须重新获取新鲜状态并执行独立授权。

## 5. 客户如何确认

客户确认的最小可审计动作是：登录身份、批次 index digest、目标指纹、决定、限制、
UTC 时间和客户端版本。人工复核 Markdown 只是可读导出；产品状态以结构化 receipt
和 ledger 为准。没有 receipt 时，即使有人在聊天或文件中写了“批准”，Rolo 也不得
提升为 `READ_ONLY_COMPLETE`。

