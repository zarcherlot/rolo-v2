<!-- status: active; authority: reference; owner: rolo maintainers; last_reviewed: 2026-09-02 -->

# RKB-0 契约决策

本文冻结 Rolo v2 Robot Knowledge Base 的最小公共契约。它是当前 v2 的执行依据，不保留旧
rolo 版本的 API、artifact 或 route 兼容承诺；历史材料仅供考古阅读。

## 1. 范围与所有权

RKB-0 只完成基线清点、契约冻结和依赖准备，不改变 Probe CLI 的输出语义，也不开放任何
写能力。唯一 canonical Probe 路径是 `src/rolo/stages/probe/`。RKB 的新 artifact 只能由
`src/rolo/rkb/` 生成，旧 bundle/report 不会被回写或自动升级成熟度。

## 2. 词汇与状态

事实层级严格区分：

| 层级 | 含义 | 可否作为 capability 证据 |
|---|---|---|
| `DECLARED` | manifest、静态配置或源码声明 | 只能产生 `DISCOVERED_UNVERIFIED` |
| `OBSERVED` | 目标机同一次采集得到的运行时观测 | 可作为 Gate 输入，不能单独授予资格 |
| `VERIFIED` | Rolo 对身份、digest、来源和时间校验通过 | 可供只读 query 使用 |
| `INFERRED` | 明确标注的启发式推断 | 不能绕过 Gate |
| `DECISION` | 人工或确定性策略的采用/拒绝决定 | 必须关联 evidence IDs |

统一失败关闭状态为 `UNKNOWN`、`UNAVAILABLE`、`STALE`；`ELIGIBLE`/`VERIFIED` 只允许在
明确 Gate 输入齐全时产生。Provider 注册成功、route 存在、源码声明或一次 read 成功都不
等同于 capability `VERIFIED`。

## 3. Identity、来源和访问边界

每个 envelope/fact 的 identity tuple 固定为：

```text
(robot_id, target_host_fingerprint, collector_id,
 deployment_mode, access, request_nonce)
```

`access` 当前唯一值为 `READ_ONLY`。`source_kind` 使用
`TARGET_PROBE`、`DECLARED_STATIC`、`OBSERVED_RUNTIME`、`VERIFIED_BUNDLE`；每条 fact 必须有
`source_ref`、`sha256`、`observed_at`、`fresh_until`、`confidence` 和 `limitations`。
控制器 hostname、PATH、Python 或本地设备列表不得自动归因给目标机。

## 4. Canonicalization、digest 和 freshness

- JSON 使用 UTF-8、递归排序 key、无多余空白、稳定分隔符 `(',', ':')`。
- envelope 的 digest payload 使用 `model_dump(mode="json", exclude_none=True)` 并排除 digest
  本身；事实 value 内显式的 JSON `null` 仍保留。
- digest 使用 SHA-256 小写十六进制；任何 identity、payload 或 fact digest 不一致均拒绝读取。
- 时间统一为带时区的 UTC ISO-8601。`fresh_until <= observed_at` 为非法。
- 初始 freshness policy：middleware graph 30 秒、进程/状态 30 秒、hardware topology 10 分钟、
  thermal 10 秒、executable identity 24 小时；任何 TTL 不得超过 Bundle 整体有效窗口。
  静态声明没有目标观测时间，不伪造 freshness。

## 5. Route 与 MHS

MHS canonical route 固定为 `mhs://<device_id>/<capability_id>`。`mhs://sensor/...` 不作为
新输入或输出格式。Rolo-owned Provider SPI 只提供 `inspect`、`status`、`read`；reset、
calibrate、setpoint、stop、power-cycle 和 firmware 更新不在 v2 范围内。

## 6. 依赖、验收和回滚

本地前置条件为 Python 3.10–3.13、uv、项目运行时依赖和 dev 依赖。CI 使用相同的 Python
矩阵和命令；缺少 `uv`、`pytest`、`ruff`、目标 ROS/驱动或真机授权时状态只能为 `BLOCKED`。
RKB-0 回滚只删除未采用的契约文档和测试入口，不修改既有 EvidenceBundle、DiscoveryReport
或 latest index。
