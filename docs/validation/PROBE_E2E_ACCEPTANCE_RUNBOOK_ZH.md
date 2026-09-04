<!-- status: active; authority: guide; owner: rolo maintainers; last_reviewed: 2026-09-04 -->

# Probe 端到端验收手册

本手册验收的是 Probe 的只读闭环：目标身份 → evidence bundle → MHS ID/Manifest 引用 →
RKB snapshot/read model → Agent 关联候选 → rolo-vis 展示。Probe 不填充厂商权威 MHS，
也不执行 reset、calibrate、setpoint、power 或运动。

## 1. 验收通过条件

一次 Probe 只有同时满足以下条件才通过：

- 目标 profile、host fingerprint、collector 和 evidence digest 可追溯；
- MHS 只输出发现到的 ID/Manifest 引用、来源、route、digest 和状态；
- vendor Manifest 缺失时为 `UNAVAILABLE`/`UNKNOWN`，没有 Rolo 猜测字段；
- LanderPi 人工整理的 Manifest 明确为 `PROVISIONAL / TEST_FIXTURE / READ_ONLY`，不覆盖 observed evidence；
- RKB 查询结果均带 `evidence_ids`、`observed_at`、`fresh_until`、`limitations` 和 `status_reason`；
- 关联结果只能是 `PROPOSED`、`UNKNOWN` 或 `UNSUPPORTED`，不能授予 Tool/write 权限；
- 全流程设备写调用计数为 0，失败和证据不足均 fail-closed。

## 2. CLI 端到端验收（当前基线的权威路径）

以下命令在已 enrollment 的目标上执行；`mentorpi` 仅是示例 robot ID。

```powershell
uv sync --locked --dev
uv run rolo target profile show --profile mentorpi
uv run rolo target inspect-profile --profile mentorpi
uv run rolo probe --profile mentorpi --active-probe runtime-readonly --evidence-timeout 60
uv run rolo target tool-surface --profile mentorpi > probe-tool-surface.json
uv run robotctl probe status --robot mentorpi
```

重点检查：

1. `probe` 返回 `status=READY`，并给出 `evidence_ref`、`evidence_sha256` 和只读限制；
2. `probe-tool-surface.json` 中只有固定、目标绑定的只读 Tool；
3. `robotctl probe status` 不得把缺失、过期或冲突证据标成 READY；
4. 任意缺命令、缺 Manifest、digest 漂移、fingerprint 不匹配或超时都应显式失败。

## 3. 应归档的直观文档产物

每个验收批次建立一个目录，例如 `validation/probe/<robot>/<run-id>/`，至少归档：

| 产物 | 内容 | 判定用途 |
|---|---|---|
| `01-profile.json` | profile、target URI、host-key fingerprint | 证明采集目标没有漂移 |
| `02-probe-result.json` | `ProbeStartResult`、evidence ref/digest、限制 | 证明 Probe 入口结果 |
| `03-target-evidence.json` | 签名、collector、各 provider probe、时间窗 | 事实和证据源 |
| `04-mhs-discovery.json` | MHS ID/Manifest 引用、来源、route、状态、digest | 证明“发现”而非“填充” |
| `05-rkb-snapshot.json` | snapshot identity、facts、digest、freshness | 证明 RKB 投影没有丢失 provenance |
| `06-tool-surface.json` | Tool descriptor、allowlist、session、surface digest | 证明 Agent 只能看到只读能力 |
| `07-conformance.json` | Tool conformance PASS/FAIL 及拒绝原因 | 证明可调用边界 |
| `08-negative-tests.json` | 缺失、过期、冲突、I²C/SPI/GPIO 禁止访问等 | 证明 fail-closed |
| `09-no-write-audit.jsonl` | 写调用计数、命令审计、设备侧日志摘要 | 证明 Probe 零写 |
| `10-human-review.md` | 证据摘要、限制、未解决问题、用户签字/确认 | 人工验收收据 |

当前实现中的常见运行时位置：

- profile/deployment：`.rolo/config/target-profiles/`、`.rolo/config/target-evidence/`；
- evidence artifact：Rolo 配置的 artifact root 下 `target-evidence/<robot>/`；
- RKB：`<rkb-root>/latest.json` 和 `snapshots/<digest>.json`；
- Tool conformance：`native/<robot>/sessions/<session>/conformance.json`。

## 4. LanderPi 验收顺序

LanderPi 只用于真实只读 canary 和 provisional fixture 验证：

```text
profile/host-key
  → inspect-profile
  → fresh Probe/evidence bundle
  → MHS ID/Manifest reference discovery
  → read-only MHS inspect/status/read
  → RKB snapshot + typed queries
  → Agent association proposal
  → human review
```

验收时必须把三类来源并排展示：`VENDOR_MANIFEST`、`OBSERVED_RUNTIME`、
`PROVISIONAL_TEST_FIXTURE`。fixture 只能验证 schema、route、replay、关联和只读 canary，
不能使设备进入 `VERIFIED` 或 `ELIGIBLE`。

## 5. rolo-vis Web GUI 验收

### 5.1 当前基线的判断

当前 Probe-first MVP 的工程状态以 CLI 和 artifact 为准，Web UI 不属于 Probe 完成的必要
条件。若 `/workbench/` 未挂载，不能据此判定 Probe 失败。

### 5.2 挂载 rolo-vis-v2 后的只读页面

在具备已校验 `rolo-plugin/v2` 包的版本上启动单一 robot-local listener：

```powershell
uv run rolo runtime serve `
  --host 127.0.0.1 `
  --port 8765 `
  --workbench-dir <validated-rolo-vis-package> `
  --rkb-root <rkb-root> `
  --artifact-root <artifact-root>
```

浏览器打开：`http://127.0.0.1:8765/workbench/`

GUI 至少应提供以下四个只读视图：

1. **目标与新鲜度**：robot ID、host fingerprint、snapshot digest、observed/fresh-until；
2. **MHS 发现卡片**：MHS ID、Manifest 引用、来源类型、digest、route、`AVAILABLE/UNAVAILABLE/PROVISIONAL`；
3. **证据图**：target → evidence → resource/route → MHS reference → association proposal；
4. **限制与审阅**：UNKNOWN、STALE、UNAVAILABLE、PROVISIONAL、冲突证据和待用户确认项。

页面上不应出现设备写按钮、Shell 输入框、凭据、原始 bundle 内容或“已验证物理安全”等文案。

### 5.3 GUI 对应的 API smoke

打开页面后，用浏览器开发者工具或 `curl` 验证同源只读接口：

```text
GET /health
GET /v1/features
GET /v1/robots
GET /v1/robots/<robot-id>/rkb
GET /v1/robots/<robot-id>/mhs
GET /v1/robots/<robot-id>/tools
```

`/workbench/` 与 `/rolo-api/*` 必须同源；GUI 或插件失败不能影响根 API 和 CLI。若 MHS
registry 缺失、snapshot 过期或 provider digest 漂移，页面应保留限制并隐藏 value，不能
渲染成成功状态。

## 6. 自动化验收门

人工确认交互和 receipt 语义见
[Probe 人工验收确认交互](PROBE_HUMAN_REVIEW_INTERACTION_ZH.md)。`10-human-review.md`
是可读导出；产品状态必须以结构化 review receipt 和 immutable ledger 为准。

```powershell
python scripts/check_docs.py
uv run pytest tests/test_probe_evidence_contract.py tests/test_probe_session_factory.py tests/test_probe_pipeline.py
uv run pytest tests/test_rkb_envelope.py tests/test_rkb_typed_queries.py tests/test_mhs_hardware.py
uv run ruff check src tests
```

真实目标还需附上目标 canary 的 stdout、artifact digest、执行时间和 no-write audit。没有
这些材料时，只能标记为离线或局部通过，不能标记 `Probe COMPLETE`。
