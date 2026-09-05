<!-- status: draft; authority: plan; owner: rolo maintainers; last_reviewed: 2026-09-05; scope: standalone compiler -->

# Rolo DSL Compiler 技术方案与开发计划

## 1. 目标和独立边界

本文只定义 Rolo DSL Compiler 本身。Compiler 可以在没有 Coding Agent、Probe 采集器、SSH、
rolo-targetd、真实 ROS/Middleware、Tool Catalog、Trace 或 Certify 的情况下独立开发、
测试、构建和发布。

Compiler 的输入是已生成的 Rolo DSL、统一 Compile Context 和本地 backend registry；输出
是 canonical DSL、Canonical IR、Bundle Plan 和结构化 diagnostics。它不执行 DSL，不连接
目标机，也不负责把结果发布到 Tool Catalog。

```text
mapping.dsl + compile-context.json + backend registry
  → parse / canonicalize / resolve / typecheck
  → Canonical IR
  → backend lowering
  → Bundle Plan
  → offline Conformance
  → Compile Result
```

后续系统通过适配层接入：

```text
Probe adapter       → Compile Context
Coding Agent        → mapping.dsl
targetd adapter     ← Bundle Plan / Compile Result
Release Publisher   ← Conformance artifact
Trace / Certify     ← Tool Release
```

## 2. 产品语义

Rolo DSL 是把目标机上已经存在的软件能力映射为归一化 Rolo Tool 的声明式语言，不是新的
应用开发语言。四种 Operation 都由 Coding Agent 生成 DSL；Compiler 不区分 DSL 是 Agent
还是人工产生的，只按同一套 schema 和语义编译。

```yaml
kind: OBSERVE | COMPOSE | INVOKE | EXECUTE
status: PROPOSED | CONFORMANT | PUBLISHED | STALE | BLOCKED
```

| kind | 编译语义 | Compiler 产物 |
|---|---|---|
| `OBSERVE` | 读取已存在的 topic、状态、参数、日志或 MHS resource | `ReadBinding` |
| `COMPOSE` | 对已发布 Tool 做有界串联、条件判断、聚合和诊断 | `WorkflowGraph` |
| `INVOKE` | 调用目标机已有 action、service、CLI 或 MHS operation | `ProtocolCall` |
| `EXECUTE` | 描述专用运行时的实现契约，不在 Compiler 内执行源码 | `RuntimeRef` |

`status` 是生命周期字段，不是 Compiler 的能力分类。Compiler 只产生 `CHECKED`、
`COMPILED`、`BLOCKED` 或 `FAILED` 结果；`PUBLISHED` 由后续 Release Publisher 负责。

## 3. 输入契约

### 3.1 Compile Context

Compiler 只接受统一的 `rolo-compile-context/v1`：

```yaml
schema_version: rolo-compile-context/v1
context_digest: 0123456789abcdef...
target:
  robot_id: landerpi
  target_fingerprint: 0123456789abcdef...
  runtime_revision: ros2-humble-demo
  observed_at: 2026-09-05T10:00:00Z
  freshness_ttl_s: 3600
resources:
  - resource_id: route:/navigation/state
    kind: ros_topic
    endpoint: /navigation/state
    message_type: nav_msgs/msg/Odometry
    schema_digest: 0123456789abcdef...
mhs_manifests:
  - manifest_id: vendor.navigation.v2
    manifest_digest: 0123456789abcdef...
    operations: [navigation.status, navigation.reset]
published_tools: []
```

Context 必须能表达资源存在、资源缺失、schema 漂移、target 不匹配、MHS operation 缺失、
Tool 未发布和 freshness 过期。Compiler 只能引用 Context 中存在的事实。

### 3.2 Rolo DSL

```yaml
schema_version: rolo-dsl/v1
tool_id: app.navigation.status
kind: OBSERVE
target:
  robot_id: landerpi
  context_digest: 0123456789abcdef...
binding: {}
input_schema: {}
output_schema: {}
mapping: {}
composition: {}
preconditions: []
error_mapping: {}
implementation: {}
evidence_refs: []
```

所有 `resource_id`、MHS operation、Tool ID 和 schema 都必须是显式引用。DSL 禁止任意
Python、shell、动态 import、未声明网络访问、未绑定目标地址和新的设备语义。

### 3.3 Compile Request/Result

```json
{
  "schema_version": "rolo-dsl-compile-request/v1",
  "request_id": "compile-001",
  "dsl_digest": "0123456789abcdef...",
  "context_digest": "0123456789abcdef...",
  "target_fingerprint": "0123456789abcdef...",
  "compiler_version": "0.1.0",
  "backend_id": "fake_runtime"
}
```

```json
{
  "schema_version": "rolo-dsl-compile-result/v1",
  "status": "COMPILED",
  "dsl_digest": "0123456789abcdef...",
  "context_digest": "0123456789abcdef...",
  "ir_digest": "0123456789abcdef...",
  "bundle_plan_digest": "0123456789abcdef...",
  "compiler_version": "0.1.0",
  "backend_id": "fake_runtime",
  "diagnostics": [],
  "artifacts": {
    "canonical_dsl": "canonical.dsl.json",
    "canonical_ir": "canonical-ir.json",
    "bundle_plan": "generated-bundle-plan.json"
  }
}
```

## 4. 编译器架构

```text
DSL bytes
  → Parser
  → Canonicalizer
  → Schema Validator
  → Context Resolver
  → Type Checker
  → IR Lowerer
  → Backend Registry
  → Bundle Plan Generator
  → Offline Conformance
  → Compile Result
```

### 4.1 Parser 和 Canonicalizer

Parser 使用 YAML/JSON 输入，拒绝未知字段、重复键、非法 UTF-8、非法版本和超大文档。
Canonicalizer 统一字段顺序、默认值、引用格式、schema 和表达式格式，并计算不包含自身
digest 的 canonical payload。

相同语义的 YAML 和 JSON、不同字段顺序和不同空白必须生成相同 `dsl_digest`。时间、随机
数、机器路径和环境变量不能隐式参与 digest。

### 4.2 Context Resolver

Resolver 将 DSL 引用解析到 Compile Context：

```text
resource_id       → ResourceDescriptor
mhs_manifest_id   → MhsManifestDescriptor
operation_id      → PublishedToolDescriptor / MHS operation
evidence_ref      → EvidenceDescriptor
```

Resolver 必须验证 robot、target fingerprint、context digest、schema digest 和 freshness。
任何无法解析的引用都生成稳定 diagnostics，不进入 IR。

### 4.3 Type Checker

Type Checker 至少支持 scalar、object、array、enum、nullable、bounded numeric、message
field path、条件表达式和 Compose 步骤连接。它只根据 Context 和 backend capability
进行静态判断，不执行目标调用。

### 4.4 Canonical IR

IR 是所有 backend 的唯一输入：

```text
ToolIdentity
TargetBinding
EvidenceRefs
OperationKind
InputSchema
OutputSchema
BindingGraph
Preconditions
ErrorMapping
RuntimeRequirements
CompositionLimits
SourceBundleRef (EXECUTE only)
```

IR 必须可 JSON 序列化、可比较、可重放。相同 DSL、Context、Compiler version 和 backend
capability 必须生成相同 `ir_digest`。

### 4.5 Backend SPI

```python
class RoloDslBackend(Protocol):
    backend_id: str
    supported_kinds: tuple[str, ...]

    def capabilities(self) -> BackendCapabilities: ...
    def resolve(self, ir: CanonicalIR, runtime: RuntimeFixture) -> ResolvedBinding: ...
    def lower(self, binding: ResolvedBinding) -> BundlePlan: ...
    def check(self, plan: BundlePlan) -> BackendConformance: ...
```

独立 Compiler 首先实现 `fake_runtime` backend，用 JSON fixture 模拟资源读取、协议调用、
Tool 组合、错误和超时。ROS、MHS、CLI 和 generated runtime backend 在后续集成计划中
实现，但必须遵循冻结的 Backend SPI 和 IR。

## 5. Bundle Plan

独立 Compiler 输出 `rolo-bundle-plan/v1`，供后续 targetd adapter 消费：

```json
{
  "schema_version": "rolo-bundle-plan/v1",
  "tool_id": "app.navigation.status",
  "kind": "OBSERVE",
  "target_fingerprint": "0123456789abcdef...",
  "dsl_digest": "0123456789abcdef...",
  "ir_digest": "0123456789abcdef...",
  "backend_id": "fake_runtime",
  "entrypoint_contract": "rolo.tool.invoke/v1",
  "bindings": [
    {
      "resource_id": "route:/navigation/state",
      "protocol": "ros_topic",
      "message_type": "nav_msgs/msg/Odometry"
    }
  ],
  "runtime_requirements": ["ros2"],
  "source_bundle_ref": null
}
```

Bundle Plan 不包含自由 shell、任意 Python、未声明网络访问或未绑定的目标地址。

## 6. Diagnostics

每条 diagnostic 固定包含 `code`、`severity`、`path`、`message` 和 `details`，并按
path/code 稳定排序：

```json
{
  "code": "RESOURCE_NOT_OBSERVED",
  "severity": "ERROR",
  "path": "binding.resource_id",
  "message": "route:/navigation/reset is absent from compile context",
  "details": {"context_digest": "0123456789abcdef..."}
}
```

首批错误码：`DSL_SCHEMA_INVALID`、`DSL_UNKNOWN_FIELD`、`TARGET_MISMATCH`、
`CONTEXT_DIGEST_MISMATCH`、`RESOURCE_NOT_OBSERVED`、`MHS_MANIFEST_NOT_FOUND`、
`MHS_OPERATION_NOT_DECLARED`、`SCHEMA_DIGEST_MISMATCH`、`TYPE_MISMATCH`、
`COMPOSITION_CYCLE`、`COMPOSITION_LIMIT_EXCEEDED`、`TOOL_NOT_PUBLISHED`、
`BACKEND_UNSUPPORTED`、`RUNTIME_CONTRACT_INVALID` 和 `NON_DETERMINISTIC_INPUT`。

## 7. CLI、SDK 和模块结构

```bash
rolo dsl validate mapping.dsl --context compile-context.json
rolo dsl canonicalize mapping.dsl --output canonical.dsl.json
rolo dsl compile mapping.dsl --context compile-context.json --backend fake_runtime
rolo dsl replay compile-request.json
```

CLI 只输出 JSON envelope，人类日志写入 stderr；不包含 SSH、targetd、Agent、Release、
Trace 或 Certify 子命令。

```text
src/rolo/dsl/
  models.py             # DSL、Context、IR、Plan、Request/Result
  schema.py             # JSON Schema 和版本检查
  parser.py             # YAML/JSON parser
  canonical.py          # canonical bytes 和 digest
  resolver.py           # Context 引用解析
  typecheck.py          # schema/mapping/compose 类型检查
  ir.py                 # lowering model 和 digest
  diagnostics.py        # 错误码和稳定排序
  compiler.py           # frontend pipeline
  backends.py           # backend SPI 和 registry
  fake_backend.py       # fake runtime backend
  cli.py                # validate/canonicalize/compile/replay
```

可复用 `rolo.core.hashing`、`rolo.core.artifacts.ArtifactStore` 和现有
`rolo.stages.probe.application` 的 candidate fixture；不把 `rolo.targetd` 引入 Compiler
运行时依赖。

## 8. 独立开发工作流

| 工作流 | 内容 | 依赖 | 主要产物 |
|---|---|---|---|
| C0 | DSL、Context、IR、Plan、Result schema，错误码和 digest 规则 | 无 | schema、fixture、契约文档 |
| C1 | parser、canonicalizer、schema validator | C0 | frontend package、canonical fixture |
| C2 | resolver、target/MHS/resource/Tool 引用和 freshness | C0、C1 | resolver、负向 fixture |
| C3 | type checker、表达式检查、Compose DAG 检查 | C1、C2 | typecheck package、diagnostic matrix |
| C4 | IR lowering、Backend SPI、registry | C1～C3 | IR package、backend contract |
| C5 | fake runtime/backend、Bundle Plan generator | C4 | fake backend、replay fixture |
| C6 | C1～C4 offline Conformance、deterministic replay | C1～C5 | conformance report、negative matrix |
| C7 | CLI、Python API、artifact writer | C1～C6 | `rolo dsl` CLI、SDK |
| C8 | packaging、版本兼容、CI 和开发文档 | C0～C7 | wheel、release checklist |

C0、fixture 和基础 CI 可以并行；C2 依赖 C1；C3 依赖 C2；C4 依赖 C3；C5 依赖 C4；C6
依赖 C5；C7 在 C6 后冻结接口。整个 C0～C8 不需要真实目标机、SSH、Agent 或 targetd。

## 9. Conformance 和测试矩阵

Compiler standalone 只负责离线 C1～C4：

| 层级 | 检查内容 | 失败结果 |
|---|---|---|
| C1 DSL | schema、canonicalization、表达式和组合边界 | 不生成 IR |
| C2 Context | target、fingerprint、route、MHS、schema、freshness、digest | 不生成 IR |
| C3 Compile | backend、IR、runtime requirement、Bundle Plan | 不返回 COMPILED |
| C4 Replay | fake runtime 输入输出、错误映射和 deterministic replay | 不能交给下游 |

必须覆盖 YAML/JSON 等价输入、字段重排、伪造资源、digest 漂移、freshness 过期、Compose
环、未发布子 Tool、backend 缺失、EXECUTE source 不执行、重复请求幂等和失败 artifact
不覆盖旧结果。

建议测试文件：

```text
tests/test_dsl_models.py
tests/test_dsl_schema.py
tests/test_dsl_parser.py
tests/test_dsl_canonical.py
tests/test_dsl_resolver.py
tests/test_dsl_typecheck.py
tests/test_dsl_ir.py
tests/test_dsl_backends.py
tests/test_dsl_bundle_plan.py
tests/test_dsl_diagnostics.py
tests/test_dsl_replay.py
tests/test_dsl_cli.py
```

## 10. 里程碑和完成定义

| 门 | 完成条件 |
|---|---|
| G0 Contract Freeze | DSL、Context、IR、Plan、Result schema、错误码和 digest 冻结 |
| G1 Frontend | 四类 DSL 可解析、canonicalize，并稳定计算 digest |
| G2 Resolution | resource/MHS/Tool 引用、target、schema 和 freshness 校验完整 |
| G3 Type/Graph | mapping 类型检查和 Compose 有界 DAG 校验通过 |
| G4 Fake Compile | 四类 Operation 均能生成可重放 Bundle Plan |
| G5 Offline Conformance | C1～C4 正负向矩阵全部通过，失败不返回 COMPILED |
| G6 CLI/SDK | CLI、Python API 和 artifact 字段一致 |
| G7 Standalone Release | wheel、schema、replay、ruff、pytest 和文档检查全部通过 |

Compiler standalone 完成后的硬条件：

- 不导入 Agent、SSH、targetd 或真实设备依赖；
- 相同 DSL、Context、Compiler version 和 backend fixture 生成相同 digest；
- 四类 Operation 都有成功、缺失引用、类型错误和 backend 不支持用例；
- 任一校验失败都返回 `BLOCKED` 或 `FAILED`；
- 编译不写业务工作区、不访问网络、不执行 DSL 中的任意代码；
- 所有 artifact 都带 DSL、Context、IR、backend 和 Compiler version 引用。

CI 命令：

```bash
python -m pytest -q tests/test_dsl_*.py
python -m ruff check src/rolo/dsl
python scripts/check_docs.py
python -m build
```

## 11. 对外交接契约

Compiler 完成后，后续工程只依赖以下版本化资产，不得修改其语义：

```text
rolo-dsl/v1
rolo-compile-context/v1
rolo-canonical-ir/v1
rolo-bundle-plan/v1
rolo-dsl-compile-request/v1
rolo-dsl-compile-result/v1
Backend SPI version
Diagnostic code catalog
```

targetd 接入时实现目标侧 runtime adapter；Agent 接入时只负责生成符合 schema 的 DSL；
Release Publisher 接入时消费 Bundle Plan 和 Conformance。Compiler 的 standalone release
通过后，即可启动[Rolo DSL Compiler 完成后的互补开发计划](ROLO_V2_DSL_POST_COMPILER_REMAINING_DEVELOPMENT_PLAN_ZH.md)。
