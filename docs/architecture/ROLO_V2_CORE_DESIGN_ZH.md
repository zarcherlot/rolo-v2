<!-- status: active; authority: normative; owner: rolo maintainers; last_reviewed: 2026-09-02 -->

# Rolo v2 核心设计：四类小而稳的标准

## 1. 产品目标

用户的目标不是维护一套机器人软件栈，而是在自己的机器人上完成 Rolo 初始化，得到一组
可信、可复用、可由 Agent 消费的工具。Rolo 负责标准、目标证据、工具发现、Conformance、
发布和撤销；Agent 负责理解目标、选择工具、设计只读 Probe、解释结果和提出能力缺口；
机器人只在目标环境执行受控请求。

Probe 是初始化阶段：

```text
用户指定机器人
  -> Rolo 建立身份、目标连接和最小工具面
  -> Agent 使用 Rolo 内置 inspect CLI 发现并规划
  -> 机器人执行受控 Probe 并返回 Evidence
  -> Rolo 独立验证并固化 Tool
```

Probe 之后，Trace/Certify 由 Agent 主导，但只能消费已发布的 Tool Session。若用户已经
知道准确的 CLI、Provider 或 Tool，可通过 Agent 提交显式注册请求；Rolo 仍必须重新采集
目标 Evidence 并完成 Conformance，不能因用户或 Agent 的声明直接注册。

## 2. 四类标准

### 2.1 Tool Standard：工具是什么

Tool 是 Agent 可以发现和调用的最小稳定能力。每个 Tool 必须声明：

- 稳定的 `tool_id`、版本和 owner；
- 输入 Schema、输出 Schema 和有界错误码；
- `read`/`write`、风险等级、敏感数据等级；
- 超时、输出上限、取消和速率限制；
- 执行路径（内置、native、provider 或 adapter）；
- route/provider/executable identity；
- 对应的 target evidence 引用和 digest；
- 是否允许进入长期 release、State Graph 和审计链。

不为每个 OS/Middleware 命令建立一个产品 Operation。常规只读观察优先使用 family-level
native Tool；只有需要稳定产品语义、跨平台统一、硬件/应用绑定、写授权或长期审计时，
才升级为 Canonical Tool。

### 2.2 Discovery & Evidence Standard：工具如何被发现和证明

Rolo 内置经过验证的 inspect CLI 和只读 Probe。Agent 可以选择这些工具、提出下一步
Probe，但不能提交任意 shell 或自造运行时事实。

所有 Probe 结果必须是结构化、目标绑定和可追溯的：

- `robot_id`、`target_fingerprint`、`source_id`；
- 一次性 request/nonce、采集时间和 freshness window；
- route 的 kind、resource ID、endpoint、接口类型/Schema、provider 和 revision；
- 原始结果的 artifact ref、SHA-256 和限制说明；
- 失败、截断和环境限制也必须被记录。

Middleware Tool 的执行环境必须来自同一份目标 Evidence：至少绑定目标的 runtime path、
依赖包、动态库路径以及 setup 文件 digest。Native runner/session 通过显式
`environment` 参数接收这份上下文，不依赖控制器自身的全局环境；环境缺失时返回结构化
失败或 `environment_limited`，不得用控制器环境补齐后宣称目标可用。

静态源码、文档、模拟和 Agent 自述只能形成候选或待验证缺口，不能单独证明目标工具
存在。目标证据可以来自本地 Probe runner 或固定的远程 Probe runner，但控制器不得把自身环境
冒充为目标环境。

### 2.3 Conformance Standard：工具何时可信

Conformance 分为两部分：

1. Agent 可报告本地静态检查，例如 Schema、错误、幂等和取消；这些只是审计输入。
2. Rolo 独立检查 Bundle、身份、digest、route、provider、Schema、sandbox、依赖、
   运行环境、Tool Catalog 和 State Graph。

只有 Rolo 的独立检查通过，Tool 才能进入可调用的发布面。Conformance 不通过时必须
fail-closed，不能以 Agent 自评、一次成功启动或文档声明替代。

### 2.4 Release Standard：工具如何被固化

Rolo 将通过 Conformance 的工具生成不可变 release，至少绑定：

```text
tool manifest
target evidence
provider/route identity
adapter/native files
Tool Catalog
State Graph
Conformance report
Gate report
```

所有文件通过 digest 绑定，`current` 指针原子更新。目标 route、executable、provider、
运行环境或关键硬件事实变化后，相关 release 自动变为 stale；失败发布不得覆盖旧 release。

## 3. Agent 触发和调用协议

Agent 不自行决定是否启动 Probe。Rolo 在初始化后创建带 TTL、allowlist、调用次数和结果
预算的 Tool Session，并发送 `ToolPlanningRequest`：

```text
goal + constraints
tool_surface_ref + sha256
target_evidence_ref + sha256
tool_session_id
allowed_tool_ids
expires_at
```

Agent 返回只包含 Tool ID 和 typed arguments 的 `ToolPlan`。Rolo 校验计划后执行并审计每一
次调用。发现 Tool 不足时，Agent 返回 `CAPABILITY_GAP`；只有此时才进入窄的 Adapter/Provider
扩展流程。

正式执行入口是 session 内的 `execute_plan`（Broker action=`plan`），而不是 Agent 直接调用
runner。Rolo 会再次校验 `target_id`、`session_id`、`surface_digest` 和 allowlist；任一步骤
失败即停止后续步骤并保留已完成调用的审计记录。

推荐的 Skill 边界是一个必需的 `rolo-tool-planning` 核心 Skill，加上按需的 provider/domain
Skill。Skill 负责规划和解释，不拥有执行、注册、Gate 或 release 权限。

## 4. 角色边界

| 角色 | 责任 |
|---|---|
| 用户 | 指定机器人和目标；提供/确认权限；批准写操作；可显式指出待注册 Tool；判断业务和物理结果 |
| Rolo | 定义四类标准；提供 inspect CLI/Probe；建立 Session；验证 Evidence；执行 Conformance；发布、撤销和审计 |
| Agent | 使用已提供 Tool；设计有限 Probe；规划调用；解释 Evidence；提出 gap 或显式注册请求 |

SSH connector 的 v2 安全约束属于 Tool Surface 的一部分：连接必须使用 pinned
`known_hosts`；enrollment 绑定 identity 后，必须使用该 identity 和
`IdentitiesOnly=yes`，禁止密码回退或无界 agent 凭据选择。target inspection、
episode capture 和 bootstrap planning 统一复用这条约束。

Credential Broker 只解析 typed reference，不向 Agent 或普通 artifact 暴露
密码、私钥正文或 keychain 内容。`ssh-agent:*` 在控制器支持的 OpenSSH 平台上统一
映射为 agent transport；`platform-keychain:*` / `secret-store:*` 由安装层解析
为已 pin 的 identity 文件，Rolo 核验文件存在性和权限后才交给 connector。
| 机器人 | 在目标环境执行受控 Probe/Tool；返回事实；执行最终授权调用；不决定是否可信或是否发布 |

## 5. v2 的范围收敛

Canonical Registry 不以 197 或 294 为目标数量。保留标准的依据是：

- 是否是跨目标复用的产品语义；
- 是否需要稳定 Schema、单位、坐标系、时间和状态语义；
- 是否涉及写授权、静止窗口、取消、补偿、急停或资源锁；
- 是否需要硬件/应用绑定、敏感数据保护、长期 State Graph 或 immutable release；
- 是否是 Codex/native Tool 无法可靠表达的跨平台或 vendor/provider 缺口。

OS/Middleware/hardware 的通用只读观察进入 Agent-native family Tool；机器人应用语义、动作、安全、
配置事务、Provider 适配和 Rolo 控制面继续保留为 Canonical。v1 Registry 及旧 release 只
作为兼容和审计基线，不应阻塞 v2 的小工具闭环。

## 6. 真机第一步

首轮真机只验证最小闭环，不验证完整机器人软件栈：

```text
enroll -> target evidence -> inspect Tool Session -> Agent ToolPlan
       -> 只读调用 -> evidence/audit -> Rolo Conformance -> release
```

首轮优先选择一个只读、低风险、目标明确的 Tool（例如主机状态、Middleware graph 或一个明确的
设备 inspect）。写操作、运动、安全和复杂 vendor adapter 在只读闭环稳定后再增加。
