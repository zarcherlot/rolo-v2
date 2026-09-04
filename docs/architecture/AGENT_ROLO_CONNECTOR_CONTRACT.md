<!-- status: active; authority: normative; owner: rolo maintainers; last_reviewed: 2026-09-04 -->

# Agent → Rolo connector contract

The external Agent harness owns model calls, context compression and intent routing. Rolo owns
target identity, freshness, allowlists, parameter validation, execution and evidence. An Agent
must use one of the semantic connector actions below and must never connect to SSH or invoke a
raw shell/topic/argv.

| Intent | Connector action | Rolo authority |
|---|---|---|
| discover | `discover_target(target_id)` | fresh target catalog and context digest |
| read | `read_rkb(query)` | typed value, evidence IDs, freshness and limitations |
| tool-invoke | `invoke_tool(tool_id, arguments, session_id)` | target/session/digest/allowlist/budget/parameter checks |
| trace/certify | `get_run(run_id)` | state, events, report and artifact references |

Every request and result carries `target_id`; tool calls also carry `session_id`. A stale,
unverified or `agent_callable=false` entry is context only and must be rejected by Rolo. `UNKNOWN`
and `BLOCKED` are valid outcomes and must be preserved by the harness. Certify is only called when
the user explicitly requests a test or regression run.

The CLI and loopback API are equivalent execution surfaces. Their JSON payloads use the schemas in
`schemas/AgentDiscoveryEnvelope.schema.json`, `schemas/AgentToolInvocation.schema.json`,
`schemas/AgentRunEvent.schema.json` and `schemas/CertifyRequest.schema.json`; artifacts are
referenced by digest and are the only replay authority.
