<!-- status: active; authority: normative; owner: rolo maintainers; last_reviewed: 2026-09-02 -->

# Rolo v2：Probe-first architecture

Rolo v2 is deliberately small. The product promise is a target-bound, read-only Tool Surface
that an Agent can consume from a Codex-like window. Trace and Certify are future contracts, not
implemented business stages in this release.

## Product chain

```text
user goal
  -> Agent asks Rolo for a profile-bound Tool Surface
  -> Rolo loads TargetProfile and auto-assembles SSH Connector
  -> Rolo verifies host key, pinned identity and TargetEvidenceBundle
  -> Rolo creates NativeToolSession (allowlist, TTL, budget, digest)
  -> Agent emits a typed ToolPlan
  -> Rolo validates and executes fixed read-only argv
  -> Rolo writes per-call evidence and independent Conformance records
```

The user does not choose a private-key path during normal use. A profile identifies the robot;
the credential broker selects an SSH agent or an enrolled identity file. Host-key approval,
identity digest, probe runner identity and evidence freshness are hard gates. Passwords are never
accepted by a tool invocation.

## Four small Tool standards

| family | stable purpose | examples |
|---|---|---|
| `hardware` | physical inventory and device presence | device inventory and presence snapshot |
| `OS` | host, process, service, resource and file observation | host/process/service/resource inspection |
| `Middleware` | graph, channel, topology and runtime observation | middleware graph/channel/topology snapshot |
| `application` | one named, narrow application gap | route-backed startup/navigation/mapping/manipulation bundle |

The current Native catalog is family-level, read-only and static-argv. It is intentionally not a
second 197-item Canonical Registry. Commands that Codex already understands remain native tools;
a new Adapter bundle is justified only when the target OS, Middleware or application cannot be
safely and consistently invoked by the Agent without Rolo-owned translation. For application gaps,
Rolo derives a candidate from target-observed routes, emits a minimal route-presence bundle, and
independently conforms it; a missing signal remains a rejected bundle. MVP provider IDs may
be implementation-specific, while the four family contracts remain platform-neutral. The Agent
receives only the public family names and tool IDs; concrete provider executable names are kept
inside the descriptor and may be replaced by a future provider implementation.

## Trust boundaries

- **Rolo** owns profile enrollment, target evidence, connector pinning, session authority,
  allowlists, budgets, artifact hashes and Conformance.
- **Agent** owns natural-language interpretation, tool selection, plan ordering and explanation.
  It may never invent argv or treat static/help output as runtime proof.
- **Robot** owns the actual runtime and returns bounded stdout/stderr and status. A missing
  executable, incomplete OS/Middleware environment or unavailable device is an explicit result,
  never success.
- **Adapter bundle** is an exceptional extension path for a named capability gap. It is generated
  only after a bounded Probe, then independently conformed and published. It does not expand the
  native surface by default.

## Entry points

```text
rolo target profile init/show/approve-host-key
rolo target inspect-profile --profile <id>
rolo target tool-surface --profile <id>
rolo target tool-plan --profile <id> <plan.json>
rolo target application-bundle --profile <id> --application <startup|navigation|mapping|manipulation>
robotctl probe target-evidence ...
robotctl probe start/status ...
```

The first two target commands are safe read-only checks. `tool-surface` returns the exact session
descriptor and catalog for the Agent. The Agent writes a `rolo-tool-plan/v1`; `tool-plan` verifies
its target, session, surface digest, allowlist and read-only mode before execution.

## Evidence and platform notes

`TargetEvidenceBundle` proves what exists on the enrolled target at collection time; it does not
prove physical correctness or safety. A target may also attach a signed, bounded `source_snapshot`
for later source-level work; Probe does not interpret it as runtime truth. SSH transport works from
any controller OS that provides an OpenSSH client. Provider execution sources only the target's
pinned runtime setup. If the target environment lacks required packages, runtime libraries or
middleware context, the tool returns a bounded failure with `environment_limited=true`.

The provider interface is intentionally open: the MVP can ship one concrete OS provider and one
concrete Middleware provider, while future providers reuse the same evidence, session, planning
and conformance contracts.

The authoritative implementation is concentrated in:

- `src/rolo/targets/profiles.py`, `src/rolo/targets/credentials.py`,
  `src/rolo/targets/executor.py` — enrollment and connector assembly;
- `src/rolo/stages/probe/target_evidence.py` — signed target evidence;
- `src/rolo/agent_tools/native_tools.py`, `src/rolo/agent_tools/session.py`,
  `src/rolo/agent_tools/planning.py` — Tool Surface, Session and ToolPlan;
- `src/rolo/stages/probe/application.py` — narrow application candidates, adapter bundles and
  independent application Conformance;
- `src/rolo/agent_tools/session_factory.py` — profile-bound session construction;
- `tests/test_probe_session_factory.py`, `tests/test_target_executors.py`,
  `tests/test_probe_evidence_contract.py`, `tests/test_product_cli_v2.py` — the retained
  v2 contract slice.

No MCP or web dashboard is required for this chain. Those integrations may be added later around
the same CLI and artifact contracts; they cannot become an alternate authority path.
