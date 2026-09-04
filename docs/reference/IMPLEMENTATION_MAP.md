<!-- status: active; authority: reference; owner: rolo maintainers; last_reviewed: 2026-09-04 -->

# Rolo v2 implementation map

This page indexes the executable v2 slice. It is intentionally not a second registry or
architecture specification. The product boundary is:

```text
TargetProfile → SSH Connector → TargetEvidenceBundle
             → NativeToolSession → Agent ToolPlan → Conformance
             ↘ application Candidate → Adapter bundle → application Conformance (named gaps only)
```

## Entry points

| Surface | Code | Responsibility |
|---|---|---|
| `rolo` | `src/rolo/product_cli.py` | User-facing profile inspection, target evidence, Tool Surface, ToolPlan and Probe commands |
| `robotctl` | `src/rolo/cli.py`, `src/rolo/commands/` | Small operational Probe/configuration surface |
| `rolo-http` | `src/rolo/http_server.py` (`rolo.api:app` compatibility) | Production ASGI server; embeds validated GET-only MHS evidence routes |
| package checks | `src/rolo/release_check.py` | Import, schema, docs and artifact sanity checks |

## Chain components

| Component | Code | Boundary |
|---|---|---|
| Target profile | `src/rolo/targets/profiles.py`, `credentials.py` | Stores target address, identity reference, host-key pin and bounded provider hints; no secret material |
| SSH connector | `src/rolo/targets/executor.py`, `src/rolo/agent_tools/session_factory.py` | Resolves a profile to a pinned local or SSH executor; fail-closed on host-key or identity mismatch |
| Target evidence | `src/rolo/stages/probe/target_evidence.py`, `active_discovery.py`, `discovery.py` | Runs bounded OS/Middleware/hardware probes and writes signed, target-bound evidence |
| Application gap bundle | `src/rolo/stages/probe/application.py`, `src/rolo/product_cli.py` | Derives four small-car candidates or one v1 application-operation candidate from observed routes, binds it to an existing native observation Tool, emits a minimal read-only adapter, and independently conforms the binding |
| Native Tool Surface | `src/rolo/agent_tools/native_tools.py` | Curated read-only family descriptors; Agent sees `hardware`/`OS`/`Middleware` names while provider commands remain implementation details |
| Tool session | `src/rolo/agent_tools/session.py`, `broker.py` | Binds target, catalog digest, nonce, allowlist and budgets; emits result artifacts and audit records |
| Agent planning | `src/rolo/agent_tools/planning.py` | Validates an Agent-produced plan against the session, digest, target and read-only policy |
| Conformance | `src/rolo/agent_tools/conformance.py` | Independently checks descriptor uniqueness, catalog identity, allowlist and fixed-argv/read-only bounds |
| Artifacts | `src/rolo/core/artifacts.py` | Writes relative `artifact://` references under the configured artifact root |
| MHS evidence API | `src/rolo/rkb/mhs_api.py`, `rkb/mhs_http.py`, `mhs_manifest_records.py` | Validates manifest/provider records at publish time and exposes read-only evidence over HTTP |

## Four semantic families

The public standard has only four families: `hardware`, `OS`, `Middleware`, and `application`.
The current MVP provider implementation may use concrete provider IDs internally, but those IDs
are not part of the user contract. A provider can be added only when a bounded Probe and an
independent Conformance test can describe its evidence and failure behavior.

## Tests and CI

The maintained v2 test slice covers native descriptors and runners, session/budget/audit,
ToolPlan validation, profile-bound executors, target evidence contracts, and Conformance. CI runs
this slice across Python 3.10–3.13, plus docs, release-check and wheel-build checks. Historical
v1 tests and design documents are not executable compatibility requirements for v2.

## Explicit non-goals

- No v1 Registry compatibility layer or 197/294-item canonical catalog.
- No MCP packaging in this slice; the Agent consumes the Tool surface directly.
- No Trace or Certify business logic; only their future boundary is named.
- No write, calibration, reset, actuator, power or firmware operation.
- No claim that target evidence proves physical safety or behavioral correctness.
