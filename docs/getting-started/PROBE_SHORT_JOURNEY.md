<!-- status: active; authority: guide; owner: docs maintainers; last_reviewed: 2026-09-02 -->

# Probe short journey

The v2 user journey starts with one goal: initialize Rolo for a robot target. The user supplies a
profile and approves the host key once. The Agent then consumes the bounded Tool Surface; it does
not need to know Rolo's storage layout or credential details.

```text
profile enrollment
  → automatic SSH Connector assembly
  → target-bound TargetEvidenceBundle
  → NativeToolSession (allowlist, TTL, budget)
  → Agent ToolPlan
  → Rolo validation, execution, evidence and Conformance
```

## What each role does

- **User**: names the target, approves first-use trust, and states the observation goal;
- **Agent**: interprets the goal, reads the Tool Surface, chooses tools, orders calls, and explains results;
- **Rolo**: pins identity and host key, collects evidence, exposes only fixed read-only argv, and records artifacts;
- **Robot**: executes the provider command in its own OS/Middleware runtime and returns bounded status/output.

## Commands

```bash
rolo target profile init ssh://user@target.example/path/to/workspace --robot my-robot
rolo target inspect-profile --profile my-robot
rolo target tool-surface --profile my-robot
rolo target tool-plan --profile my-robot PLAN.json
```

If a required executable, package, runtime library, or Middleware context is absent, the result is
explicitly `UNAVAILABLE`, `FAILED`, or `TIMEOUT`; Rolo never turns an incomplete environment into
a successful observation. A capability that the Agent cannot safely invoke enters the bounded
Probe → Adapter bundle → independent Conformance path rather than expanding the native surface.
