<!-- status: active; authority: guide; owner: rolo maintainers; last_reviewed: 2026-09-02 -->

# Rolo v2 configuration

Rolo v2 keeps normal operation profile-driven. The user names a target profile; Rolo resolves
the approved connector, evidence and Tool Surface without exposing private-key or password
contents to the Agent.

## Local state

Configuration and artifacts live outside the checkout in the platform's user configuration and
state directories. A project-local `.rolo/config` is also supported for an explicitly isolated
enrollment. Private identities, host-key files and probe runner secrets are ignored runtime state;
they must never be committed or copied into plans and logs.

## Target profile

```bash
rolo target profile init ssh://user@target.example/path/to/workspace --robot my-robot
rolo target profile show --profile my-robot
rolo target inspect-profile --profile my-robot
```

The profile stores the target address, workspace, credential reference, host-key decision and
optional runtime/provider hints. It does not store secret material. The credential broker first
tries the configured SSH agent and then the explicitly pinned identity reference. Passwords are
enrollment-only and are never accepted by a Tool invocation.

## Runtime/provider hints

Provider setup is target-owned and optional. A profile may point to a bounded setup descriptor
for the selected OS or Middleware provider; Rolo pins each resolved file and digest in the
TargetEvidenceBundle. Rolo never sources interactive shell profiles or Agent-selected paths, and
it never fills a missing target dependency from the controller environment. Missing executables,
packages, runtime libraries or Middleware context produce an explicit bounded failure.

The MVP ships one concrete OS provider and one concrete Middleware provider. Adding another
provider reuses the same profile, evidence, session, ToolPlan and Conformance contracts; it does
not change this configuration interface.

## Agent entry point

```bash
rolo target tool-surface --profile my-robot
rolo target tool-plan --profile my-robot PLAN.json
```

The returned surface is the only Tool vocabulary the Agent may use. Rolo enforces fixed argv,
read-only access, TTL, nonce, catalog digest, allowlist, output limits and per-call evidence.
