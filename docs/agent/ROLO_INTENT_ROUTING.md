<!-- status: active; authority: guide -->

# Intent routing

| User intent | First Rolo action | Follow-up |
|---|---|---|
| discover a robot or its capabilities | `probe` / `discover_target` | read RKB/MHS only as needed |
| complete a task | create Trace session | invoke only callable catalog tools |
| perform one explicit operation | `tool-plan` or `invoke_tool` | preserve result/evidence |
| run tests or regression | `certify` | only after explicit user request |
| inspect a known fact | `read_rkb` | preserve `UNKNOWN` and limitations |

The harness decides whether another call is useful after reading the previous structured result.
It must never infer a missing capability from a tool name or invent shell commands. Tool failures
must be followed by evidence-backed diagnosis or a bounded `BLOCKED`/`UNKNOWN` result.
