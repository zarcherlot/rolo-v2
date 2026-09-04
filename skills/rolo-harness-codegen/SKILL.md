---
name: rolo-harness-codegen
description: Generate reusable, parameter-ready Rolo Harness bundles from Probe evidence and a typed Tool contract, including transport bindings, feedback, stop behavior, and execution arguments.
---

# Rolo Harness Code Generation

Use this skill when Probe has established that a Tool must be registered or when a registered Tool
needs a target-local execution bundle. Read [references/output-schema.md](references/output-schema.md)
before producing the bundle.

The purpose is to prepare the complete invocation before any target transport starts. The Harness
should never rediscover parameter names or manually compose an SSH command after the user has named
a Tool. SSH (or local execution) is selected by Rolo's target executor; it is not generated source.

## Inputs

Require the current `probe-analysis-input` or registered Tool descriptor, target identity and
evidence references, typed `ExecutionBinding`, and the user's operation arguments validated against
the descriptor schema.

For `app.base.rotate`, prepare the argument object up front:

```json
{"angle_degrees": 360, "max_speed_rad_s": 0.2}
```

These are user values, not silent defaults. Preserve exact numeric values and reject extra or
missing fields before generating code.

## Generation loop

1. Normalize arguments once and calculate derived values such as signed angular speed, goal radians
   and bounded execution duration. Keep original arguments and the derived request in the bundle.
2. Generate source from a reusable primitive template selected by the Tool contract. The template
   receives a request object; it must not contain credentials, arbitrary argv, shell text or an
   unbounded topic name.
3. Emit the complete `rolo-harness-code-bundle/v1` object, including source digest, binding digest,
   target/evidence references, typed arguments and expected observation/stop contract.
4. Execute through Rolo's target executor. In an interactive coding window, the user may correct
   source or arguments; regenerate the bundle and rerun the same bounded validation. Do not hand-copy
   a new SSH payload for each iteration.
5. Submit the final bundle digest with the typed `ToolRegistrationProposal`. Registration records the
   generated source and argument contract so later Trace calls reuse the template without another
   coding round.

## Rotation contract

Rotation uses the generic bounded-Twist primitive. Its prepared request contains `/cmd_vel`, observed
odometry feedback endpoints, signed angular speed, goal yaw and a bounded duration with runtime
margin. The primitive publishes zero velocity in `finally`, reads back odometry, and returns measured
angle, error, stop confirmation and feedback topic. A full turn is another typed angle value; it must
not require a new adapter or hand-written SSH script.

## Authority and fallback

The skill generates code and typed input; Rolo remains authoritative for target identity, evidence,
binding validation, session limits, execution and registration. Never invent a route or promote a
parameter absent from the descriptor. If the descriptor or binding is incomplete, return a typed
`CODEGEN_INPUT_GAP` result with missing fields and stop. Never fall back to arbitrary shell, `ros2
topic pub`, free-form argv or direct device access.
