# Harness code generation output

The skill emits one JSON object with schema identifier `rolo-harness-code-bundle/v1` and these
additional generation fields:

```json
{
  "schema_version": "rolo-harness-code-bundle/v1",
  "tool_id": "app.base.rotate",
  "target_id": "mentorpi",
  "evidence_refs": ["target-evidence:<sha256>"],
  "binding_sha256": "<sha256>",
  "arguments": {"angle_degrees": 360, "max_speed_rad_s": 0.2},
  "request": {
    "command_endpoint": "/cmd_vel",
    "feedback_endpoints": ["/odom_raw", "/odom_rf2o"],
    "angular_speed_rad_s": 0.2,
    "goal_yaw_rad": 6.283185307179586,
    "duration_s": 47.1238898038469
  },
  "runtime": "python",
  "entrypoint": "main",
  "source": "<generated source>",
  "source_sha256": "<sha256>",
  "expected_observation": {
    "feedback": "odometry",
    "stop": "zero_velocity",
    "angle_tolerance_degrees": 3
  }
}
```

`source_sha256` is the digest of `source`; `binding_sha256` is the digest of the typed binding.
`arguments` are original user values and `request` is the derived target-bound invocation. The
generated object is an input to Rolo's existing `HarnessCodeBundle`; fields outside that runtime
model belong in the surrounding generation artifact and must not be interpolated into shell text.

For a different Tool, keep the same envelope and replace only the typed argument schema, primitive
template and expected observation contract. Missing evidence or a descriptor mismatch is a
`CODEGEN_INPUT_GAP`, never a guessed implementation.
