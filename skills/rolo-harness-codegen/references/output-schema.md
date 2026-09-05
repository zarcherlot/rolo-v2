# Generic Harness code generation output

The generator emits a surrounding artifact with schema identifier
`rolo-harness-codegen-artifact/v1`. Its `bundle` is the existing
`rolo-harness-code-bundle/v1` consumed by Rolo.

```json
{
  "schema_version": "rolo-harness-codegen-artifact/v1",
  "target_id": "<target>",
  "tool_id": "<descriptor.tool_id>",
  "evidence_refs": ["<evidence id>"],
  "descriptor_sha256": "<sha256>",
  "binding_sha256": "<sha256>",
  "arguments": {"<parameter.name>": "<typed value>"},
  "input_contract": {
    "parameters": ["<descriptor.parameters entries>"]
  },
  "observation_contract": {
    "fields": ["status", "<declared field>"]
  },
  "derived_request": {"<binding-defined key>": "<value>"},
  "bundle": {
    "schema_version": "rolo-harness-code-bundle/v1",
    "tool_id": "<descriptor.tool_id>",
    "runtime": "python",
    "entrypoint": "execute",
    "source": "<generated function source>",
    "source_sha256": "<sha256>",
    "request": {"<validated parameters and derived values>": "..."}
  }
}
```

The generator must preserve descriptor parameter entries verbatim in `input_contract` and emit an
output validator for every `observation_contract.fields` entry. `arguments` contain the user's
original values; `derived_request` contains only values computed by the typed binding. The bundle
remains compatible with `HarnessCodeBundle`; surrounding fields are not interpolated into shell or
argv text.

If a parameter cannot be represented by the declared descriptor kind, or the observation contract is
missing, emit `CODEGEN_INPUT_GAP` and no executable bundle. A successful JSON shape check does not
prove target capability; Probe evidence and Rolo registration validation remain authoritative.
