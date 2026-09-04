---
name: rolo-harness-codegen
description: Generate reusable Harness functions whose input and output contracts are derived from any pending Tool descriptor and its evidence bound execution contract.
---

# Rolo Harness Code Generation

Use this skill when Probe identifies a Tool that must be implemented and registered, or when a
registered Tool needs a target-local execution bundle. Read
[references/output-schema.md](references/output-schema.md) before producing an artifact.

This is a schema-driven code generator. It is not a catalog of device actions. The Tool descriptor
is the source of the function's input contract; the binding and observation contract are the source
of its execution and output contract. A new Tool must not require this Skill to be edited.

## Inputs

Require the current `probe-analysis-input`, the pending Tool descriptor, target identity, evidence
references, and a typed execution binding. The descriptor's `parameters` list is authoritative for
argument names, kinds, requiredness, choices, patterns and length limits. The binding is
authoritative for transport, feedback and stop behavior. If either contract is incomplete, return
`CODEGEN_INPUT_GAP` with the missing fields.

## Generate an isomorphic function

For every descriptor, construct a function contract mechanically:

```text
input  = {parameter.name: value for parameter in descriptor.parameters}
output = {field: value for field in observation_contract.fields}
```

The generated source must expose the canonical entrypoint
`execute(request: Mapping[str, Any]) -> Mapping[str, Any]`. At the boundary it must:

1. reject unknown or missing keys according to `descriptor.parameters`;
2. validate each value using its declared kind (`token`, `enum`, `integer`, `path`), choices,
   regex and length limits;
3. create a private typed request object containing exactly those validated inputs;
4. invoke the primitive selected by the binding's interface and stop strategy; and
5. return only fields declared by `observation_contract`, with a deterministic status and error
   classification. Extra output fields are rejected by the Harness validator.

Do not hand-write a function signature for a particular operation. If a descriptor changes, the
function input and validation code are regenerated from the descriptor. If a Tool has no declared
observation fields, stop with `CODEGEN_INPUT_GAP` rather than inventing a response shape.

## Generation and interaction loop

1. Freeze descriptor, binding, evidence references and the user's typed argument object.
2. Generate the function source, request object and output validator from those frozen contracts.
3. Calculate only binding-defined derived values; keep original arguments and derived request in the
   generation artifact.
4. Execute the bundle through Rolo's target executor. SSH or local execution is a transport detail
   selected by Rolo and never appears as generated shell text.
5. In the interactive Harness window, the user may revise source or arguments. Regenerate from the
   same contracts and rerun the bounded call; do not manually rebuild a transport payload.
6. Submit the source/binding digests and the generated contract with the typed registration proposal.
   Later Trace calls instantiate the same generated function from the registered contract.

## Genericity and authority

The same envelope applies to motion, navigation, mapping, sensing and future application Tools. The
only operation-specific inputs are the descriptor, binding, primitive template and observation
contract supplied by Probe and the Harness. Rolo remains authoritative for target identity, evidence,
binding validation, session limits, execution, registration and audit. Never invent a route,
parameter, output field or primitive. Never fall back to arbitrary shell, free-form argv or direct
device access.
