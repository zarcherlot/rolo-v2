"""Run one bounded Rolo v2 native-tool probe inside a target container.

The script intentionally loads the native runner directly so a target does not need
the full Rolo CLI dependency set just to validate the read-only tool path.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys


def _load(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


runtime_context = _load("rolo.runtime_context", "/tmp/rolo/runtime_context.py")
native_tools = _load(
    "rolo.agent_tools.native_tools", "/tmp/rolo/agent_tools/native_tools.py"
)
planning = _load("rolo.agent_tools.planning", "/tmp/rolo/agent_tools/planning.py")
runner = native_tools.AgentNativeRunner(native_tools.reduced_agent_native_catalog())
target_environment = {
    key: os.environ[key]
    for key in ("PATH", "PYTHONPATH", "LD_LIBRARY_PATH", "AMENT_PREFIX_PATH")
    if key in os.environ
}
catalog = runner.list_tools()
surface_digest = hashlib.sha256(
    json.dumps(
        [item.model_dump(mode="json") for item in catalog],
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
).hexdigest()
plan = planning.build_tool_plan(
    goal="确认目标机器人主机与 ROS graph 在线",
    target_id="raspberrypi-192-168-10-167",
    session_id="hardware-smoke",
    session_nonce="hardware-smoke-session-nonce",
    surface_digest=surface_digest,
    steps=[
        planning.ToolPlanStep(
            tool_id="native.os.host.inspect",
            arguments={"mode": "inventory"},
            expected_observation="目标主机内核和架构",
        ),
        planning.ToolPlanStep(
            tool_id="native.middleware.graph.inspect",
            arguments={"mode": "nodes"},
            expected_observation="当前 ROS 节点列表",
        ),
    ],
)
planning.validate_tool_plan(
    plan,
    allowed_tool_ids=[item.tool_id for item in catalog],
    catalog=catalog,
)
print(json.dumps({"type": "tool-plan", **plan.model_dump(mode="json")}, ensure_ascii=False))

for step in plan.steps:
    result = runner.run(step.tool_id, step.arguments, environment=target_environment)
    print(result.model_dump_json())
