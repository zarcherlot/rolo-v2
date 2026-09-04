"""LanderPi Agent journey MVP primitives.

The MVP package is deliberately small and dependency-light.  It provides the
stable contract shared by Probe, an external Agent adapter, Trace and Certify.
Device specific discovery remains owned by Probe; these helpers only consume
verified, target-bound artifacts.
"""

from .adapter import AgentAdapter, InMemoryAgentAdapter, RoloHttpAgentAdapter
from .catalog import build_target_catalog, load_target_catalog, save_target_catalog
from .certify import CertificationRunner, load_suite, write_report
from .context import AgentContext, build_agent_context
from .contracts import (
    CaseStatus,
    CatalogTool,
    CertificationCase,
    CertificationCaseResult,
    CertificationReport,
    CertificationSuite,
    MhsInventoryEntry,
    RkbModelRef,
    RunMode,
    SessionState,
    TargetCatalog,
    ToolState,
    TraceCall,
    TraceEvent,
    TraceSession,
    TraceSessionRequest,
)
from .probe_registration import (
    ExecutionBinding,
    ProbeAnalysisInput,
    ToolRegistrationProposal,
    ToolRegistrationResult,
    build_probe_analysis_input,
    load_registered_bindings,
    load_registered_descriptors,
    load_registered_proposals,
    register_tool_proposal,
)
from .rotation import RotationDebugAssessment, RotationDebugRequest, assess_rotation_readiness, rotation_tool_proposal
from .trace import TraceService

__all__ = [
    "AgentAdapter",
    "InMemoryAgentAdapter",
    "RoloHttpAgentAdapter",
    "build_target_catalog",
    "load_target_catalog",
    "save_target_catalog",
    "CertificationRunner",
    "load_suite",
    "write_report",
    "AgentContext",
    "build_agent_context",
    "TraceService",
    "CaseStatus",
    "CatalogTool",
    "CertificationCase",
    "CertificationCaseResult",
    "CertificationReport",
    "CertificationSuite",
    "MhsInventoryEntry",
    "RkbModelRef",
    "RunMode",
    "SessionState",
    "TargetCatalog",
    "ToolState",
    "TraceCall",
    "TraceEvent",
    "TraceSession",
    "TraceSessionRequest",
    "RotationDebugAssessment",
    "RotationDebugRequest",
    "assess_rotation_readiness",
    "rotation_tool_proposal",
    "ProbeAnalysisInput",
    "ExecutionBinding",
    "ToolRegistrationProposal",
    "ToolRegistrationResult",
    "build_probe_analysis_input",
    "register_tool_proposal",
    "load_registered_descriptors",
    "load_registered_bindings",
    "load_registered_proposals",
]
