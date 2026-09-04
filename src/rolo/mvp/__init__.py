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
from .rotation import RotationDebugAssessment, RotationDebugRequest, assess_rotation_readiness
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
]
