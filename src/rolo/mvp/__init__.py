"""LanderPi Agent journey MVP primitives.

The MVP package is deliberately small and dependency-light.  It provides the
stable contract shared by Probe, an external Agent adapter, Trace and Certify.
Device specific discovery remains owned by Probe; these helpers only consume
verified, target-bound artifacts.
"""

from .adapter import AgentAdapter, InMemoryAgentAdapter, RoloHttpAgentAdapter
from .artifacts import ArtifactIndex, build_artifact_index, rollback_artifact_index, write_artifact_index
from .binding_dispatch import ApplicationBindingDispatcher, BindingHandler
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
    CertifyRequest,
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
    TraceStartRequest,
)
from .harness_codegen import build_codegen_artifact, generate_contract_source
from .harness_execution import HarnessCodeBundle, HarnessCodeExecutor, build_python_launcher, make_code_bundle
from .journey_cli import run_certify, run_trace
from .probe_registration import (
    ExecutionBinding,
    ProbeAnalysisInput,
    ToolRegistrationProposal,
    ToolRegistrationResult,
    build_probe_analysis_input,
    load_registered_bindings,
    load_registered_codegen_artifact,
    load_registered_descriptors,
    load_registered_proposals,
    register_tool_proposal,
)
from .ros_binding import RosBindingExecutor
from .rotation import RotationDebugAssessment, RotationDebugRequest, assess_rotation_readiness, rotation_tool_proposal
from .trace import TraceService
from .trace_diagnostics import (
    OdomEkfDiagnosis,
    OdomEkfObservation,
    TraceDiagnosticPlan,
    TraceDiagnosticStep,
    assess_odom_ekf_observation,
    build_odom_ekf_diagnostic_plan,
    diagnose_trace_payload,
    observation_from_trace_payload,
)

__all__ = [
    "AgentAdapter",
    "ArtifactIndex",
    "build_artifact_index",
    "write_artifact_index",
    "rollback_artifact_index",
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
    "run_trace",
    "run_certify",
    "CaseStatus",
    "CatalogTool",
    "CertificationCase",
    "CertificationCaseResult",
    "CertificationReport",
    "CertificationSuite",
    "CertifyRequest",
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
    "TraceStartRequest",
    "TraceDiagnosticStep",
    "TraceDiagnosticPlan",
    "OdomEkfObservation",
    "OdomEkfDiagnosis",
    "build_odom_ekf_diagnostic_plan",
    "assess_odom_ekf_observation",
    "observation_from_trace_payload",
    "diagnose_trace_payload",
    "RotationDebugAssessment",
    "RotationDebugRequest",
    "assess_rotation_readiness",
    "rotation_tool_proposal",
    "RosBindingExecutor",
    "HarnessCodeBundle",
    "HarnessCodeExecutor",
    "build_python_launcher",
    "make_code_bundle",
    "generate_contract_source",
    "build_codegen_artifact",
    "ApplicationBindingDispatcher",
    "BindingHandler",
    "ProbeAnalysisInput",
    "ExecutionBinding",
    "ToolRegistrationProposal",
    "ToolRegistrationResult",
    "build_probe_analysis_input",
    "register_tool_proposal",
    "load_registered_descriptors",
    "load_registered_bindings",
    "load_registered_codegen_artifact",
    "load_registered_proposals",
]
