"""Rolo DSL contract primitives."""

from .bootstrap import BootstrapDiscoveryResult, BootstrapProbeProfile, run_bootstrap_projection
from .bootstrap_replay import BootstrapReplayReport, replay_bootstrap_artifacts, verify_bootstrap_artifacts
from .candidates import (
    CapabilityCandidate,
    CapabilityCandidateIndex,
    build_candidate_index,
    persist_candidate_index,
    query_candidates,
)
from .context_adapter import build_probe_context, persist_compile_context
from .context_digests import ContextChangeReport, ContextLayerDigests, context_layer_digests, evaluate_context_change
from .frontend import compile_frontend
from .mapping import AdapterMappingRequest, DslRepairLoop, MappingLoopResult, ProbeFollowUpRequest
from .models import DslDocument, OperationKind, OperationStatus
from .prompts import OPERATION_PROMPTS, render_mapping_prompt
from .proposal import MappingProposal, build_mapping_proposal, persist_mapping_proposal
from .sufficiency import MappingSufficiencyReport, assess_mapping_sufficiency

__all__ = [
    "AdapterMappingRequest",
    "CapabilityCandidate",
    "CapabilityCandidateIndex",
    "BootstrapDiscoveryResult",
    "BootstrapProbeProfile",
    "BootstrapReplayReport",
    "ContextChangeReport",
    "ContextLayerDigests",
    "DslDocument",
    "DslRepairLoop",
    "MappingLoopResult",
    "MappingProposal",
    "MappingSufficiencyReport",
    "OperationKind",
    "OperationStatus",
    "ProbeFollowUpRequest",
    "OPERATION_PROMPTS",
    "build_probe_context",
    "build_candidate_index",
    "context_layer_digests",
    "compile_frontend",
    "persist_compile_context",
    "persist_candidate_index",
    "persist_mapping_proposal",
    "query_candidates",
    "run_bootstrap_projection",
    "replay_bootstrap_artifacts",
    "verify_bootstrap_artifacts",
    "evaluate_context_change",
    "build_mapping_proposal",
    "render_mapping_prompt",
    "assess_mapping_sufficiency",
]
