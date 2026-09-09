"""Protocol and persistence primitives for the targetd execution bridge."""

from importlib import import_module
from typing import TYPE_CHECKING, Any

from .controller import TargetdJourneyController
from .dsl_protocol import DslFrame, DslFrameType
from .dsl_service import TargetdDslService
from .installer import TargetdInstaller, TargetdInstallManifest
from .lifecycle import (
    MAX_WORKER_LEASE_STATE_BYTES,
    MAX_WORKER_LEASES,
    LeasedWorkerRuntime,
    WorkerCallKey,
    WorkerCompletion,
    WorkerControl,
    WorkerLeaseClaim,
    WorkerLeaseRecord,
    WorkerLeaseStore,
    WorkerLifecycleError,
    WorkerStopAcknowledgement,
)
from .protocol import (
    BundleCache,
    ExecutionBundleManifest,
    ExecutionRequest,
    ExecutionRequestLike,
    ExecutionRequestV3,
    FrameKind,
    JourneyPhase,
    JourneySession,
    ProtocolFrame,
    TargetdAuthorityActivationRequest,
    TargetdCallReceipt,
    TargetdExecutionAuthority,
    TargetdExecutionAuthorityStore,
    TargetdMappingCancelRequest,
    TargetdStateStore,
    TargetdVerifiedReleaseProvisionRequest,
    decode_frame,
    encode_frame,
    execution_subject_digest,
    requires_motion_safety,
    validate_execution_request,
)
from .ros2_runtime import (
    Ros2RuntimeResolver,
    Ros2RuntimeSnapshot,
    Ros2Topic,
    parse_ros2_nodes,
    parse_ros2_topic_list,
    parse_ros2_topic_types,
    snapshot_from_cli_output,
)
from .router import JourneyPhaseRouter
from .runtime_backend import (
    DeclarativeRuntimeBackend,
    ResolvedBackend,
    Ros2ReadOnlyExecutor,
    Ros2RuntimeBackend,
    RuntimeBackend,
    RuntimeBackendRegistry,
    ros2_registry,
)
from .service import (
    TargetdHealth,
    TargetdReleaseCatalog,
    TargetdReleaseHead,
    TargetdService,
)
from .session import FrameCodec, TargetdSession
from .transport import (
    InMemoryTargetdTransport,
    JourneyDslTransport,
    JourneySessionClient,
    SshStdioChannel,
)
from .worker import Provider, PythonBundleWorker, RosContainerProvider

if TYPE_CHECKING:
    from .certify_adapter import MAX_CERTIFY_REQUEST_RECORDS as MAX_CERTIFY_REQUEST_RECORDS
    from .certify_adapter import TargetdV2CertifyAdapter as TargetdV2CertifyAdapter
    from .certify_adapter import TargetdV2CertifyRequestRecord as TargetdV2CertifyRequestRecord
    from .certify_adapter import TargetdV2CertifyResponse as TargetdV2CertifyResponse

_LAZY_EXPORTS = {
    "MAX_CERTIFY_REQUEST_RECORDS": (
        ".certify_adapter",
        "MAX_CERTIFY_REQUEST_RECORDS",
    ),
    "TargetdV2CertifyAdapter": (".certify_adapter", "TargetdV2CertifyAdapter"),
    "TargetdV2CertifyRequestRecord": (
        ".certify_adapter",
        "TargetdV2CertifyRequestRecord",
    ),
    "TargetdV2CertifyResponse": (".certify_adapter", "TargetdV2CertifyResponse"),
}

__all__ = [
    "BundleCache",
    "ExecutionBundleManifest",
    "ExecutionRequest",
    "ExecutionRequestLike",
    "ExecutionRequestV3",
    "execution_subject_digest",
    "requires_motion_safety",
    "validate_execution_request",
    "decode_frame",
    "encode_frame",
    "FrameKind",
    "JourneyPhase",
    "JourneySession",
    "ProtocolFrame",
    "TargetdAuthorityActivationRequest",
    "TargetdCallReceipt",
    "TargetdExecutionAuthority",
    "TargetdExecutionAuthorityStore",
    "TargetdMappingCancelRequest",
    "TargetdVerifiedReleaseProvisionRequest",
    "TargetdStateStore",
    "TargetdHealth",
    "TargetdReleaseCatalog",
    "TargetdReleaseHead",
    "TargetdService",
    "JourneySessionClient",
    "JourneyDslTransport",
    "SshStdioChannel",
    "PythonBundleWorker",
    "Provider",
    "RosContainerProvider",
    "TargetdJourneyController",
    "JourneyPhaseRouter",
    "TargetdInstaller",
    "TargetdInstallManifest",
    "MAX_WORKER_LEASE_STATE_BYTES",
    "MAX_WORKER_LEASES",
    "LeasedWorkerRuntime",
    "WorkerCallKey",
    "WorkerCompletion",
    "WorkerControl",
    "WorkerLeaseClaim",
    "WorkerLeaseRecord",
    "WorkerLeaseStore",
    "WorkerLifecycleError",
    "WorkerStopAcknowledgement",
    "DslFrame",
    "DslFrameType",
    "FrameCodec",
    "InMemoryTargetdTransport",
    "TargetdDslService",
    "TargetdSession",
    "Ros2Topic",
    "Ros2RuntimeResolver",
    "Ros2RuntimeSnapshot",
    "parse_ros2_nodes",
    "parse_ros2_topic_list",
    "parse_ros2_topic_types",
    "snapshot_from_cli_output",
    "ResolvedBackend",
    "DeclarativeRuntimeBackend",
    "Ros2RuntimeBackend",
    "Ros2ReadOnlyExecutor",
    "RuntimeBackend",
    "RuntimeBackendRegistry",
    "ros2_registry",
    "MAX_CERTIFY_REQUEST_RECORDS",
    "TargetdV2CertifyAdapter",
    "TargetdV2CertifyRequestRecord",
    "TargetdV2CertifyResponse",
]


def __getattr__(name: str) -> Any:
    """Keep optional control-plane Certify imports off the daemon path."""

    export = _LAZY_EXPORTS.get(name)
    if export is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute_name = export
    value = getattr(import_module(module_name, __name__), attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
