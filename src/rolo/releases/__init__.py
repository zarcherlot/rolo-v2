from importlib import import_module
from typing import TYPE_CHECKING, Any

from .catalog import (
    CatalogHead,
    CatalogMutation,
    CatalogTransaction,
    ReleaseCatalog,
    ReleaseCatalogError,
    release_payload_digest,
)
from .proofs import (
    TRUSTED_TARGET_CONFORMANCE_AUTHORITY,
    ReleaseTargetConformanceBinding,
    ResolvedTargetConformanceArtifacts,
    TargetConformanceArtifactError,
    TargetConformanceArtifactReference,
    TargetConformanceArtifactStore,
    TrustedTargetConformanceArtifactResolver,
)
from .publisher import (
    ProductionReleasePublisher,
    ReleasePublicationReceipt,
    ReleasePublisher,
    TargetConformanceReport,
    ToolRelease,
    tool_release_digest,
)
from .signature import (
    PRODUCTION_TARGET_SIGNATURE_AUTHORITY,
    ReleaseSignatureError,
    TargetReleaseSignature,
    TargetReleaseSigner,
    TargetSignatureAlgorithm,
    TargetSignatureVerification,
    TargetSignatureVerifier,
    signature_message,
    statement_digest,
)
from .targetd_upload import (
    TargetdReleaseUploadAdapter,
    TargetdReleaseUploadBeginRequest,
    TargetdReleaseUploadBeginResponse,
    TargetdReleaseUploadCommitRequest,
    TargetdReleaseUploadCommitResponse,
    TargetdReleaseUploadError,
    TargetdReleaseUploadOperation,
    TargetdReleaseUploadPutChunkRequest,
    TargetdReleaseUploadPutChunkResponse,
    TargetdReleaseUploadReceipt,
    TargetdReleaseUploadRequest,
    TargetdReleaseUploadResponse,
    TargetdReleaseUploadStatusRequest,
    TargetdReleaseUploadStatusResponse,
    TargetdReleaseUploadTransport,
    targetd_release_upload_idempotency_key,
)
from .upload import (
    ChunkUploadManifest,
    ContentAddressedUploadStore,
    ReleaseUploadError,
    UploadCommit,
    UploadStatus,
    content_digest,
)

if TYPE_CHECKING:
    from .consumers import CertifyConsumer as CertifyConsumer
    from .consumers import ExecutionEnvelope as ExecutionEnvelope
    from .consumers import TraceConsumer as TraceConsumer
    from .journey import PostCompilerJourney as PostCompilerJourney
    from .journey import PostCompilerJourneyResult as PostCompilerJourneyResult
    from .journey import PublishedReleaseInvoker as PublishedReleaseInvoker
    from .journey import ReleaseBoundCertify as ReleaseBoundCertify
    from .journey import ReleaseBoundTrace as ReleaseBoundTrace
    from .journey import ReleaseInvocation as ReleaseInvocation

_LAZY_EXPORTS = {
    "CertifyConsumer": (".consumers", "CertifyConsumer"),
    "ExecutionEnvelope": (".consumers", "ExecutionEnvelope"),
    "TraceConsumer": (".consumers", "TraceConsumer"),
    "PostCompilerJourney": (".journey", "PostCompilerJourney"),
    "PostCompilerJourneyResult": (".journey", "PostCompilerJourneyResult"),
    "PublishedReleaseInvoker": (".journey", "PublishedReleaseInvoker"),
    "ReleaseBoundCertify": (".journey", "ReleaseBoundCertify"),
    "ReleaseBoundTrace": (".journey", "ReleaseBoundTrace"),
    "ReleaseInvocation": (".journey", "ReleaseInvocation"),
}

__all__ = [
    "CertifyConsumer",
    "CatalogHead",
    "CatalogMutation",
    "CatalogTransaction",
    "ChunkUploadManifest",
    "ContentAddressedUploadStore",
    "ExecutionEnvelope",
    "PostCompilerJourney",
    "PostCompilerJourneyResult",
    "ProductionReleasePublisher",
    "PublishedReleaseInvoker",
    "ReleaseBoundCertify",
    "ReleaseBoundTrace",
    "ReleaseInvocation",
    "ReleasePublisher",
    "ReleasePublicationReceipt",
    "ReleaseCatalog",
    "ReleaseCatalogError",
    "ReleaseSignatureError",
    "ReleaseTargetConformanceBinding",
    "ReleaseUploadError",
    "PRODUCTION_TARGET_SIGNATURE_AUTHORITY",
    "TRUSTED_TARGET_CONFORMANCE_AUTHORITY",
    "ResolvedTargetConformanceArtifacts",
    "TargetConformanceArtifactError",
    "TargetConformanceArtifactReference",
    "TargetConformanceArtifactStore",
    "TargetConformanceReport",
    "TargetReleaseSignature",
    "TargetReleaseSigner",
    "TargetSignatureAlgorithm",
    "TargetSignatureVerification",
    "TargetSignatureVerifier",
    "TargetdReleaseUploadAdapter",
    "TargetdReleaseUploadBeginRequest",
    "TargetdReleaseUploadBeginResponse",
    "TargetdReleaseUploadCommitRequest",
    "TargetdReleaseUploadCommitResponse",
    "TargetdReleaseUploadError",
    "TargetdReleaseUploadOperation",
    "TargetdReleaseUploadPutChunkRequest",
    "TargetdReleaseUploadPutChunkResponse",
    "TargetdReleaseUploadReceipt",
    "TargetdReleaseUploadRequest",
    "TargetdReleaseUploadResponse",
    "TargetdReleaseUploadStatusRequest",
    "TargetdReleaseUploadStatusResponse",
    "TargetdReleaseUploadTransport",
    "ToolRelease",
    "TraceConsumer",
    "UploadCommit",
    "UploadStatus",
    "TrustedTargetConformanceArtifactResolver",
    "content_digest",
    "release_payload_digest",
    "signature_message",
    "statement_digest",
    "targetd_release_upload_idempotency_key",
    "tool_release_digest",
]


def __getattr__(name: str) -> Any:
    """Load control-plane release helpers only when they are requested."""

    export = _LAZY_EXPORTS.get(name)
    if export is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute_name = export
    value = getattr(import_module(module_name, __name__), attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
