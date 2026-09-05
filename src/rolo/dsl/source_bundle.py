"""EXECUTE source bundle contract and deterministic manifest validation."""

from pydantic import Field, field_validator

from .models import StrictModel


class SourceBundleManifest(StrictModel):
    schema_version: str = "rolo-source-bundle/v1"
    source_bundle_digest: str = Field(min_length=7)
    entrypoint: str = Field(min_length=1)
    runtime: str = Field(min_length=1)
    files: tuple[str, ...] = ()
    implementation_contract: str = Field(min_length=1)

    @field_validator("source_bundle_digest")
    @classmethod
    def digest_format(cls, value: str) -> str:
        if not value.startswith("sha256:"):
            raise ValueError("source_bundle_digest must use sha256:<hex>")
        return value
