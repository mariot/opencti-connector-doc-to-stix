from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
)
from connectors_sdk.settings.annotated_types import ListFromString
from pydantic import Field


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    name: str = Field(description="The name of the connector.", default="Doc to STIX")
    scope: ListFromString = Field(
        description="Entity types the connector enriches from their attached files.",
        default=[
            "Report",
            "Grouping",
            "Case-Incident",
            "Case-Rfi",
            "Case-Rft",
            "Intrusion-Set",
            "Threat-Actor-Group",
            "Campaign",
            "Malware",
            "Tool",
            "Incident",
        ],
    )


class DocToStixConfig(BaseConfigModel):
    """Which model reads the documents, and which files it reads."""

    model: str = Field(
        description="Model name: an Ollama model (qwen3:30b-a3b, or the fine-tuned "
        "doc-to-stix model), or a Claude model when anthropic_api_key is set.",
        default="qwen3:30b-a3b",
    )
    ollama_url: str = Field(
        description="Ollama base URL (used when anthropic_api_key is empty).",
        default="http://ollama:11434",
    )
    anthropic_api_key: str = Field(
        description="Use Claude through the Anthropic API instead of Ollama.",
        default="",
    )
    author: str = Field(
        description="Name of the identity the extracted objects are created by.",
        default="doc-to-stix",
    )
    max_files: int = Field(
        description="Files to read per entity (most recent first).", default=1, ge=1
    )
    mime_types: ListFromString = Field(
        description="Attached files the connector reads.",
        default=["application/pdf", "text/html", "text/plain", "text/markdown"],
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    doc_to_stix: DocToStixConfig = Field(default_factory=DocToStixConfig)
