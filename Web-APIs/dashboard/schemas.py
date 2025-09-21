from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List
from datetime import datetime


# --- Base and Nested Models ---

class Finding(BaseModel):
    """Represents a specific finding within an incident, like a malicious string or line of code."""
    type: str
    value: str
    line_number: Optional[int] = None

    # Pydantic v2 configuration for ORM mode
    model_config = ConfigDict(from_attributes=True)


class CompromisedAsset(BaseModel):
    """
    Represents a compromised asset, mapping to the 'logs' table.
    Uses field aliases to map snake_case attributes to database column names.
    """
    entity_id: int
    machine_ip: Optional[str] = None
    machine_username: Optional[str] = None
    machine_country: Optional[str] = None
    machine_locations: Optional[str] = None
    machine_hwid: str = Field(alias="machine_HWID")
    malware_path: Optional[str] = None
    malware_install_date: datetime = Field(alias="malware_installDate")
    domains_leaked: Optional[List[str]] = Field(alias="Domains_Leaked", default=None)
    leaked_cookies: int = Field(alias="Leaked_cookies")
    leaked_autofills: int = Field(alias="Leaked_Autofills")

    # Pydantic v2 configuration for ORM mode and alias population
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
    )


# --- Main API Data Models ---

class Incident(BaseModel):
    """
    The main incident model, representing a full security incident record.
    This model is configured to work with ORM objects.
    """
    # Fields from the 'content_details' table
    artifact_id: int
    source: Optional[str] = None
    source_path: Optional[str] = None
    original_filename: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    mime_type: Optional[str] = None
    size_bytes: Optional[int] = None
    hash_sha256: Optional[str] = None
    collected_at: Optional[datetime] = None
    posted_at: Optional[datetime] = None
    storage_path: Optional[str] = None

    # Nested data models
    findings: List[Finding] = []
    compromised_assets: List[CompromisedAsset] = []

    # Pydantic v2 configuration for ORM mode
    model_config = ConfigDict(from_attributes=True)


class IncidentSummary(BaseModel):
    """A lightweight model for displaying a list of incidents."""
    artifact_id: int
    original_filename: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    source: Optional[str] = None
    collected_at: Optional[datetime] = None
    posted_at: Optional[datetime] = None

    # Pydantic v2 configuration for ORM mode
    model_config = ConfigDict(from_attributes=True)


class IncidentWithFindingsSummary(BaseModel):
    """
    A detailed model for search results that includes a list of associated findings.
    """
    artifact_id: int
    original_filename: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    source: Optional[str] = None
    collected_at: Optional[datetime] = None
    posted_at: Optional[datetime] = None
    findings: List[Finding] = []

    # Pydantic v2 configuration for ORM mode
    model_config = ConfigDict(from_attributes=True)


class DashboardStats(BaseModel):
    """A model for representing high-level dashboard statistics."""
    new_incidents_7_days: int
    critical_high_incidents: int
    compromised_machines: int
    leaked_credentials: int


class SearchQuery(BaseModel):
    """Defines the structure for an asset-based search request."""
    domains: Optional[List[str]] = None
    ip_ranges: Optional[List[str]] = None
    keywords: Optional[List[str]] = None