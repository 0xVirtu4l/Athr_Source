from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List
from datetime import datetime


# --- Base and Nested Models ---

class CompromisedAsset(BaseModel):
    """
    Represents a compromised asset, mapping to the 'logs' table.
    Uses field aliases to map snake_case attributes to database column names.
    """
    entity_id: int
    machine_ip: Optional[str] = None
    machine_username: Optional[str] = None
    machine_name: Optional[str] = None
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

class LeakedFileInfo(BaseModel):
    """
    Represents all information related to a single leaked file (artifact).
    """
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

    # Aggregated data from related tables
    emails: List[str] = []
    logs: List[CompromisedAsset] = []

    # Pydantic v2 configuration for ORM mode
    model_config = ConfigDict(from_attributes=True)


class DomainSearchQuery(BaseModel):
    """Defines the structure for a domain-based search request."""
    domains: Optional[List[str]] = None