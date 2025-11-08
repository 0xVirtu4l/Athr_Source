from pydantic import BaseModel, ConfigDict, EmailStr
from typing import Optional, List


class User(BaseModel):
    """
    Pydantic model representing a user from the users table.
    Includes all columns with updated analytics fields.
    """
    user_id: str
    org_id: str
    full_name: str
    email: str
    role: str
    created_at: str
    last_login: str
    account_status: str
    last_login_ip: Optional[str]
    auth_provider: str
    last_activity_at: Optional[str]
    login_count: int
    incident_reports_viewed: int
    is_billing_contact: bool

    model_config = ConfigDict(from_attributes=True)


class IncidentReport(BaseModel):
    """
    Pydantic model representing an incident from the incident_reports table.
    """
    incident_id: str
    org_id: str
    source: str
    severity: str
    category: str
    collected_at: str
    leaked_email_count: int
    compromised_machine_count: int

    model_config = ConfigDict(from_attributes=True)


class Organization(BaseModel):
    """
    Pydantic model representing an organization from the organizations table.
    Includes calculated fields for user_count and incident_count.
    """
    org_id: str
    name: str
    plan: str
    domains: List[str]
    ip_ranges: List[str]
    keywords: List[str]
    created_at: str
    user_count: int
    incident_count: int

    model_config = ConfigDict(from_attributes=True)


class Stats(BaseModel):
    """
    Pydantic model for main dashboard KPIs.
    """
    total_organizations: int
    total_users: int
    total_incidents: int

    model_config = ConfigDict(from_attributes=True)


class AdminStatus(BaseModel):
    """
    Pydantic model for admin status check response.
    """
    is_admin: bool
