import json
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    Text,
    ForeignKey,
    TypeDecorator,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class CommaSeparatedList(TypeDecorator):
    """
    Custom type to handle comma-separated strings in a text column
    and represent them as a Python list.
    """

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        # On the way in, convert list to comma-separated string
        if value is not None:
            return ",".join(str(v) for v in value)

    def process_result_value(self, value, dialect):
        # On the way out, convert comma-separated string to list
        if value:  # Handles both None and empty strings
            return [item.strip() for item in value.split(",")]
        return [] # Return an empty list for empty/NULL db values


class ContentDetails(Base):
    __tablename__ = "content_details"

    artifact_id = Column(Integer, primary_key=True, index=True)
    source = Column(String, index=True, nullable=True)
    source_path = Column(String, nullable=True)
    original_filename = Column(String, nullable=True)
    severity = Column(String, index=True, nullable=True)
    category = Column(String, index=True, nullable=True)
    mime_type = Column(String, nullable=True)
    size_bytes = Column(Integer, nullable=True)
    hash_sha256 = Column(String, nullable=True)
    collected_at = Column(DateTime, nullable=True)
    posted_at = Column(DateTime, nullable=True)
    storage_path = Column(String, nullable=True)

    # Relationships
    findings_ulp = relationship("UlpFinding", back_populates="incident")
    findings_general = relationship("GeneralFinding", back_populates="incident")
    compromised_assets = relationship("Log", back_populates="incident")


class Log(Base):
    __tablename__ = "logs"

    entity_id = Column(Integer, primary_key=True)
    artifact_id = Column(Integer, ForeignKey("content_details.artifact_id"))
    machine_ip = Column(String, nullable=True)
    machine_username = Column(String, nullable=True)
    machine_name = Column(String, nullable=True)
    machine_country = Column(String, nullable=True)
    machine_locations = Column(String, nullable=True)
    machine_HWID = Column(String, nullable=True)
    malware_path = Column(String, nullable=True)
    malware_installDate = Column(DateTime, nullable=True)
    Domains_Leaked = Column(CommaSeparatedList, nullable=True)
    Leaked_cookies = Column(Integer, nullable=True)
    Leaked_Autofills = Column(Integer, nullable=True)

    incident = relationship("ContentDetails", back_populates="compromised_assets")


class UlpFinding(Base):
    __tablename__ = "ulp"
    entity_id = Column(Integer, primary_key=True)
    artifact_id = Column(Integer, ForeignKey("content_details.artifact_id"))
    email = Column(String, nullable=True)
    line_number = Column(Integer, nullable=True)
    col_start = Column(Integer, nullable=True)
    col_end = Column(Integer, nullable=True)

    incident = relationship("ContentDetails", back_populates="findings_ulp")


class GeneralFinding(Base):
    __tablename__ = "general"
    entity_id = Column(Integer, primary_key=True)
    artifact_id = Column(Integer, ForeignKey("content_details.artifact_id"))
    type = Column(String, nullable=True)
    value = Column(String, nullable=True)
    line_number = Column(Integer, nullable=True)
    col_start = Column(Integer, nullable=True)
    col_end = Column(Integer, nullable=True)

    incident = relationship("ContentDetails", back_populates="findings_general")