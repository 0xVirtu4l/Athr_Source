import asyncio
from datetime import datetime, timedelta
from typing import List, Optional
import ipaddress

from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

import models, schemas


async def get_dashboard_stats(db: AsyncSession) -> schemas.DashboardStats:
    """
    Asynchronously runs four separate COUNT queries to calculate statistics
    for the main dashboard view.
    """
    seven_days_ago = datetime.utcnow() - timedelta(days=7)

    new_incidents_query = db.execute(
        select(func.count(models.ContentDetails.artifact_id)).where(
            models.ContentDetails.collected_at >= seven_days_ago
        )
    )
    critical_high_query = db.execute(
        select(func.count(models.ContentDetails.artifact_id)).where(
            models.ContentDetails.severity.in_(["Critical", "High"])
        )
    )
    compromised_machines_query = db.execute(
        select(func.count(func.distinct(models.Log.machine_name)))
    )
    leaked_credentials_query = db.execute(
        select(func.count(models.ContentDetails.artifact_id)).where(
            models.ContentDetails.category == "Leaked Credentials"
        )
    )

    # Run all queries concurrently for better performance
    results = await asyncio.gather(
        new_incidents_query,
        critical_high_query,
        compromised_machines_query,
        leaked_credentials_query,
    )

    new_incidents_count = results[0].scalar_one()
    critical_high_count = results[1].scalar_one()
    compromised_machines_count = results[2].scalar_one()
    leaked_credentials_count = results[3].scalar_one()

    # Return the populated Pydantic model
    return schemas.DashboardStats(
        new_incidents_7_days=new_incidents_count,
        critical_high_incidents=critical_high_count,
        compromised_machines=compromised_machines_count,
        leaked_credentials=leaked_credentials_count,
    )


async def get_incidents(
    db: AsyncSession,
    skip: int,
    limit: int,
    severity: Optional[str],
    category: Optional[str],
    source: Optional[str],
) -> List[schemas.IncidentSummary]:
    """
    Fetches a paginated and filtered list of incidents.
    Uses SQLAlchemy ORM for dynamic filtering and pagination.
    """
    query = select(models.ContentDetails)

    # Dynamically add WHERE clauses for active filters
    if severity:
        query = query.where(models.ContentDetails.severity == severity)
    if category:
        query = query.where(models.ContentDetails.category == category)
    if source:
        query = query.where(models.ContentDetails.source == source)

    # Add ordering and pagination
    query = query.order_by(models.ContentDetails.collected_at.desc()).offset(skip).limit(limit)

    result = await db.execute(query)
    incidents = result.scalars().all()

    # Manually create the summary objects to ensure all fields are present
    return [
        schemas.IncidentSummary.model_validate(inc)
        for inc in incidents
    ]


async def get_incident_by_id(
    db: AsyncSession, incident_id: int
) -> Optional[schemas.Incident]:
    """
    Fetches a single, complete incident by its ID, including all related
    findings and compromised asset data from multiple tables.
    """
    query = (
        select(models.ContentDetails)
        .where(models.ContentDetails.artifact_id == incident_id)
        .options(
            selectinload(models.ContentDetails.findings_ulp),
            selectinload(models.ContentDetails.findings_general),
            selectinload(models.ContentDetails.compromised_assets),
        )
    )

    result = await db.execute(query)
    incident = result.scalar_one_or_none()

    if not incident:
        return None

    # Process findings from the 'ulp' table (emails)
    all_findings = [
        schemas.Finding(type="email", value=f.email, line_number=f.line_number)
        for f in incident.findings_ulp
    ]
    # Process and add findings from the 'general' table
    all_findings.extend(
        [schemas.Finding.model_validate(f) for f in incident.findings_general]
    )

    # The 'incident' object from SQLAlchemy now contains all necessary data
    # due to `selectinload`. We can build the final Pydantic model from it.
    incident_data = schemas.Incident.model_validate(incident).model_dump()
    incident_data["findings"] = all_findings
    incident_data["compromised_assets"] = [schemas.CompromisedAsset.model_validate(asset) for asset in incident.compromised_assets]

    return schemas.Incident.model_validate(incident_data)


async def find_incidents_by_assets(
    db: AsyncSession, query: schemas.SearchQuery
) -> List[schemas.IncidentWithFindingsSummary]:
    """
    Finds incidents by searching for organizational assets (domains, IPs, keywords)
    across multiple tables and returns a summary of matching incidents.
    """
    matching_artifact_ids = set()

    # 1. Search by Domains
    if query.domains:
        domain_conditions = []
        for domain in query.domains:
            # Match suffix of email addresses and domain-like values
            pattern = f"%{domain}"
            domain_conditions.extend([
                models.UlpFinding.email.like(pattern),
                models.GeneralFinding.value.like(pattern),
                models.Log.Domains_Leaked.like(pattern),
            ])

        if domain_conditions:
            # Query all tables that might contain domain info
            domain_search_query = select(
                models.UlpFinding.artifact_id,
                models.GeneralFinding.artifact_id,
                models.Log.artifact_id
            ).join(models.ContentDetails, models.UlpFinding.artifact_id == models.ContentDetails.artifact_id, isouter=True) \
            .join(models.GeneralFinding, models.GeneralFinding.artifact_id == models.ContentDetails.artifact_id, isouter=True) \
            .join(models.Log, models.Log.artifact_id == models.ContentDetails.artifact_id, isouter=True) \
            .where(or_(*domain_conditions))

            result = await db.execute(domain_search_query)
            for row in result.all():
                for artifact_id in row:
                    if artifact_id is not None:
                        matching_artifact_ids.add(artifact_id)

    # 2. Search by IP Ranges (CIDR)
    if query.ip_ranges:
        # Since SQLite doesn't support CIDR matching, we fetch IPs and check in Python.
        # NOTE: This could be slow on very large 'logs' tables.
        # In a production system with a different DB (e.g., PostgreSQL),
        # this could be done with native CIDR types and operators.
        try:
            networks = [ipaddress.ip_network(ip_range, strict=False) for ip_range in query.ip_ranges]
            if networks:
                ip_query = select(models.Log.artifact_id, models.Log.machine_ip)
                result = await db.execute(ip_query)
                for artifact_id, machine_ip_str in result.all():
                    if not machine_ip_str:
                        continue
                    try:
                        addr = ipaddress.ip_address(machine_ip_str)
                        if any(addr in net for net in networks):
                            matching_artifact_ids.add(artifact_id)
                    except ValueError:
                        continue  # Ignore invalid IP addresses in the database
        except ValueError:
            # Ignore invalid CIDR ranges in the query
            pass

    # 3. Search by Keywords
    if query.keywords:
        keyword_conditions = []
        for keyword in query.keywords:
            pattern = f"%{keyword}%"
            keyword_conditions.extend([
                models.ContentDetails.source_path.like(pattern),
                models.ContentDetails.original_filename.like(pattern),
                models.GeneralFinding.value.like(pattern),
                models.Log.machine_username.like(pattern),
                models.Log.machine_name.like(pattern),
                models.Log.malware_path.like(pattern),
            ])

        if keyword_conditions:
            keyword_search_query = select(models.ContentDetails.artifact_id).distinct().where(
                or_(
                    models.ContentDetails.artifact_id == models.GeneralFinding.artifact_id,
                    models.ContentDetails.artifact_id == models.Log.artifact_id
                )
            ).where(or_(*keyword_conditions))

            result = await db.execute(keyword_search_query)
            for row in result.scalars().all():
                matching_artifact_ids.add(row)

    # 4. Final Query
    if not matching_artifact_ids:
        return []

    final_query = select(models.ContentDetails).where(
        models.ContentDetails.artifact_id.in_(matching_artifact_ids)
    ).options(
        selectinload(models.ContentDetails.findings_ulp),
        selectinload(models.ContentDetails.findings_general),
    ).order_by(models.ContentDetails.collected_at.desc())

    result = await db.execute(final_query)
    incidents = result.scalars().all()

    # 5. Return Results
    results_with_findings = []
    for incident in incidents:
        # Process findings from the 'ulp' table (emails)
        all_findings = [
            schemas.Finding(type="email", value=f.email, line_number=f.line_number)
            for f in incident.findings_ulp
        ]
        # Process and add findings from the 'general' table
        all_findings.extend(
            [schemas.Finding.model_validate(f) for f in incident.findings_general]
        )

        summary = schemas.IncidentWithFindingsSummary.model_validate(incident)
        summary.findings = all_findings
        results_with_findings.append(summary)

    return results_with_findings