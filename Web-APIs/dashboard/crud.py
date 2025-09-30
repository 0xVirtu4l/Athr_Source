from typing import List, Optional

from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

import models, schemas
from collections import defaultdict


async def find_leaks_by_domains(
    db: AsyncSession, query: schemas.DomainSearchQuery
) -> List[schemas.LeakedFileInfo]:
    """
    Finds leaked files by searching for domains in associated emails and logs.
    It aggregates all findings for each unique file (artifact_id).
    """
    if not query.domains:
        return []

    # 1. Build search conditions specific to each table
    ulp_conditions = []
    general_conditions = []
    log_conditions = []
    for domain in query.domains:
        email_pattern = f"%@{domain}"
        domain_pattern = f"%{domain}%"
        ulp_conditions.append(models.UlpFinding.email.like(email_pattern))
        # Assuming emails are stored in the 'value' column of the 'general' table
        general_conditions.append(models.GeneralFinding.value.like(email_pattern))
        log_conditions.append(models.Log.Domains_Leaked.like(domain_pattern))

    # 2. Find all unique artifact_ids that match the conditions
    # We query each table separately with its own conditions to avoid cartesian products.
    ulp_ids_query = select(models.UlpFinding.artifact_id).where(or_(*ulp_conditions))
    general_ids_query = select(models.GeneralFinding.artifact_id).where(
        or_(*general_conditions)
    )
    log_ids_query = select(models.Log.artifact_id).where(or_(*log_conditions))

    matching_artifact_ids = set()
    for q in [ulp_ids_query, general_ids_query, log_ids_query]:
        result = await db.execute(q)
        for artifact_id in result.scalars().all():
            if artifact_id is not None:
                matching_artifact_ids.add(artifact_id)

    if not matching_artifact_ids:
        return []

    # 3. Fetch all content_details and related data for the matching artifacts
    final_query = (
        select(models.ContentDetails)
        .where(models.ContentDetails.artifact_id.in_(matching_artifact_ids))
        .options(
            selectinload(models.ContentDetails.findings_ulp),
            selectinload(models.ContentDetails.findings_general),
            selectinload(models.ContentDetails.compromised_assets),
        )
        .order_by(models.ContentDetails.collected_at.desc())
    )

    result = await db.execute(final_query)
    # Use .unique() to ensure each ContentDetails object is processed once
    artifacts = result.scalars().unique().all()

    # 4. Format the response
    response_list = []
    for artifact in artifacts:
        # Filter emails and logs to only include those matching the query domains
        matching_emails = {f.email for f in artifact.findings_ulp if any(f.email.endswith(f"@{d}") for d in query.domains)}
        matching_emails.update({f.value for f in artifact.findings_general if any(f.value.endswith(f"@{d}") for d in query.domains)})

        matching_logs = [schemas.CompromisedAsset.model_validate(log) for log in artifact.compromised_assets if log.Domains_Leaked and any(d in log.Domains_Leaked for d in query.domains)]

        # Create the final response object for this artifact
        leaked_file_info = schemas.LeakedFileInfo.model_validate(artifact)
        leaked_file_info.emails = sorted(list(matching_emails))
        leaked_file_info.logs = matching_logs
        response_list.append(leaked_file_info)

    return response_list