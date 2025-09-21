import uvicorn
from typing import List, Optional
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.responses import Response

import crud, schemas
from database import get_session, create_db_and_tables



@asynccontextmanager
async def lifespan(app: FastAPI):
    # On startup, create database tables
    await create_db_and_tables()
    yield


# Instantiate the FastAPI application
app = FastAPI(
    title="Security Dashboard API",
    description="An asynchronous API to serve security incident data.",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get('/favicon.ico', include_in_schema=False)
async def favicon():
    return Response(status_code=204)


@app.get(
    "/dashboard/stats",
    response_model=schemas.DashboardStats,
    tags=["Dashboard"],
    summary="Get high-level dashboard statistics",
)
async def read_dashboard_stats(
    db: AsyncSession = Depends(get_session),
):
    """
    Retrieve aggregated statistics for the main dashboard, such as new incidents,
    criticality counts, and total compromised assets.
    """
    return await crud.get_dashboard_stats(db)


@app.get(
    "/incidents",
    response_model=List[schemas.IncidentSummary],
    tags=["Incidents"],
    summary="Get a list of incidents with filtering and pagination",
)
async def read_incidents(
    severity: Optional[str] = None,
    category: Optional[str] = None,
    source: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_session),
):
    """
    Retrieve a list of incidents. Supports filtering by severity, category, and source,
    as well as pagination using skip and limit parameters.
    """
    incidents = await crud.get_incidents(
        db, skip=skip, limit=limit, severity=severity, category=category, source=source
    )
    return incidents


@app.get(
    "/incidents/{incident_id}",
    response_model=schemas.Incident,
    tags=["Incidents"],
    summary="Get a single incident by its ID",
)
async def read_incident(
    incident_id: int, db: AsyncSession = Depends(get_session)
):
    """
    Retrieve the full details for a single incident by its unique artifact_id,
    including all associated findings and compromised asset information.
    """
    db_incident = await crud.get_incident_by_id(db, incident_id=incident_id)
    if db_incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return db_incident


@app.post(
    "/search",
    response_model=List[schemas.IncidentWithFindingsSummary],
    tags=["Search"],
    summary="Search for incidents based on organizational assets",
)
async def search_org_incidents(
    query: schemas.SearchQuery,
    db: AsyncSession = Depends(get_session),
):
    """
    Searches for incidents that match a given set of organizational assets,
    including domains, IP ranges, and keywords.
    """
    incidents = await crud.find_incidents_by_assets(db=db, query=query)
    return incidents


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)