from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from typing import List
import uvicorn
import aiosqlite
import os
from dotenv import load_dotenv
from pydantic import EmailStr

import crud
import schemas
from database import get_db_connection

# Load environment variables
load_dotenv()

# Load admin emails from environment variable
ADMIN_EMAILS_STR = os.environ.get("ADMIN_EMAILS", "")
admin_email_set = set(email.strip() for email in ADMIN_EMAILS_STR.split(',') if email.strip())

# Create FastAPI app instance
app = FastAPI(
    title="Admin API",
    description="Admin dashboard API for managing organizations, users, and incidents",
    version="1.0.0"
)

# Add CORS middleware for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/is-admin", response_model=schemas.AdminStatus)
async def check_admin_status(email: EmailStr):
    """
    Public endpoint to check if an email belongs to an admin.
    Does not require database access.
    
    Args:
        email: Email address to check
        
    Returns:
        schemas.AdminStatus: Object with is_admin boolean field
    """
    is_admin = str(email).lower() in {e.lower() for e in admin_email_set}
    return schemas.AdminStatus(is_admin=is_admin)


@app.get("/admin/stats", response_model=schemas.Stats)
async def get_stats(db: aiosqlite.Connection = Depends(get_db_connection)):
    """
    Get dashboard statistics including total counts for organizations, users, and incidents.
    
    Returns:
        schemas.Stats: Dashboard statistics
    """
    return await crud.get_admin_stats(db)


@app.get("/admin/organizations", response_model=List[schemas.Organization])
async def get_organizations(db: aiosqlite.Connection = Depends(get_db_connection)):
    """
    Get all organizations with their user counts and incident counts.
    
    Returns:
        List[schemas.Organization]: List of all organizations
    """
    return await crud.get_organizations(db)


@app.get("/admin/organizations/{org_id}/users", response_model=List[schemas.User])
async def get_organization_users(
    org_id: str,
    db: aiosqlite.Connection = Depends(get_db_connection)
):
    """
    Get all users for a specific organization.
    
    Args:
        org_id: Organization ID
        
    Returns:
        List[schemas.User]: List of users belonging to the organization
    """
    return await crud.get_users_for_organization(db, org_id)


@app.get("/admin/organizations/{org_id}/incidents", response_model=List[schemas.IncidentReport])
async def get_organization_incidents(
    org_id: str,
    db: aiosqlite.Connection = Depends(get_db_connection)
):
    """
    Get all incident reports for a specific organization.
    
    Args:
        org_id: Organization ID
        
    Returns:
        List[schemas.IncidentReport]: List of incident reports belonging to the organization, ordered by collected_at (newest first)
    """
    return await crud.get_incident_reports_for_organization(db, org_id)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8003)
