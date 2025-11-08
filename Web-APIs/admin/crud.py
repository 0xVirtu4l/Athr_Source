import aiosqlite
import json
from typing import List
import schemas


async def get_admin_stats(db: aiosqlite.Connection) -> schemas.Stats:
    """
    Get dashboard statistics (total counts for organizations, users, and incidents).
    
    Args:
        db: Async SQLite database connection
        
    Returns:
        schemas.Stats: Statistics object with total counts
    """
    # Count organizations
    cursor = await db.execute("SELECT COUNT(*) FROM organizations")
    total_organizations = (await cursor.fetchone())[0]
    await cursor.close()
    
    # Count users
    cursor = await db.execute("SELECT COUNT(*) FROM users")
    total_users = (await cursor.fetchone())[0]
    await cursor.close()
    
    # Count incidents
    cursor = await db.execute("SELECT COUNT(*) FROM incident_reports")
    total_incidents = (await cursor.fetchone())[0]
    await cursor.close()
    
    return schemas.Stats(
        total_organizations=total_organizations,
        total_users=total_users,
        total_incidents=total_incidents
    )


async def get_organizations(db: aiosqlite.Connection) -> List[schemas.Organization]:
    """
    Get all organizations with calculated user and incident counts.
    
    Args:
        db: Async SQLite database connection
        
    Returns:
        List[schemas.Organization]: List of all organizations with counts
    """
    organizations = []
    
    # Get all organizations
    cursor = await db.execute("SELECT * FROM organizations")
    org_rows = await cursor.fetchall()
    await cursor.close()
    
    for org_row in org_rows:
        org_id = org_row["org_id"]
        
        # Count users for this organization
        user_cursor = await db.execute(
            "SELECT COUNT(*) FROM users WHERE org_id = ?",
            (org_id,)
        )
        user_count = (await user_cursor.fetchone())[0]
        await user_cursor.close()
        
        # Count incidents for this organization
        incident_cursor = await db.execute(
            "SELECT COUNT(*) FROM incident_reports WHERE org_id = ?",
            (org_id,)
        )
        incident_count = (await incident_cursor.fetchone())[0]
        await incident_cursor.close()
        
        # Parse JSON fields
        domains = json.loads(org_row["domains"])
        ip_ranges = json.loads(org_row["ip_ranges"])
        keywords = json.loads(org_row["keywords"])
        
        # Create organization object
        org = schemas.Organization(
            org_id=org_row["org_id"],
            name=org_row["name"],
            plan=org_row["plan"],
            domains=domains,
            ip_ranges=ip_ranges,
            keywords=keywords,
            created_at=org_row["created_at"],
            user_count=user_count,
            incident_count=incident_count
        )
        organizations.append(org)
    
    return organizations


async def get_users_for_organization(
    db: aiosqlite.Connection, 
    org_id: str
) -> List[schemas.User]:
    """
    Get all users for a specific organization.
    
    Args:
        db: Async SQLite database connection
        org_id: Organization ID to filter users
        
    Returns:
        List[schemas.User]: List of users belonging to the organization
    """
    users = []
    
    cursor = await db.execute(
        "SELECT * FROM users WHERE org_id = ?",
        (org_id,)
    )
    user_rows = await cursor.fetchall()
    await cursor.close()
    
    for user_row in user_rows:
        user = schemas.User(
            user_id=user_row["user_id"],
            org_id=user_row["org_id"],
            full_name=user_row["full_name"],
            email=user_row["email"],
            role=user_row["role"],
            created_at=user_row["created_at"],
            last_login=user_row["last_login"],
            account_status=user_row["account_status"],
            last_login_ip=user_row["last_login_ip"],
            auth_provider=user_row["auth_provider"],
            last_activity_at=user_row["last_activity_at"],
            login_count=user_row["login_count"],
            incident_reports_viewed=user_row["incident_reports_viewed"],
            is_billing_contact=bool(user_row["is_billing_contact"])
        )
        users.append(user)
    
    return users
