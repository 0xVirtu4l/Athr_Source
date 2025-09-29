import uvicorn
from typing import List
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI
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
    title="Leaked File Search API",
    description="An API to search for leaked files containing specific domains.",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get('/favicon.ico', include_in_schema=False)
async def favicon():
    return Response(status_code=204)


@app.get(
    "/search/domains",
    response_model=List[schemas.LeakedFileInfo],
    tags=["Search"],
    summary="Search for leaked files by domain",
)
async def search_leaks_by_domain(
    query: schemas.DomainSearchQuery,
    db: AsyncSession = Depends(get_session),
):
    """
    Searches for leaked files (`artifacts`) that contain data related to a
    given list of domains. It checks for matching emails and domain lists
    associated with each file.
    """
    leaks = await crud.find_leaks_by_domains(db=db, query=query)
    return leaks


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8002, reload=True)