import uvicorn
from typing import List
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, Query
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.middleware.cors import CORSMiddleware
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

# --- CORS MIDDLEWARE SETUP ---
# origins = [
#     "http://localhost",
#     "http://localhost:8080",
#     "http://127.0.0.1:8080",
#     "http://localhost:5500", # A common port for Flutter web development
#     "http://127.0.0.1:5500",
#     "https://athr-78dc5.web.app",
#     "https://athr.pages.dev",
#     "https://athr.mohamedayman.org",
# ]

app.add_middleware(
    CORSMiddleware,
    # allow_origins=origins,
    allow_origins=["*"],  # Allow all origins for now
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
    domains: str = Query(..., description="Comma-separated list of domains to search for."),
    db: AsyncSession = Depends(get_session),
):
    """
    Searches for leaked files (`artifacts`) that contain data related to a
    given list of domains. It checks for matching emails and domain lists
    associated with each file.
    
    The domains are passed via the `domains` query parameter as a comma-separated string.
    """
    domain_list = [d.strip() for d in domains.split(",") if d.strip()]
    if not domain_list:
        return []
    query = schemas.DomainSearchQuery(domains=domain_list)
    leaks = await crud.find_leaks_by_domains(db=db, query=query)
    return leaks


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8002, reload=True)