from typing import AsyncGenerator
from pathlib import Path

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from models import Base

# The database file is in the same directory as this script.
# We construct an absolute path to it to avoid issues with the current working directory.
DATABASE_FILE = "athr_demo_test.db"
SQLALCHEMY_DATABASE_URL = f"sqlite+aiosqlite:///{Path(__file__).parent / DATABASE_FILE}"

engine = create_async_engine(SQLALCHEMY_DATABASE_URL)

async_session_maker = async_sessionmaker(engine, expire_on_commit=False)


async def create_db_and_tables():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that provides an asynchronous database connection.

    It creates a new SQLAlchemy session for each request, and ensures
    it is closed after the request is finished.
    """
    async with async_session_maker() as session:
        yield session