import aiosqlite

DATABASE_URL = "admin_mock.db"


async def get_db_connection():
    """
    FastAPI dependency for getting an async database connection.
    Yields a connection with row_factory set to aiosqlite.Row for dict-like access.
    """
    db = await aiosqlite.connect(DATABASE_URL)
    try:
        db.row_factory = aiosqlite.Row
        yield db
    finally:
        await db.close()
