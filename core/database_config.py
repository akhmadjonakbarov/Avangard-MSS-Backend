from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import sessionmaker, declarative_base
from core.settings import settings

# Use async engine
engine = create_async_engine(
    settings.DATABASE_URL,  # e.g. "postgresql+asyncpg://user:pass@localhost:5432/db"
    echo=True,
    future=True,
)

# Session factory for async
AsyncSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)

async_session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)

Base = declarative_base()

# Dependency for FastAPI
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session
