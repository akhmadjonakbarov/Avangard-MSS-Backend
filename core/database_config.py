from typing import Generator
from databases import Database
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from core.settings import settings

# Create a Database instance
database = Database(settings.DATABASE_URL)

engine = create_engine(
    settings.DATABASE_URL
)

SessionLocal = sessionmaker(
    autoflush=False, autocommit=False, bind=engine
)


def db_init() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
