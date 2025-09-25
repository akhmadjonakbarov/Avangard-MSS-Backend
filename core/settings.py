from dotenv import load_dotenv
import os
from pydantic_settings import BaseSettings


load_dotenv()

class Settings(BaseSettings):
    APP_NAME: str = "Avangard Service"
    API_V1: str = "/api/v1"
    TIME_ZONE: str = 'Asia/Tashkent'
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 120
    SECRET_KEY: str = "dd9a735175a83222d92c987aec57f4bde11f0e770b5d9ebd5803f734b290edba"
    ALGORITHM: str = "HS256"
    ADMIN_EMAIL: str = "akhmadjonakbarov@gmail.com"
    DATABASE_URL: str = os.getenv("DATABASE_URL")


    async def init(self):
        """Initialize database models (create tables)."""
        from apps.base.models import Base
        from core.database_config import engine

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)


settings = Settings()
