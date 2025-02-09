from pydantic_settings import BaseSettings
from dotenv import load_dotenv

import os

load_dotenv()


class Settings(BaseSettings):
    APP_NAME: str = "Avangard Service"
    API_V1: str = "/api/v1"
    TIME_ZONE: str = 'Asia/Tashkent'
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 120
    SECRET_KEY: str = "dd9a735175a83222d92c987aec57f4bde11f0e770b5d9ebd5803f734b290edba"
    ALGORITHM: str = "HS256"
    ADMIN_EMAIL: str = "akhmadjonakbarov@gmail.com"
    DATABASE_URL: str = os.getenv('DATABASE_URL')

    def init(self):
        from apps.base.models import Base
        from core.database_config import engine
        Base.metadata.create_all(bind=engine)


settings = Settings()
