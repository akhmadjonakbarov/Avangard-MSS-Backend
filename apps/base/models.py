from datetime import datetime

import pytz
from sqlalchemy import Integer, Column, DateTime, Boolean

from sqlalchemy.orm import as_declarative

from core.settings import settings


@as_declarative()
class Base:
    id = Column(Integer, primary_key=True, autoincrement=True)  # Shared `id` column
    is_deleted = Column(Boolean, default=False, nullable=True)
    deleted_at = Column(DateTime, nullable=True)

    # Use Tashkent timezone for created_at and updated_at
    @classmethod
    def get_tashkent_time(cls):
        timezone = pytz.timezone(settings.TIME_ZONE)
        return datetime.now(timezone)

    created_at = Column(DateTime, default=lambda: Base.get_tashkent_time())
    updated_at = Column(DateTime, default=lambda: Base.get_tashkent_time(),
                        onupdate=lambda: Base.get_tashkent_time())

    def soft_delete(self):
        self.is_deleted = True
        self.deleted_at = self.get_tashkent_time()
