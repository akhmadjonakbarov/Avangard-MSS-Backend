from sqlalchemy import Column, String, Boolean

from apps.base.models import Base


class User(Base):
    __tablename__ = 'users'

    first_name = Column(String(length=30))
    last_name = Column(String(length=30))
    is_active = Column(Boolean, default=True)
    email = Column(String(length=100), unique=True)
    password = Column(String, nullable=False)
    is_admin = Column(Boolean, nullable=True, default=False)

    def __str__(self):
        return f"User: {self.first_name} {self.last_name} is_admin:{self.is_admin}"
