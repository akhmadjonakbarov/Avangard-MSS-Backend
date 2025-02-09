from sqlalchemy import Column, String, Boolean
from sqlalchemy.orm import relationship

from apps.base.models import Base


class User(Base):
    __tablename__ = 'users'

    first_name = Column(String(length=30))
    last_name = Column(String(length=30))
    is_active = Column(Boolean, default=True)
    email = Column(String(length=100), unique=True)
    password = Column(String, nullable=False)

    credentials = relationship('Credential', back_populates='user')
