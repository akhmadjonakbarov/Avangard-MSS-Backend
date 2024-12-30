from sqlalchemy import Column, String, Integer, ForeignKey
from sqlalchemy.orm import relationship

from apps.base.models import Base


class CredentialModel(Base):
    __tablename__ = 'credentials'
    data = Column(String(2048), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    user = relationship('UserModel', back_populates='credentials')
