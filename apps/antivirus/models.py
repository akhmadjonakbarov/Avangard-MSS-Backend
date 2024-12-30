from sqlalchemy import Column, String

from apps.base.models import Base


class MalwareModel(Base):
    __tablename__ = 'malwares'
    name = Column(String, unique=True)
    sha256 = Column(String, unique=True, nullable=True)
    md5 = Column(String, unique=True, nullable=True)

    def __str__(self):
        return str(self.name)
