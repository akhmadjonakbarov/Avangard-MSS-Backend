from sqlalchemy import Column, String

from apps.base.models import Base


class Version(Base):
    __tablename__ = 'app_versions'
    version_name = Column(String)
    version_code = Column(String, nullable=True)
    download_link = Column(String)
