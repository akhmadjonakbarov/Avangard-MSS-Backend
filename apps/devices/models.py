from apps.base.models import Base
from sqlalchemy import Column, Integer, String


class Device(Base):
    __tablename__ = 'devices'

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_code = Column(String, nullable=False, unique=True)
    model = Column(String, nullable=False)
    manufacturer = Column(String, nullable=False)
    lang = Column(String, nullable=False)
    android_id = Column(String, nullable=False, unique=True)

    def __repr__(self):
        return f"<Device(id={self.id}, device_code={self.device_code}, model={self.model})>"
