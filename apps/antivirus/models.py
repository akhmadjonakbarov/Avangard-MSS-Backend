import enum

from apps.base.models import Base

from sqlalchemy import Column, Integer, String, ForeignKey, Table, LargeBinary, Enum
from sqlalchemy.orm import relationship

# Many-to-many: Apps <-> Malwares
app_malware = Table(
    "app_malware",
    Base.metadata,
    Column("app_id", Integer, ForeignKey("apps.id"), primary_key=True),
    Column("malware_id", Integer, ForeignKey("malwares.id"), primary_key=True),
)


class App(Base):
    __tablename__ = 'apps'

    id = Column(Integer, primary_key=True, autoincrement=True)
    application_id = Column(String, unique=True)  # Android package name

    malwares = relationship("Malware", secondary=app_malware, back_populates="apps", lazy="selectin")


class Malware(Base):
    __tablename__ = 'malwares'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String)  # file name or signature
    sha256 = Column(String, unique=True, nullable=True)
    md5 = Column(String, unique=True, nullable=True)

    apps = relationship("App", secondary=app_malware, back_populates="malwares")
    detections = relationship("Detection", back_populates="malware", cascade="all, delete-orphan")

    def __str__(self):
        return str(self.name)


class Detection(Base):
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True, autoincrement=True)
    engine_name = Column(String)
    engine_version = Column(String, nullable=True)
    category = Column(String)  # malicious, undetected, harmless, suspicious
    result = Column(String, nullable=True)  # e.g. Trojan.AndroidOS.SmsSpy.C!c
    malware_id = Column(Integer, ForeignKey("malwares.id"))
    malware = relationship("Malware", back_populates="detections")


class ScanStatus(str):
    pending = "pending"
    processing = "processing"
    completed = "completed"
    failed = "failed"
    timeout = "timeout"


class ScanTask(Base):
    __tablename__ = "scan_tasks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    application_id = Column(String, nullable=False)
    file_bytes = Column(LargeBinary, nullable=False)
    status = Column(String, nullable=False, default=ScanStatus.pending)
