import enum
import hashlib
from apps.base.models import Base
from sqlalchemy import Column, Integer, String, ForeignKey, Table, LargeBinary, Enum, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

# Many-to-many: Apps <-> Malwares
app_malware = Table(
    "app_malware",
    Base.metadata,
    Column("app_id", Integer, ForeignKey("apps.id"), primary_key=True),
    Column("malware_id", Integer, ForeignKey("malwares.id"), primary_key=True),
)


class ScanStatus(str):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class App(Base):
    __tablename__ = 'apps'

    id = Column(Integer, primary_key=True, autoincrement=True)
    application_id = Column(String, unique=True)  # Android package name
    file_hash = Column(String(64), nullable=True, index=True)  # SHA-256 hash
    total_engines = Column(Integer, nullable=True)
    malicious_count = Column(Integer, default=0)
    suspicious_count = Column(Integer, default=0)
    harmless_count = Column(Integer, default=0)
    undetected_count = Column(Integer, default=0)
    scan_date = Column(DateTime, nullable=True)
    malwares = relationship("Malware", secondary=app_malware, back_populates="apps", lazy="selectin")


class Malware(Base):
    __tablename__ = 'malwares'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String)  # file name or signature
    category = Column(String, nullable=True)  # malicious, suspicious
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
    method = Column(String, nullable=True)
    category = Column(String)  # malicious, undetected, harmless, suspicious
    result = Column(String, nullable=True)  # e.g. Trojan.AndroidOS.SmsSpy.C!c
    file_hash = Column(String(64), nullable=True, index=True)  # SHA-256 hash of scanned file
    malware_id = Column(Integer, ForeignKey("malwares.id"))
    malware = relationship("Malware", back_populates="detections")


class ScanTask(Base):
    __tablename__ = "scan_tasks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    application_id = Column(String, nullable=False)
    file_bytes = Column(LargeBinary, nullable=False)
    scanning_hash = Column(String(64), nullable=True, index=True)  # SHA-256 hash
    status = Column(String, nullable=False, default=ScanStatus.PENDING)
    device_code = Column(String, nullable=True)

    def calculate_hash(self) -> str:
        """Calculate SHA-256 hash of file_bytes."""
        return hashlib.sha256(self.file_bytes).hexdigest()
