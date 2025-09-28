from marshmallow import fields

from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

from apps.base.serializers import BaseSchema


class DeviceSerializer(BaseSchema):
    device_code = fields.Str()
    model = fields.Str()
    manufacturer = fields.Str()
    lang = fields.Str()
    android_id = fields.Str()


class DetectionBase(BaseModel):
    engine_name: str
    engine_version: Optional[str] = None
    method: Optional[str] = None
    category: str
    result: Optional[str] = None
    file_hash: Optional[str] = None

class DetectionCreate(DetectionBase):
    malware_id: Optional[int] = None

class DetectionRead(DetectionBase):
    id: int
    class Config:
        orm_mode = True


class MalwareBase(BaseModel):
    name: str
    category: Optional[str] = None
    sha256: Optional[str] = None
    md5: Optional[str] = None

class MalwareCreate(MalwareBase):
    pass

class MalwareRead(MalwareBase):
    id: int

    class Config:
        orm_mode = True


class AppBase(BaseModel):
    application_id: str
    file_hash: Optional[str] = None
    total_engines: Optional[int] = None
    malicious_count: Optional[int] = 0
    suspicious_count: Optional[int] = 0
    harmless_count: Optional[int] = 0
    undetected_count: Optional[int] = 0
    scan_date: Optional[datetime] = None

class AppCreate(AppBase):
    malware_ids: List[int] = []  # ✅ admin can attach multiple malwares

class AppRead(AppBase):
    id: int
    malwares: List[MalwareRead] = []
    class Config:
        orm_mode = True
