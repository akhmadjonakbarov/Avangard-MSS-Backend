# Pydantic schema for Device
from pydantic import BaseModel


class DeviceCreate(BaseModel):
    device_code: str
    model: str
    manufacturer: str
    lang: str
    android_id: str


class DeviceResponse(DeviceCreate):
    id: int

    class Config:
        from_attributes = True
