# Pydantic schema for Device


import re

from pydantic import BaseModel, constr, validator

SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")
ANDROID_ID_REGEX = re.compile(r"^[a-f0-9]{16}$")  # usually 16 hex chars


class DeviceRequest(BaseModel):
    device_code: str
    model: constr(min_length=2, max_length=100)
    manufacturer: constr(min_length=2, max_length=100)
    lang: constr(min_length=2, max_length=5)  # e.g., en, en-US
    android_id: str

    @validator("device_code")
    def validate_device_code(cls, v):
        if not SHA256_REGEX.match(v):
            raise ValueError("device_code must be a valid SHA-256 hex digest")
        return v.lower()

    @validator("android_id")
    def validate_android_id(cls, v):
        if not ANDROID_ID_REGEX.match(v):
            raise ValueError("android_id must be a 16-char hex string")
        return v.lower()


class DeviceResponse(DeviceRequest):
    id: int

    class Config:
        from_attributes = True
