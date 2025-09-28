from pydantic import BaseModel
from typing import Optional


# Request schema (for create/update)
class VersionRequest(BaseModel):
    version_name: str
    version_code: Optional[str] = None
    download_link: str


# Response schema (for reading from DB)
class VersionResponse(VersionRequest):
    id: int

    class Config:
        from_attributes = True   # ✅ allows ORM objects to be converted automatically
