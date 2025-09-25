from typing import Optional

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    email: str = Field(min_length=6)
    password: str = Field(min_length=6)
    first_name: str
    last_name: str
    admin_key: Optional[str]
