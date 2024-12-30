from pydantic import BaseModel, Field


class CreateUserRequest(BaseModel):
    first_name: str = Field(min_length=4)
    last_name: str = Field(min_length=4)
    password: str = Field(min_length=6)
    email: str



