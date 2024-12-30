from pydantic import BaseModel


class CredentialRequestBody(BaseModel):
    data: str
