from pydantic import BaseModel


class CredentialRequestBody(BaseModel):
    credential_data: str
    id: int
