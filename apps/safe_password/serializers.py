from marshmallow import Schema, fields

from apps import Credential


class CredentialSerializer(Schema):
    credential_data = fields.Method("get_credential_data")
    id = fields.Int()

    def get_credential_data(self, obj: Credential):
        return obj.data
