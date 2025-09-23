from apps.antivirus.models import App
from apps.base.serializers import BaseSchema
from marshmallow import fields


class MalwareSerializer(BaseSchema):
    id = fields.Int()
    name = fields.String()


class AppSerializer(BaseSchema):
    application_id = fields.String()
    malwares = fields.Method("get_malwares")

    @classmethod
    def get_malwares(cls, app: App):
        return [
            {"id": m.id, "name": m.name}
            for m in app.malwares
        ]
