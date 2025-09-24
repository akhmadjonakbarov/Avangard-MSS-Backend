from apps.antivirus.models import App
from apps.base.serializers import BaseSchema
from marshmallow import fields


class MalwareSerializer(BaseSchema):
    id = fields.Int()
    name = fields.String()
    category = fields.String()


class AppSerializer(BaseSchema):
    application_id = fields.String()
    file_hash = fields.String()
    total_engines = fields.Int()
    malicious_count = fields.Int()
    suspicious_count = fields.Int()
    harmless_count = fields.Int()
    undetected_count = fields.Int()
    scan_date = fields.DateTime()
    created_at = fields.DateTime()
    malwares = fields.Method("get_malwares")

    @classmethod
    def get_malwares(cls, app: App):
        return [
            {"id": m.id, "name": m.name, "category": m.category}
            for m in app.malwares
        ]


class ScanTaskSerializer(BaseSchema):
    id = fields.Int()
    application_id = fields.String()
    file_bytes = fields.String()
    scanning_hash = fields.String()
    status = fields.String()
    device_code = fields.String()
