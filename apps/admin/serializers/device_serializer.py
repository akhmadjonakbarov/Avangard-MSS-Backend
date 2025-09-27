from marshmallow import fields

from apps.base.serializers import BaseSchema


class DeviceSerializer(BaseSchema):
    device_code = fields.Str()
    model = fields.Str()
    manufacturer = fields.Str()
    lang = fields.Str()
    android_id = fields.Str()
