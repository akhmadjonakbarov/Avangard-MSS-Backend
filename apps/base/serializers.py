from marshmallow import Schema
from marshmallow import fields


class BaseSchema(Schema):
    id = fields.Integer()
    created_at = fields.DateTime()
    updated_at = fields.DateTime()


class SerializerExcludeFields:
    main_fields = ('id', 'created_at', 'updated_at')
    date_fields = ('created_at', 'updated_at')
