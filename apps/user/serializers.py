from marshmallow.fields import Nested
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from .models import User
from apps.base.serializers import SerializerExcludeFields


class UserModelSerializer(SQLAlchemyAutoSchema):

    class Meta:
        model = User
        load_instance = True
        fields = ('id', 'first_name', 'last_name', 'email') + \
            SerializerExcludeFields.date_fields
