from marshmallow.fields import Nested
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from .models import UserModel
from apps.base.serializer_fields import SerializerExcludeFields



class UserModelSerializer(SQLAlchemyAutoSchema):

    class Meta:
        model = UserModel
        load_instance = True
        fields = ('id', 'first_name', 'last_name', 'email') + SerializerExcludeFields.date_fields
