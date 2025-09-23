from datetime import datetime, timedelta

from jose import jwt
from passlib.context import CryptContext

from core.settings import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def create_access_token(
        email: str, user_id: int,
        expires_delta: timedelta = timedelta(settings.ACCESS_TOKEN_EXPIRE_MINUTES)
) -> str:
    encode = {
        'email': email,
        'id': user_id
    }
    expires = datetime.utcnow() + expires_delta
    encode.update({
        'exp': expires.timestamp()
    })
    return jwt.encode(
        encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )


def create_access_token_for_device(
        device_code: str,
        expires_delta: timedelta = timedelta(settings.ACCESS_TOKEN_EXPIRE_MINUTES)
) -> str:
    encode = {
        'device_code': device_code,

    }
    expires = datetime.utcnow() + expires_delta
    encode.update({
        'exp': expires.timestamp()
    })
    return jwt.encode(
        encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)
