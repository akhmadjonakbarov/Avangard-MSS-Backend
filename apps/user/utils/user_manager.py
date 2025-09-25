from typing import Annotated

from fastapi import Depends, HTTPException
from jose import jwt, JWTError
from core.settings import settings
from di.core_di import oauth2_bearer


async def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email: str = payload.get('email')
        user_id: int = payload.get('id')
        is_admin: bool = payload.get('is_admin')
        if user_id is None or email is None:
            raise HTTPException(status_code=403, detail="Missing token")
        return {
            'email': email,
            'id': user_id, 'is_admin': is_admin
        }
    except JWTError:
        raise HTTPException(status_code=403, detail="Invalid token")


async def get_admin(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email: str = payload.get('email')
        user_id: int = payload.get('id')
        is_admin: bool = payload.get('is_admin')
        if user_id is None or email is None:
            raise HTTPException(status_code=403, detail="Missing token")
        if is_admin is None or is_admin is False:
            raise HTTPException(status_code=403, detail="You are not admin")
        return {
            'email': email,
            'id': user_id, 'is_admin': is_admin
        }
    except JWTError:
        raise HTTPException(status_code=403, detail="Invalid token")
