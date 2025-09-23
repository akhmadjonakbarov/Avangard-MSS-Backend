from typing import Annotated

from fastapi import Depends, HTTPException
from jose import jwt, JWTError
from core.settings import settings
from di.core_di import oauth2_bearer


async def get_current_device(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        device_code: str = payload.get('device_code')

        if device_code is None:
            raise HTTPException(status_code=403, detail="Missing token")
        return {
            'device_code': device_code,
        }
    except JWTError:
        raise HTTPException(status_code=403, detail="Invalid token")
