from typing import List

from fastapi import APIRouter, HTTPException
from sqlalchemy import select
from starlette import status

from apps import Device
from apps.devices.schemes import DeviceResponse
from di.db import db_dependency
from di.user import admin_dependency

router = APIRouter()


@router.get('', response_model=List[DeviceResponse])
async def get_devices(
        db: db_dependency,
        user: admin_dependency
):
    try:
        result = await db.execute(select(Device))
        devices = result.scalars().all()
        return devices
    except Exception as e:
        print(e)
        return {
            "detail": str(e)
        }


@router.delete("/delete/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(
        db: db_dependency,
        user: admin_dependency,
        device_id: int,

):
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    await db.delete(device)
    await db.commit()
    return {"message": "Device deleted successfully"}
