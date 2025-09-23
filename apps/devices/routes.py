from typing import List
from fastapi import APIRouter, HTTPException, status

from sqlalchemy import select

from core.security import create_access_token_for_device
from di.db import db_dependency
from di.device import device_dependency
from .models import Device
from .schemes import DeviceCreate, DeviceResponse

router = APIRouter(
    prefix='/devices',
    tags=['Device Manager']
)


# Create a new device
@router.post("/add", status_code=status.HTTP_201_CREATED)
async def create_device(
        db: db_dependency,
        device: DeviceCreate,

):
    try:
        async with db.begin():
            result = await db.execute(
                select(Device).where(Device.device_code == device.device_code)
            )
            db_device = result.scalar_one_or_none()

            if db_device:
                token = create_access_token_for_device(db_device.device_code)
                return {'access_token': token}

            new_device = Device(**device.dict())
            db.add(new_device)

        await db.refresh(new_device)
        token = create_access_token_for_device(new_device.device_code)
        return {'access_token': token}

    except HTTPException:
        raise
    except Exception as e:
        print(e)
        raise HTTPException(detail=str(e), status_code=400)


# Get all devices
@router.get("/all", response_model=List[DeviceResponse], status_code=status.HTTP_200_OK)
async def get_devices(
        db: db_dependency,
        device: device_dependency
):
    result = await db.execute(select(Device))
    devices = result.scalars().all()
    return devices


# Update a device
@router.patch("/update/{device_id}", response_model=DeviceResponse)
async def update_device(
        db: db_dependency,

        device_id: int,
        updated_device: DeviceCreate,

):
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    for key, value in updated_device.dict().items():
        setattr(device, key, value)

    await db.commit()
    await db.refresh(device)
    return device


# Delete a device
@router.delete("/delete/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(
        db: db_dependency,

        device_id: int,

):
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    await db.delete(device)
    await db.commit()
    return {"message": "Device deleted successfully"}
