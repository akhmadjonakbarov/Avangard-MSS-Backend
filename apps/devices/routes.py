from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from core.security import create_access_token_for_device
from di.db import db_dependency
from .models import Device
from .schemes import DeviceRequest

router = APIRouter(
    prefix='/devices',
    tags=['Device Manager']
)


@router.post("/add", status_code=status.HTTP_201_CREATED)
async def create_device(
        db: db_dependency,
        device: DeviceRequest,
):
    try:
        # Check if device already exists
        result = await db.execute(
            select(Device).where(Device.device_code == device.device_code)
        )
        db_device = result.scalar_one_or_none()

        if db_device:
            token = create_access_token_for_device(db_device.device_code)
            return {"access_token": token}

        # Create new device
        new_device = Device(**device.model_dump())
        db.add(new_device)
        await db.commit()  # commit transaction
        await db.refresh(new_device)  # refresh to get ID, etc.

        token = create_access_token_for_device(new_device.device_code)
        return {"access_token": token}

    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error: " + str(e),
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
