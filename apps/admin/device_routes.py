from typing import List

from fastapi import APIRouter, HTTPException
from sqlalchemy import select
from starlette import status
from yaml import serialize

from apps import Device
from apps.admin.serializers.device_serializer import DeviceSerializer
from apps.devices.schemes import DeviceResponse
from di.db import db_dependency
from di.user import admin_dependency

router = APIRouter()

from typing import Any, Dict
from fastapi import Query
from sqlalchemy import func


@router.get('', response_model=Dict[str, Any])
async def get_devices(
        db: db_dependency,
        user: admin_dependency,
        page: int = Query(1, ge=1, description="Page number"),
        page_size: int = Query(10, ge=1, le=100, description="Items per page"),
):
    try:
        # total count
        total_result = await db.execute(select(func.count()).select_from(Device))
        total = total_result.scalar_one()

        # calculate offset
        offset = (page - 1) * page_size

        # fetch devices
        result = await db.execute(
            select(Device).offset(offset).limit(page_size)
        )
        devices = result.scalars().all()

        serialized_devices = DeviceSerializer(many=True)

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": (total + page_size - 1) // page_size,
            "devices": serialized_devices.dump(devices),
        }
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
