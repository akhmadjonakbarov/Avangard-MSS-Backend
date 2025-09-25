from typing import List

from fastapi import APIRouter
from sqlalchemy import select

from apps.antivirus.models import ScanTask
from apps.antivirus.serializers import ScanTaskSerializer
from apps.devices.schemes import DeviceResponse
from di.db import db_dependency
from di.user import admin_dependency

router = APIRouter()


@router.get('')
async def get_scan_tasks(
        db: db_dependency,
        user: admin_dependency
):
    try:
        result = await db.execute(select(ScanTask))
        devices = result.scalars().all()
        serializer = ScanTaskSerializer(many=True)
        return {
            "tasks": serializer.dump(devices)
        }
    except Exception as e:
        print(e)
        return {
            "detail": str(e)
        }
