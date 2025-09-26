from typing import List

from fastapi import APIRouter, HTTPException
from sqlalchemy import select
from starlette import status

from apps.antivirus.models import ScanTask
from apps.antivirus.serializers import ScanTaskSerializer, UpdateScanTaskStatusRequest

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


@router.patch('/{task_id}/status', status_code=status.HTTP_200_OK)
async def update_scan_task_status(
        task_id: int,
        req: UpdateScanTaskStatusRequest,
        db: db_dependency,
        user: admin_dependency
):
    # Fetch task
    result = await db.execute(select(ScanTask).where(ScanTask.id == task_id))
    task: ScanTask | None = result.scalar_one_or_none()

    if not task:
        raise HTTPException(status_code=404, detail="ScanTask not found")

    # Update status
    task.status = req.status

    # Commit changes
    await db.commit()
    await db.refresh(task)

    return {"message": "Status updated successfully", "task_id": task.id, "new_status": task.status}
