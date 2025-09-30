from fastapi import APIRouter, HTTPException
from sqlalchemy import select
from starlette import status

from apps.antivirus.models import ScanTask
from apps.antivirus.serializers import ScanTaskSerializer, UpdateScanTaskStatusRequest

from di.db import db_dependency
from di.user import admin_dependency

router = APIRouter()

from fastapi import Query
from sqlalchemy import func


@router.get('')
async def get_scan_tasks(
        db: db_dependency,
        user: admin_dependency,
        page: int = Query(1, ge=1, description="Page number"),
        page_size: int = Query(10, ge=1, le=100, description="Items per page"),
):
    try:
        # total count for pagination metadata
        total_result = await db.execute(select(func.count()).select_from(ScanTask))
        total = total_result.scalar_one()

        # calculate offset from page and page_size
        offset = (page - 1) * page_size

        # fetch paginated results
        result = await db.execute(
            select(ScanTask).offset(offset).limit(page_size)
        )
        tasks = result.scalars().all()

        serializer = ScanTaskSerializer(many=True)

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": (total + page_size - 1) // page_size,  # total pages
            "tasks": serializer.dump(tasks),
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


@router.delete('/delete/all', status_code=status.HTTP_204_NO_CONTENT)
async def delete_all_scan_tasks(
        db: db_dependency,
        user: admin_dependency
):
    result = await db.execute(select(ScanTask))
    tasks = result.scalars().all()  # Get all tasks

    if not tasks:
        raise HTTPException(status_code=404, detail="No ScanTasks found to delete")

    for task in tasks:
        await db.delete(task)

    await db.commit()


@router.delete('/delete/{task_id}', status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan_task(
        task_id: int,
        req: UpdateScanTaskStatusRequest,
        db: db_dependency,
        user: admin_dependency
):
    result = await db.execute(select(ScanTask).where(ScanTask.id == task_id))
    task: ScanTask | None = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="ScanTask not found")

    await db.delete(task)
    await db.commit()
