from fastapi import APIRouter
from .device_routes import router as device
from .scan_task_routes import router as scan_task

admin_route = APIRouter(
    prefix='/admin'
)

admin_route.include_router(device, prefix="/devices", tags=["Admin Devices"])
admin_route.include_router(scan_task, prefix="/scan-tasks", tags=["Admin Scan Taks"])
