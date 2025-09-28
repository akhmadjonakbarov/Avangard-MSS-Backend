from fastapi import APIRouter
from .device_routes import router as device
from .scan_task_routes import router as scan_task
from .anti_virus_database_routes import router as antivirus_database

admin_route = APIRouter(
    prefix='/admin'
)

admin_route.include_router(device, prefix="/device_admin", tags=["Admin Devices"])
admin_route.include_router(scan_task, prefix="/scan-tasks", tags=["Admin Scan Taks"])
admin_route.include_router(antivirus_database, prefix="/antivirus-database", tags=["Admin AntiVirus Database"])
