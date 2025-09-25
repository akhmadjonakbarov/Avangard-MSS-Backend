from fastapi import APIRouter
from apps.user import routes as user_routes
from apps.admin.routes import admin_route
from apps.devices import routes as device_routes
from apps.antivirus import routes as antivirus_routes
from core.settings import settings

mobile_router = APIRouter(
    prefix='/mobile'
)

mobile_router.include_router(antivirus_routes.router, prefix='/antivirus', tags=["Mobile AntiVirus"])

main_router = APIRouter(
    prefix=settings.API_V1
)
main_router.include_router(
    user_routes.admin_router
)
main_router.include_router(
    device_routes.router,

)
main_router.include_router(
    mobile_router
)
main_router.include_router(
    admin_route
)
