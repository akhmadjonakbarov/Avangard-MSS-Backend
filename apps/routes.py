from fastapi import APIRouter
from apps.user import routes as user_routes
from apps.safe_password import routes as keepass_routes
from apps.devices import routes as device_routes
from apps.antivirus import routes as antivirus_routes
from core.settings import settings

main_router = APIRouter(
    prefix=settings.API_V1
)
main_router.include_router(
    user_routes.router
)
main_router.include_router(
    keepass_routes.router
)
main_router.include_router(
    device_routes.router,

)
main_router.include_router(
    antivirus_routes.router
)
