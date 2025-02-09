from fastapi import APIRouter
from apps.user import routes as user_routes
from apps.keepassxc import routes as keepass_routes
from apps.devices import routes as device_routes
from core.settings import settings

main_router = APIRouter(
    prefix=settings.API_V1
)

main_router.include_router(
    user_routes.router, prefix=settings.API_V1
)
main_router.include_router(
    keepass_routes.router, prefix=settings.API_V1
)
main_router.include_router(
    device_routes.router, prefix=settings.API_V1
)
