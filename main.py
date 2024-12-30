from fastapi import FastAPI
import uvicorn
from core.settings import settings
# routes
from apps.user import routes as user_routes
from apps.keepassxc import routes as keepass_routes
from apps.devices import routes as device_routes

app = FastAPI(
    title=settings.APP_NAME,
)

app.include_router(
    user_routes.router, prefix=settings.API_V1
)
app.include_router(
    keepass_routes.router, prefix=settings.API_V1
)
app.include_router(
    device_routes.router, prefix=settings.API_V1
)

if __name__ == '__main__':
    uvicorn.run("main:app", host="127.0.0.1", port=8000)
