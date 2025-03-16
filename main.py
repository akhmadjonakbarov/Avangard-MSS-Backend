from fastapi import FastAPI

from core.settings import settings
# routes
from apps.routes import main_router

app = FastAPI(
    title=settings.APP_NAME,
)

app.include_router(
    main_router
)

if __name__ == '__main__':
    import uvicorn
    settings.init()
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
