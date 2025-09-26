from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from apps.routes import main_router
from core.settings import settings

app = FastAPI(
    title=settings.APP_NAME,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def on_startup():
    await settings.init()


app.include_router(
    main_router
)

if __name__ == '__main__':
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
