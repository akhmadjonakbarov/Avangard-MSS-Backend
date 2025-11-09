from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from apps.routes import main_router
from core.settings import settings
from fastapi import Request
from fastapi.responses import RedirectResponse

app = FastAPI(
    title=settings.APP_NAME,
)
# 👇 Add your dashboard origin here
origins = [
    "https://avangard-admin-019a39bb-ae8f-765a-9.vercel.app",
    "https://avangard-mobile.uz/docs"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # exact origin of your dashboard
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def redirect_browsers(request: Request, call_next):
    user_agent = request.headers.get("user-agent", "").lower()
    origin = request.headers.get("origin", "")
    path = request.url.path

    # ✅ Allow requests from your dashboard or docs path
    if (
        origin == "https://avangard-admin-019a39bb-ae8f-765a-9.vercel.app"
        or path.startswith("/docs")
        or path.startswith("/redoc")
        or path.startswith("/api/v1/auth/token")
    ):
        return await call_next(request)

    # Common browsers
    browser_signatures = [
        "mozilla",
        "chrome",
        "safari",
        "edg",
        "opera",
        "brave",
    ]

    if any(sig in user_agent for sig in browser_signatures):
        return RedirectResponse(url="https://cyber-bro.uz")

    return await call_next(request)



@app.on_event("startup")
async def on_startup():
    await settings.init()


app.include_router(
    main_router
)

if __name__ == '__main__':
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
