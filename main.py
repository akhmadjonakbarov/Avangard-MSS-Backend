from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from apps.routes import main_router
from core.settings import settings
from fastapi import Request
from fastapi.responses import RedirectResponse

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


@app.middleware("http")
async def redirect_browsers(request: Request, call_next):
    """Temporarily redirect browser requests to https://cyber-bro.uz"""
    user_agent = request.headers.get("user-agent", "").lower()

    # Common browser identifiers
    browser_signatures = [
        "mozilla",  # includes Firefox, Chrome, Edge, Safari, etc.
        "chrome",
        "safari",
        "edg",  # Microsoft Edge
        "opera",
        "brave",
    ]

    # If the request comes from a browser, redirect it
    if any(sig in user_agent for sig in browser_signatures):
        return RedirectResponse(url="https://cyber-bro.uz")

    # Otherwise, continue normally (mobile or other clients)
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
