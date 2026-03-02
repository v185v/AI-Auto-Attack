from fastapi import FastAPI

from backend.api import api_router
from backend.core.config import get_settings


def create_app() -> FastAPI:
    settings = get_settings()
    app_name = str(settings.get("app", {}).get("name", "ai-attack"))
    app = FastAPI(title=app_name, version="0.1.0")
    app.include_router(api_router)
    return app


app = create_app()

