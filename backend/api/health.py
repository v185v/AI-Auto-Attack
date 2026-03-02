from fastapi import APIRouter

from backend.core.config import get_settings

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict[str, str]:
    settings = get_settings()
    app_config = settings.get("app", {})
    return {
        "status": "ok",
        "service": str(app_config.get("name", "ai-attack")),
        "env": str(app_config.get("env", "dev")),
    }

