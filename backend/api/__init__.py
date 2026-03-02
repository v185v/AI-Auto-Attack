from fastapi import APIRouter

from backend.api.audit import router as audit_router
from backend.api.health import router as health_router
from backend.api.metrics import router as metrics_router
from backend.api.security import router as security_router
from backend.api.tasks import router as tasks_router
from backend.api.workflows import router as workflows_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(security_router)
api_router.include_router(audit_router)
api_router.include_router(workflows_router)
api_router.include_router(tasks_router)
api_router.include_router(metrics_router)
