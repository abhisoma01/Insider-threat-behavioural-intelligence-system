from fastapi import APIRouter
from app.api.v1.auth import router as auth_router
from app.api.v1.employees import router as employees_router
from app.api.v1.alerts import router as alerts_router
from app.api.v1.activity import router as activity_router
from app.api.v1.risk import router as risk_router
from app.api.v1.behavior import router as behavior_router
from app.api.v1.notifications import router as notifications_router
from app.api.v1.reports import router as reports_router
from app.api.v1.collectors import router as collectors_router

api_router = APIRouter()

api_router.include_router(auth_router)
api_router.include_router(employees_router)
api_router.include_router(alerts_router)
api_router.include_router(activity_router)
api_router.include_router(risk_router)
api_router.include_router(behavior_router)
api_router.include_router(notifications_router)
api_router.include_router(reports_router)
api_router.include_router(collectors_router)

__all__ = ["api_router"]
