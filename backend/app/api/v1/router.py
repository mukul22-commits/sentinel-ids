"""API v1 router aggregator."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.v1.deps import get_request_id
from app.api.v1.endpoints.alerts import router as alerts_router
from app.api.v1.endpoints.captures import router as captures_router
from app.api.v1.endpoints.packets import router as packets_router
from app.api.v1.endpoints.system import router as system_router
from app.api.v1.routes.auth import router as auth_router
from app.api.v1.routes.connectors import router as connectors_router
from app.api.v1.routes.detection import router as detection_router
from app.api.v1.routes.incidents import router as incidents_router
from app.api.v1.routes.iocs import router as iocs_router
from app.api.v1.routes.ml import router as ml_router
from app.api.v1.routes.notifications import router as notifications_router
from app.api.v1.routes.policies import router as policies_router
from app.api.v1.routes.rules import router as rules_router
from app.api.v1.routes.sensors import router as sensors_router
from app.api.v1.routes.siem import router as siem_router
from app.api.v1.routes.users import router as users_router
from app.schemas.common import Envelope

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(system_router)
api_router.include_router(packets_router)
api_router.include_router(alerts_router)
api_router.include_router(captures_router)
api_router.include_router(rules_router)
api_router.include_router(iocs_router)
api_router.include_router(policies_router)
api_router.include_router(ml_router)
api_router.include_router(detection_router)
api_router.include_router(connectors_router)
api_router.include_router(siem_router)
api_router.include_router(sensors_router)
api_router.include_router(auth_router)
api_router.include_router(users_router)
api_router.include_router(incidents_router)
api_router.include_router(notifications_router)


@api_router.get("/ping", tags=["system"], response_model=Envelope[str])
async def ping(request_id: str = Depends(get_request_id)) -> Envelope[str]:
    """Liveness probe for the v1 API surface."""
    return Envelope(success=True, data="pong", request_id=request_id)
