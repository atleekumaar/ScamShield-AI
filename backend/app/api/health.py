"""Health check endpoint router."""

from fastapi import APIRouter
from backend.app.models.schemas import HealthResponse

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Return health status of the ScamShield AI backend service."""
    return HealthResponse(
        status="healthy",
        service="scamshield-api",
        version="0.1.0",
    )
