"""API router package for ScamShield AI."""

from backend.app.api.analyze import router as analyze_router
from backend.app.api.health import router as health_router

__all__ = ["analyze_router", "health_router"]
