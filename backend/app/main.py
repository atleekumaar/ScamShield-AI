"""Main FastAPI application entry point for ScamShield AI."""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.app.api.analyze import router as analyze_router
from backend.app.api.health import router as health_router
from backend.app.config import settings

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
)
logger = logging.getLogger("scamshield.main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context for startup and shutdown routines."""
    logger.info("Initializing ScamShield AI Backend (Environment: %s)", settings.ENVIRONMENT)
    logger.info("Configured LLM Provider: %s", settings.LLM_PROVIDER)
    yield
    logger.info("Shutting down ScamShield AI Backend")


app = FastAPI(
    title="ScamShield AI",
    description="Multimodal AI Security Analyst backend for detecting digital fraud and scams.",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Exception Handlers for structured error contracts
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Handle FastAPI / Pydantic validation errors with clean structured envelope."""
    error_messages = []
    for err in exc.errors():
        loc = " -> ".join(str(l) for l in err.get("loc", []))
        msg = err.get("msg", "Validation error")
        error_messages.append(f"{loc}: {msg}")

    detail_message = "; ".join(error_messages) if error_messages else "Invalid request payload."
    logger.warning("Request validation failed on %s: %s", request.url.path, detail_message)

    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "INVALID_INPUT",
                "message": detail_message,
            }
        },
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Handle HTTPExceptions with structured error response."""
    if isinstance(exc.detail, dict) and "code" in exc.detail and "message" in exc.detail:
        code = exc.detail["code"]
        message = exc.detail["message"]
    else:
        code = "HTTP_ERROR"
        message = str(exc.detail)

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": code,
                "message": message,
            }
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all unhandled exceptions handler."""
    logger.error("Unhandled exception on %s: %s", request.url.path, str(exc), exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected server error occurred during processing.",
            }
        },
    )


# Include Routers
app.include_router(health_router)
app.include_router(analyze_router)


@app.get("/", tags=["Root"])
async def root():
    """Service metadata endpoint."""
    return {
        "service": "ScamShield AI",
        "description": "Multimodal AI Security Analyst backend",
        "version": "0.1.0",
        "docs_url": "/docs",
        "health_url": "/health",
    }
