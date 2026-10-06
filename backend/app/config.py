"""Application configuration module using pydantic-settings."""

from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """ScamShield AI Settings loaded from environment variables."""

    # Server Settings
    ENVIRONMENT: str = "development"
    PORT: int = 8000
    HOST: str = "0.0.0.0"
    LOG_LEVEL: str = "INFO"

    # LLM Settings
    LLM_PROVIDER: str = "gemini"  # gemini, openai, mock
    LLM_API_KEY: Optional[str] = None
    LLM_MODEL: str = "gemini-2.5-flash"
    LLM_TIMEOUT_SECONDS: int = 10

    # Engine Settings
    MAX_INPUT_LENGTH: int = 20000

    # Paths
    BASE_DIR: Path = Path(__file__).resolve().parent
    KNOWLEDGE_DIR: Path = BASE_DIR / "knowledge"

    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parent.parent / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
