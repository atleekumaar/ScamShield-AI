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
    LLM_PROVIDER: str = "auto"  # auto, groq, gemini, openai, mock
    LLM_API_KEY: Optional[str] = None
    LLM_MODEL: Optional[str] = None
    LLM_TIMEOUT_SECONDS: int = 15

    # Specific Provider Credentials & Models
    GROQ_API_KEY: Optional[str] = None
    GROQ_MODEL: str = "llama-3.3-70b-versatile"

    GEMINI_API_KEY: Optional[str] = None
    GEMINI_MODEL: str = "gemini-2.5-flash"

    OPENAI_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-4o-mini"

    # Engine Settings
    MAX_INPUT_LENGTH: int = 20000

    # Paths
    BASE_DIR: Path = Path(__file__).resolve().parent
    KNOWLEDGE_DIR: Path = BASE_DIR / "knowledge"

    model_config = SettingsConfigDict(
        env_file=(
            Path(__file__).resolve().parent.parent.parent / ".env",
            Path(__file__).resolve().parent.parent / ".env",
            Path(__file__).resolve().parent / ".env",
        ),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def effective_provider(self) -> str:
        provider = (self.LLM_PROVIDER or "").lower().strip()
        if provider and provider not in ("auto", ""):
            return provider

        # Auto-detect provider based on credentials
        if self.GROQ_API_KEY or (self.LLM_API_KEY and (self.LLM_API_KEY or "").startswith("gsk_")):
            return "groq"
        if self.GEMINI_API_KEY or (self.LLM_API_KEY and "AIza" in (self.LLM_API_KEY or "")):
            return "gemini"
        if self.OPENAI_API_KEY or (self.LLM_API_KEY and (self.LLM_API_KEY or "").startswith("sk-")):
            return "openai"
        if self.LLM_API_KEY:
            return "gemini"

        return "mock"

    @property
    def effective_api_key(self) -> Optional[str]:
        prov = self.effective_provider
        if prov == "groq":
            return self.GROQ_API_KEY or self.LLM_API_KEY
        if prov == "gemini":
            return self.GEMINI_API_KEY or self.LLM_API_KEY
        if prov == "openai":
            return self.OPENAI_API_KEY or self.LLM_API_KEY
        return self.LLM_API_KEY

    @property
    def effective_model(self) -> str:
        if self.LLM_MODEL:
            return self.LLM_MODEL
        prov = self.effective_provider
        if prov == "groq":
            return self.GROQ_MODEL or "llama-3.3-70b-versatile"
        if prov == "gemini":
            return self.GEMINI_MODEL or "gemini-2.5-flash"
        if prov == "openai":
            return self.OPENAI_MODEL or "gpt-4o-mini"
        return "mock-analyst-v1"


settings = Settings()
