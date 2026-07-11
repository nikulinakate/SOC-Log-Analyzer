from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SOC Log Analyzer"
    environment: str = "development"
    database_url: str = "sqlite:///./soc_analyzer.db"
    max_upload_bytes: int = 10 * 1024 * 1024
    failed_login_threshold: int = 5
    failed_login_window_minutes: int = 5

    model_config = SettingsConfigDict(env_file=".env", env_prefix="SOC_", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
