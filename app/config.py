"""Konfigurasi aplikasi (mirror server1/src/config.js)."""
from __future__ import annotations

import os
from functools import lru_cache
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _parse_bool(v: str | None, default: bool) -> bool:
    if v is None or v == "":
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _normalize_origin(value: str) -> str | None:
    if not value:
        return None
    t = str(value).strip()
    if not t:
        return None
    if t.lower().startswith(("http://", "https://")):
        return t.rstrip("/")
    return f"https://{t.rstrip('/')}"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    MODE: str = Field(default="development")
    NODE_ENV: str = Field(default="development", alias="NODE_ENV")
    PORT: int = 8787
    DATABASE_URL: str = ""
    JWT_SECRET: str = ""
    CORS_ALLOW_ALL: bool = True
    CORS_ORIGINS: str = ""
    HMAC_MAX_SKEW_MS: int = 30000
    RATE_LIMIT_WINDOW_MS: int = 60000
    RATE_LIMIT_DEFAULT: int = 1000
    API_KEY_GRACE_MS: int = 60000
    BREAKER_TIMEOUT_MS: int = 8000
    BREAKER_HALF_OPEN_AFTER_MS: int = 2000
    MAX_UPLOAD_BYTES: int = 10 * 1024 * 1024
    MAX_PROXY_BODY_BYTES: int = 2 * 1024 * 1024
    DB_MAX_POOL: int = 10
    ENABLE_DEV_LOGIN: bool = True
    ENABLE_INTERNAL_TEST_ROUTES: bool = False
    EXPOSE_METRICS: bool = True
    EXPOSE_OPENAPI: bool = True
    ALLOW_CREDENTIAL_EXPORT: bool = True
    ENABLE_SELF_REGISTRATION: bool = True
    ENABLE_RUNTIME_MIGRATIONS: bool = True
    VERCEL: str | None = None
    AWS_LAMBDA_FUNCTION_NAME: str | None = None
    RUNTIME: str | None = None

    def model_post_init(self, __context) -> None:
        # Default fitur dev jika production
        if self.NODE_ENV == "production" or self.MODE == "production":
            if os.getenv("ENABLE_DEV_LOGIN") is None:
                object.__setattr__(self, "ENABLE_DEV_LOGIN", False)
            if os.getenv("ENABLE_INTERNAL_TEST_ROUTES") is None:
                object.__setattr__(self, "ENABLE_INTERNAL_TEST_ROUTES", False)

    @property
    def is_production(self) -> bool:
        return self.NODE_ENV == "production" or self.MODE == "production"

    @property
    def is_serverless(self) -> bool:
        return bool(self.VERCEL or self.AWS_LAMBDA_FUNCTION_NAME or (self.RUNTIME or "").lower() == "serverless")

    @property
    def provider_upstreams(self) -> dict[str, str]:
        return {
            "gemini": "https://generativelanguage.googleapis.com",
            "groq": "https://api.groq.com/openai/v1",
            "apify": "https://api.apify.com/v2",
            "cloudinary": "https://api.cloudinary.com",
            "imagekit": "https://api.imagekit.io",
            # News & data APIs (gateway proxy + credential injection)
            "newsapi": "https://newsapi.org/v2",
            "gnews": "https://gnews.io/api/v4",
            "mediastack": "https://api.mediastack.com/v1",
            "openweather": "https://api.openweathermap.org/data/2.5",
            "alphavantage": "https://www.alphavantage.co",
            "huggingface": "https://api-inference.huggingface.co",
        }

    def cors_origins_list(self) -> List[str]:
        raw = self.CORS_ORIGINS or os.getenv("CORS_ORIGIN") or ""
        if raw:
            return list({x for x in (_normalize_origin(x.strip()) for x in raw.split(",")) if x})
        if self.is_production:
            urls = [
                os.getenv("VERCEL_PROJECT_PRODUCTION_URL"),
                os.getenv("VERCEL_BRANCH_URL"),
                os.getenv("VERCEL_URL"),
            ]
            return list({x for x in (_normalize_origin(u) for u in urls if u) if x})
        return [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ]


@lru_cache
def get_settings() -> Settings:
    return Settings()


PLACEHOLDER_PASSWORD = "REPLACE_WITH_REAL_PASSWORD"


def assert_config() -> None:
    s = get_settings()
    if not s.DATABASE_URL:
        raise RuntimeError("DATABASE_URL wajib di-set")
    if PLACEHOLDER_PASSWORD in s.DATABASE_URL:
        raise RuntimeError("DATABASE_URL masih pakai password placeholder.")
    if not s.JWT_SECRET:
        raise RuntimeError("JWT_SECRET wajib di-set")
