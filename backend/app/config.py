"""
App configuration via pydantic-settings.

Secrets are validated on startup: if either hex key is missing or malformed
the app refuses to start rather than running with a weak default.
"""
import re
from functools import lru_cache
from pathlib import Path
from typing import Literal, Optional

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(Path(__file__).parent.parent / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    falkordb_host: str = Field(default="127.0.0.1")
    falkordb_port: int = Field(default=6379, ge=1, le=65535)
    falkordb_graph_name: str = Field(default="contextual_security_graph")
    falkordb_timeout_ms: int = Field(default=5000, ge=100)

    # Both secrets must be 64-char hex strings and must differ from each other.
    tenant_master_key_secret: str = Field(..., min_length=64, max_length=64)
    auth_jwt_secret: str = Field(..., min_length=64, max_length=64)

    default_tenant_id: str = Field(
        default="tenant-corp-alpha",
        validation_alias=AliasChoices("default_tenant_id", "default_active_tenant"),
    )
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(default="INFO")
    environment: Literal["development", "staging", "production"] = Field(default="development")

    # Application policy and query bounds
    max_traversal_depth: int = Field(default=5, ge=1, le=10)
    query_row_cap: int = Field(default=100, ge=1, le=1000)
    cors_origins: str = Field(default="*")

    # Infrastructure remediation automation (GitHub API v3)
    github_token: Optional[str] = Field(default=None)
    github_repo: Optional[str] = Field(default=None)

    @field_validator("tenant_master_key_secret", "auth_jwt_secret")
    @classmethod
    def must_be_hex(cls, v: str, info) -> str:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", v):
            raise ValueError(
                f"{info.field_name} must be exactly 64 hex characters. Got length {len(v)}."
            )
        return v.lower()

    @field_validator("auth_jwt_secret")
    @classmethod
    def secrets_must_differ(cls, v: str, info) -> str:
        if "tenant_master_key_secret" in info.data and v == info.data["tenant_master_key_secret"]:
            raise ValueError(
                "AUTH_JWT_SECRET and TENANT_MASTER_KEY_SECRET must be different values."
            )
        return v


@lru_cache()
def get_settings() -> Settings:
    return Settings()
