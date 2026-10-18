"""
Auth router: issues HS256 demo tokens for the local development environment.

In production this is replaced by an OIDC identity provider (Auth0, Okta, etc).
The endpoint exists so operators can exercise the Gate A / Gate B separation-of-duties
flows without needing an external IdP configured.
"""
import time

import jwt
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.config import get_settings

router = APIRouter()

# Demo users: roles are embedded in the token payload.
# Never hardcode secrets here; the signing key comes from settings.
_DEMO_USERS = {
    "analyst-alice-01": {
        "passphrase": "demo-alice-2026",
        "roles": ["security:analyst", "security:reviewer"],
        "tenant_id": "tenant-corp-alpha",
    },
    "analyst-bob-02": {
        "passphrase": "demo-bob-2026",
        "roles": ["security:analyst"],
        "tenant_id": "tenant-corp-alpha",
    },
    "lead-carol-01": {
        "passphrase": "demo-carol-2026",
        "roles": ["security:lead", "security:admin"],
        "tenant_id": "tenant-corp-alpha",
    },
    "lead-dave-beta": {
        "passphrase": "demo-dave-2026",
        "roles": ["security:lead"],
        "tenant_id": "tenant-corp-beta",
    },
}

_TOKEN_TTL = 3600  # 1 hour


class TokenRequest(BaseModel):
    username: str
    passphrase: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = _TOKEN_TTL


@router.post("/token", response_model=TokenResponse, status_code=status.HTTP_200_OK)
def issue_token(body: TokenRequest):
    user = _DEMO_USERS.get(body.username)
    if not user or user["passphrase"] != body.passphrase:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
        )

    settings = get_settings()
    now = int(time.time())
    payload = {
        "sub": body.username,
        "tenant_id": user["tenant_id"],
        "roles": user["roles"],
        "iat": now,
        "exp": now + _TOKEN_TTL,
    }
    token = jwt.encode(
        payload,
        key=bytes.fromhex(settings.auth_jwt_secret),
        algorithm="HS256",
    )
    return TokenResponse(access_token=token)
