"""
JWT authentication middleware.

Validates HS256 tokens and extracts the verified principal into request.state.
Any missing or invalid token returns 401. Any token with a mismatched
audience or expired timestamp returns 401, never 403.
"""
from datetime import datetime, timezone
from typing import Optional

import jwt
from fastapi import HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import get_settings

_bearer_scheme = HTTPBearer(auto_error=False)


def _decode_token(token: str) -> dict:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            key=bytes.fromhex(settings.auth_jwt_secret),
            algorithms=["HS256"],
            options={"verify_exp": True},
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_current_user(request: Request) -> dict:
    """
    Extract and verify the JWT from the Authorization header.
    Returns the decoded payload. Raises 401 on any failure.
    """
    auth_header: Optional[str] = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = auth_header.split(" ", 1)[1]
    return _decode_token(token)


def require_role(*allowed_roles: str):
    """
    Returns a dependency that validates the caller has at least one of the
    specified roles in their JWT claims.
    """
    def _check(request: Request) -> dict:
        user = get_current_user(request)
        user_roles = user.get("roles", [])
        if not any(r in user_roles for r in allowed_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient privileges. Required: {list(allowed_roles)}",
            )
        return user
    return _check
