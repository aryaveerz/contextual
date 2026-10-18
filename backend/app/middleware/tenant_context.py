"""
Tenant Context Middleware

Extracts the JWT from the Authorization header, validates it, and attaches the
principal information to the request state for downstream handlers.

All routes that need authentication already depend on `get_current_user`, but
the security policy (USER_SESSION_AND_RBAC_SPEC.md) requires the principal to be
available via `request.state.principal` so that any handler can reference the
authenticated identity without re-decoding the token.

The middleware runs early in the request lifecycle, aborting with 401 on any
missing or invalid token. It also populates convenience attributes:
- request.state.principal (subject claim)
- request.state.tenant_id
- request.state.roles
"""
import logging
from fastapi import HTTPException, status
from starlette.responses import JSONResponse
from app.auth.jwt_auth import _decode_token

logger = logging.getLogger("contextual.middleware.tenant")


class TenantContextMiddleware:
    """
    Pure ASGI middleware for tenant context extraction.
    Native ASGI ensures zero interference with streaming SSE and WebSockets.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")
        # Skip authentication for open endpoints (health, docs, openapi, token issuance, fixtures, mcp)
        if path.startswith(("/health", "/api/health", "/docs", "/redoc", "/openapi.json", "/api/auth", "/api/fixtures", "/mcp")):
            return await self.app(scope, receive, send)

        headers = dict(scope.get("headers", []))
        auth_bytes = headers.get(b"authorization", b"")
        auth_header = auth_bytes.decode("utf-8", "ignore")

        if not auth_header or not auth_header.startswith("Bearer "):
            response = JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Missing or malformed Authorization header."},
                headers={"WWW-Authenticate": "Bearer"},
            )
            return await response(scope, receive, send)

        token = auth_header.split(" ", 1)[1]
        try:
            payload = _decode_token(token)
        except HTTPException as exc:
            logger.warning("Authentication failure: %s", exc.detail)
            response = JSONResponse(
                status_code=exc.status_code,
                content={"detail": "Invalid or expired authentication token."},
                headers=exc.headers or {"WWW-Authenticate": "Bearer"},
            )
            return await response(scope, receive, send)
        except Exception as exc:
            logger.warning("Token decoding exception: %s", exc)
            response = JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid or expired authentication token."},
                headers={"WWW-Authenticate": "Bearer"},
            )
            return await response(scope, receive, send)

        # Attach principal info to scope["state"] (FastAPI request.state)
        state = scope.setdefault("state", {})
        state["principal"] = payload.get("sub")
        state["tenant_id"] = payload.get("tenant_id")
        state["roles"] = payload.get("roles", [])
        state["jwt_payload"] = payload

        await self.app(scope, receive, send)