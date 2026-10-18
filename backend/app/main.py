"""
FastAPI application entry point.

Wires up middleware, routes, and the FalkorDB + SQLite stores.
Rate limiting is applied per-client on the investigation endpoint
to protect the graph engine from query floods.
"""
import collections
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.storage.durable_store import DurableStore
from app.routers import investigate, reviews, auth, agent
from app.middleware.tenant_context import TenantContextMiddleware


_RATE_LIMIT_WINDOW = 60          # seconds
_RATE_LIMIT_MAX_REQUESTS = 60    # per window per client key
_rate_buckets: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    store = DurableStore()
    store.initialize()
    app.state.store = store
    yield


app = FastAPI(
    title="Contextual",
    description="Bitemporal graph investigation and audit defense engine.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

_settings = get_settings()
_cors_raw = getattr(_settings, "cors_origins", "*")
_cors_origins_list = (
    [o.strip() for o in _cors_raw.split(",") if o.strip()]
    if _cors_raw != "*"
    else ["*"]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Tenant context middleware runs early, attaching principal to request.state
app.add_middleware(TenantContextMiddleware)


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")
        if path in ("/docs", "/redoc", "/openapi.json"):
            csp = (
                b"default-src 'self'; "
                b"script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                b"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                b"img-src 'self' data: https://fastapi.tiangolo.com;"
            )
        else:
            csp = b"default-src 'self'"

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend([
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"content-security-policy", csp),
                    (b"strict-transport-security", b"max-age=31536000; includeSubDomains"),
                    (b"referrer-policy", b"strict-origin-when-cross-origin"),
                ])
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


app.add_middleware(SecurityHeadersMiddleware)



from app.services.investigation import check_rate_limit
from app.auth.jwt_auth import _decode_token


class InvestigationRateLimitMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if (
            scope["type"] == "http"
            and scope["path"] in ("/api/investigate", "/api/agent/investigate")
            and scope["method"] == "POST"
        ):
            headers = dict(scope.get("headers", []))
            auth_bytes = headers.get(b"authorization", b"")
            auth_header = auth_bytes.decode("utf-8", "ignore")

            client_key = None
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ", 1)[1].strip()
                try:
                    payload = _decode_token(token)
                    tenant_id = payload.get("tenant_id")
                    principal = payload.get("sub")
                    if tenant_id and principal:
                        client_key = f"{tenant_id}:{principal}"
                except Exception:
                    pass

            if not client_key:
                client = scope.get("client")
                client_ip = client[0] if client else "0.0.0.0"
                client_key = f"unauth:{client_ip}"

            retry_after = check_rate_limit(client_key)
            if retry_after is not None:
                response = JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={"detail": "Too many requests. Slow down the time slider."},
                    headers={"Retry-After": str(retry_after)},
                )
                return await response(scope, receive, send)

        await self.app(scope, receive, send)


app.add_middleware(InvestigationRateLimitMiddleware)



app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(investigate.router, prefix="/api", tags=["investigate"])
app.include_router(reviews.router, prefix="/api/reviews", tags=["reviews"])
app.include_router(agent.router, prefix="/api/agent", tags=["agent"])

# Mount MCP SSE application at /mcp (provides /mcp/sse and /mcp/messages/)
from app.mcp.server import mcp_server
app.mount("/mcp", mcp_server.sse_app())


@app.get("/health", tags=["health"])
@app.get("/api/health", tags=["health"])
def health():
    return {"status": "ok", "service": "contextual"}

