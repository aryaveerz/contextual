"""
Model Context Protocol (MCP) Server for Contextual.

Exposes exactly 3 approved, security-conscious investigation tools:
1. investigate_finding: Full graph investigation, verdict assembly, and receipt creation.
2. query_attack_path: Bitemporal topology check with tenant-fenced path evidence.
3. get_decision_history: Retrieves prior investigation decisions from persistent graph memory.

Authentication and tenant identity are derived strictly from the transport context
(Authorization: Bearer <jwt>), completely prohibiting client-supplied tenant overrides.
"""
import logging
from typing import Any, Dict, Optional

from mcp.server.mcpserver import Context, MCPServer

from app.auth.jwt_auth import _decode_token
from app.graph.layer3_envelope import get_query_engine
from app.graph.memory import get_graph_memory_manager
from app.services.investigation import (
    FindingNotFoundError,
    check_rate_limit,
    perform_investigation,
)

logger = logging.getLogger("contextual.mcp.server")

# Instantiate MCPServer with Contextual metadata
mcp_server = MCPServer(
    name="contextual-investigation-server",
    version="1.0.0",
    description="Contextual: Bitemporal graph audit defense and retrospective incident investigation engine.",
)


class McpAuthError(Exception):
    """Raised when authentication fails in an MCP tool invocation."""
    pass


def _authenticate_mcp_context(ctx: Optional[Context]) -> Dict[str, Any]:
    """
    Extract and verify caller identity from the MCP transport headers.
    Returns decoded JWT claims: sub, tenant_id, roles.
    Raises McpAuthError on missing or invalid tokens.
    """
    auth_header = None
    if ctx:
        try:
            headers = ctx.headers
        except Exception:
            headers = None

        if headers:
            for k, v in headers.items():
                if k.lower() == "authorization":
                    auth_header = v
                    break

    if not auth_header or not auth_header.startswith("Bearer "):
        raise McpAuthError("Missing or malformed Authorization header. Expected 'Bearer <token>'.")


    token = auth_header.split(" ", 1)[1].strip()
    try:
        payload = _decode_token(token)
    except Exception as exc:
        raise McpAuthError(f"Authentication failed: {exc}")

    tenant_id = payload.get("tenant_id")
    if not tenant_id:
        raise McpAuthError("Token is missing required tenant_id claim.")

    return payload


@mcp_server.tool()
async def investigate_finding(
    finding_id: str,
    world_time: str,
    knowledge_time: str,
    ctx: Context,
) -> Dict[str, Any]:
    """
    Execute a bitemporal graph investigation on a security finding.
    Assembles the 16-row policy verdict, signs an RFC 8785 canonical receipt,
    persists the receipt into SQLite, and stores an InvestigationDecision in FalkorDB.

    Parameters:
    - finding_id: Identifier of the target finding node.
    - world_time: ISO-8601 timestamp representing World Time (vt) when facts were true.
    - knowledge_time: ISO-8601 timestamp representing Knowledge Time (kt) when the system learned facts.
    """
    try:
        current_user = _authenticate_mcp_context(ctx)
    except McpAuthError as e:
        return {"status": "error", "error_code": "UNAUTHORIZED", "detail": str(e)}

    tenant_id = current_user["tenant_id"]

    # Enforce sliding-window rate limit
    client_key = f"{tenant_id}:{current_user.get('sub', 'unknown')}"
    retry_after = check_rate_limit(client_key)
    if retry_after is not None:
        return {
            "status": "error",
            "error_code": "RATE_LIMITED",
            "detail": f"Rate limit exceeded (60 req/min). Please retry after {retry_after}s.",
            "retry_after": retry_after,
        }

    # Validate inputs
    if not finding_id or not finding_id.strip():
        return {"status": "error", "error_code": "INVALID_INPUT", "detail": "finding_id cannot be empty."}
    if not world_time or not knowledge_time:
        return {"status": "error", "error_code": "INVALID_INPUT", "detail": "world_time and knowledge_time are required."}

    from app.routers.investigate import _validate_iso_timestamp
    try:
        valid_vt = _validate_iso_timestamp(world_time)
        valid_kt = _validate_iso_timestamp(knowledge_time)
    except Exception as exc:
        return {"status": "error", "error_code": "INVALID_INPUT", "detail": f"Malformed timestamp: {exc}"}

    try:
        result = perform_investigation(
            finding_id=finding_id.strip(),
            tenant_id=tenant_id,
            world_time=valid_vt,
            knowledge_time=valid_kt,
            current_user=current_user,
        )
        return {
            "status": "COMPLETED",
            "receipt_id": result["receipt_id"],
            "finding_id": result["finding_id"],
            "tenant_id": result["tenant_id"],
            "verdict": result["verdict"],
            "reason": result["reason"],
            "signals": result["signals"],
            "evidence_digest": result["evidence_digest"],
            "hmac_signature": result["hmac_signature"],
            "lifecycle_state": result["lifecycle_state"],
            "graph_evidence": result["graph_evidence"],
            "created_at": result["created_at"],
        }
    except FindingNotFoundError:
        return {"status": "error", "error_code": "NOT_FOUND", "detail": "Finding not found."}
    except Exception as exc:
        logger.error("Error executing MCP investigate_finding: %s", exc)
        return {"status": "error", "error_code": "INVESTIGATION_FAILED", "detail": "Investigation execution error."}


@mcp_server.tool()
async def query_attack_path(
    finding_id: str,
    world_time: str,
    knowledge_time: str,
    ctx: Context,
) -> Dict[str, Any]:
    """
    Check whether an attack path connects the security finding to a sensitive asset
    at the specified bitemporal coordinates (world_time, knowledge_time).
    Enforces tenant isolation on all traversal hops.

    Parameters:
    - finding_id: Identifier of the target finding.
    - world_time: ISO-8601 timestamp for World Time (vt).
    - knowledge_time: ISO-8601 timestamp for Knowledge Time (kt).
    """
    try:
        current_user = _authenticate_mcp_context(ctx)
    except McpAuthError as e:
        return {"status": "error", "error_code": "UNAUTHORIZED", "detail": str(e)}

    tenant_id = current_user["tenant_id"]

    # Enforce sliding-window rate limit
    client_key = f"{tenant_id}:{current_user.get('sub', 'unknown')}"
    retry_after = check_rate_limit(client_key)
    if retry_after is not None:
        return {
            "status": "error",
            "error_code": "RATE_LIMITED",
            "detail": f"Rate limit exceeded (60 req/min). Please retry after {retry_after}s.",
            "retry_after": retry_after,
        }

    # Validate finding exists for this tenant (anti-enumeration IDOR defense)
    memory_manager = get_graph_memory_manager()
    try:
        if not memory_manager.finding_exists(finding_id.strip(), tenant_id):
            return {"status": "error", "error_code": "NOT_FOUND", "detail": "Finding not found."}
    except Exception as exc:
        logger.error("Error checking finding existence in query_attack_path: %s", exc)
        return {"status": "error", "error_code": "DATABASE_ERROR", "detail": "Failed to verify finding."}

    from app.routers.investigate import _validate_iso_timestamp
    try:
        valid_vt = _validate_iso_timestamp(world_time)
        valid_kt = _validate_iso_timestamp(knowledge_time)
    except Exception as exc:
        return {"status": "error", "error_code": "INVALID_INPUT", "detail": f"Malformed timestamp: {exc}"}

    engine = get_query_engine()
    path_exists, path_details = engine.execute_topology_check(
        finding_id=finding_id.strip(),
        tenant_id=tenant_id,
        world_time=valid_vt,
        knowledge_time=valid_kt,
    )

    return {
        "status": "COMPLETED",
        "finding_id": finding_id.strip(),
        "tenant_id": tenant_id,
        "world_time": world_time.strip(),
        "knowledge_time": knowledge_time.strip(),
        "path_exists": path_exists,
        "path_evidence": path_details,
        "note": "Attack path analysis models graph topology reachability at (world_time, knowledge_time). A topological path represents reachability and does not prove active exploitation.",
    }


@mcp_server.tool()
async def get_decision_history(
    finding_id: str,
    limit: int = 20,
    ctx: Optional[Context] = None,
) -> Dict[str, Any]:
    """
    Retrieve prior investigation decisions from persistent graph memory for a finding.
    Returns receipt identifiers, verdicts, reasons, RFC 8785 evidence digests,
    and original temporal coordinates.

    Parameters:
    - finding_id: Identifier of the target finding.
    - limit: Maximum number of historical records to return (1-100, default 20).
    """
    try:
        current_user = _authenticate_mcp_context(ctx)
    except McpAuthError as e:
        return {"status": "error", "error_code": "UNAUTHORIZED", "detail": str(e)}

    tenant_id = current_user["tenant_id"]

    bounded_limit = max(1, min(limit, 100))
    memory_manager = get_graph_memory_manager()

    # Anti-enumeration IDOR defense: Verify finding exists and belongs to authenticated tenant
    try:
        if not memory_manager.finding_exists(finding_id.strip(), tenant_id):
            return {"status": "error", "error_code": "NOT_FOUND", "detail": "Finding not found."}
    except Exception as exc:
        logger.error("Error checking finding existence in get_decision_history: %s", exc)
        return {"status": "error", "error_code": "DATABASE_ERROR", "detail": "Failed to verify finding."}

    try:
        history_records = memory_manager.get_finding_history(
            finding_id=finding_id.strip(),
            tenant_id=tenant_id,
            limit=bounded_limit,
        )
        return {
            "status": "COMPLETED",
            "finding_id": finding_id.strip(),
            "tenant_id": tenant_id,
            "history": history_records,
            "count": len(history_records),
            "note": "Historical verdicts represent point-in-time assessments and do not constitute automatic approval for subsequent actions.",
        }
    except Exception as exc:
        logger.error("Failed to retrieve decision history via MCP: %s", exc)
        return {"status": "error", "error_code": "RETRIEVAL_FAILED", "detail": "Failed to query decision history."}
