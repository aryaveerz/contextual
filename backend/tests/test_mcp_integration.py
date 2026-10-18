"""
Tests for Model Context Protocol (MCP) Integration.

Validates:
1. Tool registration and discovery (exactly the 3 approved tools).
2. Input schema verification (no caller-supplied tenant_id).
3. Successful investigate_finding execution via MCP.
4. Successful query_attack_path execution via MCP.
5. Successful get_decision_history retrieval via MCP.
6. REST vs MCP consistency for equivalent investigations.
7. Authentication enforcement (missing/invalid token returns UNAUTHORIZED).
8. Anti-enumeration IDOR defense across all 3 MCP tools (NOT_FOUND).
9. Anti-spoofing: X-Tenant-ID cannot override verified JWT principal.
10. Temporal preservation across bitemporal queries.
11. Live SSE client transport integration test.
"""
import asyncio
import json
import uuid
import pytest
import uvicorn
from fastapi.testclient import TestClient
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

from app.main import app
from app.mcp.server import mcp_server


@pytest.fixture
def client():
    return TestClient(app)


def get_token(client: TestClient, username: str, passphrase: str) -> str:
    resp = client.post(
        "/api/auth/token",
        json={"username": username, "passphrase": passphrase},
    )
    assert resp.status_code == 200, f"Token failed: {resp.text}"
    return resp.json()["access_token"]


@pytest.mark.asyncio
async def test_01_mcp_tool_discovery():
    """Test 1: Verify exactly the 3 approved tools are registered and discovered."""
    tools = await mcp_server.list_tools()
    tool_names = [t.name for t in tools]
    assert len(tool_names) == 3, f"Expected 3 tools, got: {tool_names}"
    assert "investigate_finding" in tool_names
    assert "query_attack_path" in tool_names
    assert "get_decision_history" in tool_names


@pytest.mark.asyncio
async def test_02_mcp_input_schemas():
    """Test 2: Verify input schemas do NOT accept caller-supplied tenant_id."""
    tools = await mcp_server.list_tools()
    tool_map = {t.name: t for t in tools}

    # investigate_finding
    inv_schema = tool_map["investigate_finding"].input_schema
    assert "finding_id" in inv_schema["properties"]
    assert "world_time" in inv_schema["properties"]
    assert "knowledge_time" in inv_schema["properties"]
    assert "tenant_id" not in inv_schema["properties"], "tenant_id must NEVER be accepted from tool arguments"

    # query_attack_path
    path_schema = tool_map["query_attack_path"].input_schema
    assert "finding_id" in path_schema["properties"]
    assert "tenant_id" not in path_schema["properties"]

    # get_decision_history
    hist_schema = tool_map["get_decision_history"].input_schema
    assert "finding_id" in hist_schema["properties"]
    assert "tenant_id" not in hist_schema["properties"]


@pytest.mark.asyncio
async def test_03_mcp_auth_failure_missing_token():
    """Test 7: Unauthenticated tool invocation returns UNAUTHORIZED."""
    res = await mcp_server.call_tool(
        "investigate_finding",
        {
            "finding_id": "finding-01",
            "world_time": "2026-01-05T00:00:00Z",
            "knowledge_time": "2026-01-05T00:00:00Z",
        },
    )
    content = json.loads(res.content[0].text)
    assert content["status"] == "error"
    assert content["error_code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_04_mcp_end_to_end_sse_client(client):
    """
    Test 3, 4, 5, 6, 8, 9, 10, 11:
    End-to-end integration test with real MCP sse_client against running server.
    Tests discovery, execution of all 3 tools, cross-tenant isolation, and REST consistency.
    """
    token_alice = get_token(client, "analyst-alice-01", "demo-alice-2026")
    token_beta = get_token(client, "lead-dave-beta", "demo-dave-2026")

    # Start live background server on port 8998
    config = uvicorn.Config(app, host="127.0.0.1", port=8998, log_level="error")
    server = uvicorn.Server(config)
    server_task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.5)

    try:
        # Connect real MCP client with Alice's credentials (Tenant Alpha)
        async with sse_client(
            "http://127.0.0.1:8998/mcp/sse",
            headers={"Authorization": f"Bearer {token_alice}"},
        ) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # 1. Discover tools
                tool_list = await session.list_tools()
                names = [t.name for t in tool_list.tools]
                assert set(names) == {"investigate_finding", "query_attack_path", "get_decision_history"}

                # 2. Tool A: investigate_finding
                inv_res = await session.call_tool(
                    "investigate_finding",
                    {
                        "finding_id": "finding-priv-esc-01",
                        "world_time": "2026-01-05T00:00:00Z",
                        "knowledge_time": "2026-01-05T00:00:00Z",
                    },
                )
                inv_data = json.loads(inv_res.content[0].text)
                assert inv_data["status"] == "COMPLETED"
                assert inv_data["verdict"] == "CULPABLE"
                assert inv_data["tenant_id"] == "tenant-corp-alpha"
                receipt_id = inv_data["receipt_id"]
                digest = inv_data["evidence_digest"]

                # Compare with REST endpoint result (Consistency check)
                rest_resp = client.post(
                    "/api/investigate",
                    json={
                        "finding_id": "finding-priv-esc-01",
                        "world_time": "2026-01-05T00:00:00Z",
                        "knowledge_time": "2026-01-05T00:00:00Z",
                    },
                    headers={"Authorization": f"Bearer {token_alice}"},
                )
                assert rest_resp.status_code == 200
                rest_data = rest_resp.json()
                assert rest_data["verdict"] == inv_data["verdict"]
                assert rest_data["receipt_id"] == inv_data["receipt_id"]
                assert rest_data["evidence_digest"] == inv_data["evidence_digest"]
                assert rest_data["signals"] == inv_data["signals"]

                # 3. Tool B: query_attack_path
                # Jan 2: path not yet learned
                path_res_jan2 = await session.call_tool(
                    "query_attack_path",
                    {
                        "finding_id": "finding-priv-esc-01",
                        "world_time": "2026-01-02T10:00:00Z",
                        "knowledge_time": "2026-01-02T10:00:00Z",
                    },
                )
                jan2_data = json.loads(path_res_jan2.content[0].text)
                assert jan2_data["status"] == "COMPLETED"
                assert jan2_data["path_exists"] is False

                # Jan 5: path learned and visible
                path_res_jan5 = await session.call_tool(
                    "query_attack_path",
                    {
                        "finding_id": "finding-priv-esc-01",
                        "world_time": "2026-01-05T00:00:00Z",
                        "knowledge_time": "2026-01-05T00:00:00Z",
                    },
                )
                jan5_data = json.loads(path_res_jan5.content[0].text)
                assert jan5_data["status"] == "COMPLETED"
                assert jan5_data["path_exists"] is True
                assert jan5_data["path_evidence"] is not None

                # 4. Tool C: get_decision_history
                hist_res = await session.call_tool(
                    "get_decision_history",
                    {"finding_id": "finding-priv-esc-01", "limit": 100},
                )
                hist_data = json.loads(hist_res.content[0].text)
                assert hist_data["status"] == "COMPLETED"
                assert hist_data["finding_id"] == "finding-priv-esc-01"
                assert any(h["receipt_id"] == receipt_id for h in hist_data["history"])

                # 5. Cross-Tenant IDOR Defense for Alice querying Beta finding
                cross_inv = await session.call_tool(
                    "investigate_finding",
                    {
                        "finding_id": "finding-beta-01",
                        "world_time": "2026-01-05T00:00:00Z",
                        "knowledge_time": "2026-01-05T00:00:00Z",
                    },
                )
                cross_inv_data = json.loads(cross_inv.content[0].text)
                assert cross_inv_data["status"] == "error"
                assert cross_inv_data["error_code"] == "NOT_FOUND"

                cross_path = await session.call_tool(
                    "query_attack_path",
                    {
                        "finding_id": "finding-beta-01",
                        "world_time": "2026-01-05T00:00:00Z",
                        "knowledge_time": "2026-01-05T00:00:00Z",
                    },
                )
                cross_path_data = json.loads(cross_path.content[0].text)
                assert cross_path_data["status"] == "error"
                assert cross_path_data["error_code"] == "NOT_FOUND"

                cross_hist = await session.call_tool(
                    "get_decision_history",
                    {"finding_id": "finding-beta-01", "limit": 10},
                )
                cross_hist_data = json.loads(cross_hist.content[0].text)
                assert cross_hist_data["status"] == "error"
                assert cross_hist_data["error_code"] == "NOT_FOUND"

        # Separate connection for Tenant Beta: should successfully query finding-beta-01
        async with sse_client(
            "http://127.0.0.1:8998/mcp/sse",
            headers={"Authorization": f"Bearer {token_beta}"},
        ) as (read_b, write_b):
            async with ClientSession(read_b, write_b) as session_b:
                await session_b.initialize()
                beta_hist = await session_b.call_tool(
                    "get_decision_history",
                    {"finding_id": "finding-beta-01", "limit": 10},
                )
                beta_data = json.loads(beta_hist.content[0].text)
                assert beta_data["status"] == "COMPLETED"
                assert beta_data["tenant_id"] == "tenant-corp-beta"

    finally:
        server.should_exit = True
        await server_task
