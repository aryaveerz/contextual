import os
import time
from unittest.mock import MagicMock
import jwt
import pytest
from app.config import get_settings
from app.graph.layer3_envelope import Layer3QueryEngine, get_query_engine
from app.assembly.policy import assemble_verdict, format_verdict_result, Verdict, VerdictReason
from app.services.investigation import perform_investigation
from app.mcp.server import mcp_server

ANALYST_TOKEN_CLAIMS = {
    "sub": "user-lead-01",
    "tenant_id": "tenant-corp-alpha",
    "roles": ["security:lead", "security:analyst"],
}


def make_test_token(claims: dict) -> str:
    settings = get_settings()
    now = int(time.time())
    payload = {
        "sub": claims.get("sub", "user-lead-01"),
        "tenant_id": claims.get("tenant_id", "tenant-corp-alpha"),
        "roles": claims.get("roles", ["security:lead"]),
        "iat": now,
        "exp": now + 3600,
    }
    return jwt.encode(
        payload,
        key=bytes.fromhex(settings.auth_jwt_secret),
        algorithm="HS256",
    )


def test_q9_centrality_live_execution():
    """Verify FalkorDB algo.betweenness returns DataReaderRole as rank #1 for tenant-corp-alpha."""
    engine = get_query_engine()
    roles = engine.execute_centrality_check("tenant-corp-alpha")
    assert isinstance(roles, list)
    assert len(roles) >= 1
    top_role = roles[0]
    assert top_role["role_id"] == "role-data-reader"
    assert top_role["role_name"] == "DataReaderRole"
    assert top_role["centrality_rank"] == 1
    assert top_role["centrality_score"] >= 0.0


def test_q9_centrality_strict_tenant_isolation():
    """Verify tenant-corp-beta receives zero roles from tenant-corp-alpha's IAM graph."""
    engine = get_query_engine()
    beta_roles = engine.execute_centrality_check("tenant-corp-beta")
    assert isinstance(beta_roles, list)
    assert len(beta_roles) == 0


def test_q9_centrality_graceful_fallback_on_query_failure():
    """Verify engine handles query/algo exceptions safely without crashing."""
    mock_client = MagicMock()
    mock_client.execute_query.side_effect = RuntimeError("FalkorDB algorithm unavailable")
    engine = Layer3QueryEngine(client=mock_client)
    res = engine.execute_centrality_check("tenant-corp-alpha")
    assert res == []


def test_evaluate_blast_radius_temporal_progression():
    """
    On Jan 2 (no attack path): blast_radius reports unexposed.
    On Jan 5 (path compromised through DataReaderRole): blast_radius reports high blast radius.
    """
    engine = get_query_engine()

    # Jan 2 investigation: no attack path
    res_jan2 = perform_investigation(
        finding_id="finding-01",
        tenant_id="tenant-corp-alpha",
        world_time="2026-01-02T00:00:00Z",
        knowledge_time="2026-01-02T00:00:00Z",
        current_user=ANALYST_TOKEN_CLAIMS,
    )
    assert res_jan2["verdict"] == "DEGRADED"  # P1=False, P2=True, P3=True, P4=1
    assert res_jan2["signals"]["p1_path"] is False
    assert res_jan2["signals"]["blast_radius"]["high_centrality_role"] is False
    assert res_jan2["signals"]["blast_radius"]["centrality_rank"] is None

    # Jan 5 investigation: attack path active traversing DataReaderRole
    res_jan5 = perform_investigation(
        finding_id="finding-01",
        tenant_id="tenant-corp-alpha",
        world_time="2026-01-05T00:00:00Z",
        knowledge_time="2026-01-05T00:00:00Z",
        current_user=ANALYST_TOKEN_CLAIMS,
    )
    assert res_jan5["verdict"] == "CULPABLE"  # P1=True, P2=True, P3=True, P4=1
    assert res_jan5["signals"]["p1_path"] is True
    blast = res_jan5["signals"]["blast_radius"]
    assert blast["high_centrality_role"] is True
    assert blast["centrality_rank"] == 1
    assert blast["role_id"] == "role-data-reader"
    assert blast["role_name"] == "DataReaderRole"
    assert blast["centrality_score"] == 4.0


def test_16_row_truth_table_invariance_with_centrality():
    """Verify that adding centrality blast_radius does NOT alter any of the 16 truth table verdicts."""
    # Test all 16 rows: (P1, P2, P3, P4)
    expected_matrix = [
        # (p1, p2, p3, p4) -> expected verdict
        (False, True, True, 0, Verdict.EXONERATED),
        (False, True, True, 1, Verdict.DEGRADED),
        (False, True, False, 0, Verdict.DEGRADED),
        (False, True, False, 1, Verdict.CULPABLE),
        (False, False, True, 0, Verdict.DEGRADED),
        (False, False, True, 1, Verdict.CULPABLE),
        (False, False, False, 0, Verdict.DEGRADED),
        (False, False, False, 1, Verdict.CULPABLE),
        (True, True, True, 0, Verdict.EXONERATED),
        (True, True, True, 1, Verdict.CULPABLE),
        (True, True, False, 0, Verdict.CULPABLE),
        (True, True, False, 1, Verdict.CULPABLE),
        (True, False, True, 0, Verdict.CULPABLE),
        (True, False, True, 1, Verdict.CULPABLE),
        (True, False, False, 0, Verdict.CULPABLE),
        (True, False, False, 1, Verdict.CULPABLE),
    ]

    mock_blast = {
        "high_centrality_role": True,
        "centrality_rank": 1,
        "role_id": "role-data-reader",
        "role_name": "DataReaderRole",
        "centrality_score": 4.0,
    }

    for p1, p2, p3, p4, expected_v in expected_matrix:
        v, r = assemble_verdict(p1, p2, p3, p4)
        assert v == expected_v, f"Mismatch for inputs ({p1}, {p2}, {p3}, {p4})"
        formatted = format_verdict_result(v, r, p1, p2, p3, p4, blast_radius=mock_blast)
        assert formatted["verdict"] == expected_v.value
        # Assert base signals are intact
        assert formatted["signals"]["p1_path"] == p1
        assert formatted["signals"]["p2_role"] == p2
        assert formatted["signals"]["p3_rule"] == p3
        assert formatted["signals"]["p4_cves"] == p4
        assert formatted["signals"]["blast_radius"] == mock_blast


def test_mcp_surface_remains_strictly_three_tools():
    """Verify that exactly 3 approved MCP tools exist without adding arbitrary query tools."""
    tool_names = set(mcp_server._tool_manager._tools.keys())
    assert len(tool_names) == 3
    assert tool_names == {"investigate_finding", "query_attack_path", "get_decision_history"}


@pytest.mark.asyncio
async def test_mcp_rest_parity_for_blast_radius():
    """Verify that MCP investigate_finding returns signals.blast_radius identical to REST."""
    token = make_test_token(ANALYST_TOKEN_CLAIMS)
    ctx = MagicMock()
    ctx.headers = {"Authorization": f"Bearer {token}"}

    from app.mcp.server import investigate_finding

    mcp_res = await investigate_finding(
        finding_id="finding-01",
        world_time="2026-01-05T00:00:00Z",
        knowledge_time="2026-01-05T00:00:00Z",
        ctx=ctx,
    )

    assert mcp_res["status"] == "COMPLETED"
    assert "blast_radius" in mcp_res["signals"]
    assert mcp_res["signals"]["blast_radius"]["high_centrality_role"] is True
    assert mcp_res["signals"]["blast_radius"]["role_id"] == "role-data-reader"
    assert "Q9_centrality" in mcp_res["graph_evidence"]
