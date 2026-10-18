"""
Integration test suite for bitemporal graph investigation.
Validates dual-clock world time vs knowledge time path visibility in FalkorDB.
"""
import pytest
from app.graph.layer3_envelope import get_query_engine
from app.assembly.policy import assemble_policy_disposition

FINDING_ID = "finding-01"
TENANT_ALPHA = "tenant-corp-alpha"
JAN_2_2026 = "2026-01-02T10:00:00Z"
JAN_5_2026 = "2026-01-05T00:00:00Z"


@pytest.fixture
def query_engine():
    return get_query_engine()


def test_jan_2_evaluation_exonerated(query_engine):
    """Jan 2: Path not yet learned → s_topo=False"""
    path_exists, _ = query_engine.execute_topology_check(
        FINDING_ID, TENANT_ALPHA, JAN_2_2026, JAN_2_2026
    )
    # At Jan 2, IAMRole→SensitiveAsset edge learned_at=Jan 5, so incomplete path
    assert path_exists is False, "Jan 2: Path incomplete (asset edge not learned)"


def test_jan_5_evaluation_path_visible(query_engine):
    """Jan 5: Full path learned → s_topo=True"""
    path_exists, path_details = query_engine.execute_topology_check(
        FINDING_ID, TENANT_ALPHA, JAN_5_2026, JAN_5_2026
    )
    # At Jan 5, all edges learned including IAMRole→SensitiveAsset
    assert path_exists is True, "Jan 5: Full path visible (all edges learned)"
    assert path_details is not None


def test_tenant_isolation(query_engine):
    """Test cross-tenant boundary isolation."""
    results = query_engine.execute_full_investigation(
        FINDING_ID, "tenant-corp-beta", JAN_5_2026, JAN_5_2026
    )
    # Should not return tenant-alpha data
    assert results["queries"]["Q1_topology"]["path_exists"] is False
