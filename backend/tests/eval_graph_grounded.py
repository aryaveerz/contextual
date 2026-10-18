"""
Evaluation Suite: Controlled Graph-On vs Graph-Off Investigation Ablation

Proves that FalkorDB graph-grounded reasoning materially contributes to
incident investigations compared to isolated flat-record inspection.

Ablation Comparison Protocol:
1. Identical Input Dataset: The authorized synthetic environment in FalkorDB (tenant-corp-alpha).
2. Controlled Conditions:
   - Condition A (Graph-Off / Flat Record Inspection):
     Only the isolated finding record is visible.
     Without graph traversal, multi-hop reachability to sensitive assets, transitive IAM role
     assumptions, and temporal discovery of intermediate edges cannot be evaluated.
     Baseline limitation: P1 (Attack Path) cannot be evaluated from topology and defaults to False/Unknown.
   - Condition B (Graph-On / FalkorDB Layer 3 Engine):
     Evaluates the full openCypher multi-hop path across Finding, Endpoint, Service, IAMRole,
     and SensitiveAsset with bitemporal constraints ($vt, $kt).
3. Measurable Evaluation Criteria:
   - Multi-Hop Reachability Detection (Did the system discover that the finding reaches SensitiveAsset?)
   - Retrospective Temporal Discrimination (Can the system distinguish Jan 2 undiscovered state from Jan 5 discovered state?)
   - Policy Verdict Accuracy according to the 16-row truth table.
"""
import os
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import pytest

# Ensure backend root is on sys.path when invoked directly as a script
_backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

from app.graph.layer3_envelope import get_query_engine
from app.assembly.policy import assemble_verdict, Verdict, VerdictReason


@dataclass
class AblationTrialResult:
    finding_id: str
    scenario_name: str
    world_time: str
    knowledge_time: str
    # Graph-Off Baseline
    baseline_p1_path: Optional[bool]
    baseline_verdict: str
    baseline_path_hops_discovered: int
    # Graph-On FalkorDB
    graph_p1_path: Optional[bool]
    graph_verdict: str
    graph_path_hops_discovered: int
    graph_material_evidence: List[str]


def run_graph_off_evaluation(finding_meta: Dict[str, Any], user_roles: List[str]) -> Dict[str, Any]:
    """
    Flat record baseline inspection.
    Only attributes directly on the finding node are available.
    Zero graph traversals. Cannot see endpoints, services, IAM roles, or sensitive assets.
    """
    p1_path = False  # Without graph traversal, transitive reachability cannot be established
    p2_role = any(r in user_roles for r in ("security:analyst", "security:reviewer", "security:lead", "security:admin"))
    p3_rule = True   # Static local policy assumption
    p4_cves = 1 if (finding_meta.get("severity") or "").upper() in ("CRITICAL", "HIGH", "MEDIUM") else 0

    verdict, reason = assemble_verdict(p1_path, p2_role, p3_rule, p4_cves)
    return {
        "p1_path": p1_path,
        "verdict": verdict.value,
        "reason": reason.value,
        "path_hops": 0,
        "evidence": ["isolated_finding_record_only"],
    }


def run_graph_on_evaluation(finding_id: str, tenant_id: str, vt: str, kt: str, user_roles: List[str]) -> Dict[str, Any]:
    """
    Graph-grounded FalkorDB Layer 3 query engine.
    Follows multi-hop relationships with strict bitemporal fencing.
    """
    engine = get_query_engine()
    results = engine.execute_full_investigation(finding_id, tenant_id, vt, kt)

    q1 = results["queries"]["Q1_topology"]
    q2 = results["queries"]["Q2_rules"]
    q3 = results["queries"].get("Q3_finding") or {}
    q7 = results["queries"].get("Q7_full_path") or []

    p1_path = q1["path_exists"]
    p2_role = any(r in user_roles for r in ("security:analyst", "security:reviewer", "security:lead", "security:admin"))
    p3_rule = q2["rules_exist"]
    severity = (q3.get("severity") or "").upper()
    p4_cves = 1 if severity in ("CRITICAL", "HIGH", "MEDIUM") else 0

    verdict, reason = assemble_verdict(p1_path, p2_role, p3_rule, p4_cves)

    hops = 0
    node_names = []
    if q1.get("path_exists") and q1.get("path_details"):
        hops = q1["path_details"].get("path_length", 0)
        node_names = q1["path_details"].get("path_nodes", [])

    return {
        "p1_path": p1_path,
        "verdict": verdict.value,
        "reason": reason.value,
        "path_hops": hops,
        "evidence": node_names,
    }


def run_controlled_ablation() -> List[AblationTrialResult]:
    """
    Executes a controlled ablation across two key temporal points:
    1. Jan 2 (T1): Finding reported, but IAM->Asset access not yet discovered.
    2. Jan 5 (T2): Scanner correlates IAM->PII asset access.
    """
    tenant_id = "tenant-corp-alpha"
    finding_id = "finding-01"
    user_roles = ["security:analyst"]

    synthetic_finding_meta = {
        "id": "finding-01",
        "severity": "HIGH",
        "description": "Privilege escalation via unrestricted AssumeRole",
    }

    trials = [
        {
            "scenario": "Jan 2 (Pre-Discovery)",
            "vt": "2026-01-02T10:00:00Z",
            "kt": "2026-01-02T10:00:00Z",
            "expected_graph_p1": False,
            "expected_graph_verdict": "DEGRADED",  # P1=False, P2=True, P3=True, P4=1 -> DEGRADED (isolated vuln)
        },
        {
            "scenario": "Jan 5 (Full Discovery)",
            "vt": "2026-01-05T00:00:00Z",
            "kt": "2026-01-05T00:00:00Z",
            "expected_graph_p1": True,
            "expected_graph_verdict": "CULPABLE",  # P1=True, P2=True, P3=True, P4=1 -> CULPABLE (attack path with CVE)
        },
    ]

    results: List[AblationTrialResult] = []

    for t in trials:
        baseline = run_graph_off_evaluation(synthetic_finding_meta, user_roles)
        graph = run_graph_on_evaluation(finding_id, tenant_id, t["vt"], t["kt"], user_roles)

        trial_res = AblationTrialResult(
            finding_id=finding_id,
            scenario_name=t["scenario"],
            world_time=t["vt"],
            knowledge_time=t["kt"],
            baseline_p1_path=baseline["p1_path"],
            baseline_verdict=baseline["verdict"],
            baseline_path_hops_discovered=baseline["path_hops"],
            graph_p1_path=graph["p1_path"],
            graph_verdict=graph["verdict"],
            graph_path_hops_discovered=graph["path_hops"],
            graph_material_evidence=graph["evidence"],
        )
        results.append(trial_res)

    # 1. Verify Jan 2 Pre-Discovery:
    jan2 = results[0]
    assert jan2.graph_p1_path is False, "FalkorDB must accurately verify no complete path existed at Jan 2"
    assert jan2.graph_verdict == "DEGRADED"

    # 2. Verify Jan 5 Post-Discovery:
    jan5 = results[1]
    assert jan5.graph_p1_path is True, "FalkorDB must uncover the 4-hop attack path at Jan 5"
    assert jan5.graph_path_hops_discovered >= 4, f"Expected >= 4 hops, got {jan5.graph_path_hops_discovered}"
    assert jan5.graph_verdict == "CULPABLE"
    assert len(jan5.graph_material_evidence) >= 5, "Path must contain all intermediate nodes"

    # 3. Verify Baseline Blindness:
    # Notice: In the baseline (graph-off), the verdict NEVER changes between Jan 2 and Jan 5
    # because flat records have zero visibility into network reachability or temporal edge discovery!
    assert jan2.baseline_verdict == jan5.baseline_verdict == "DEGRADED"
    assert jan2.baseline_path_hops_discovered == jan5.baseline_path_hops_discovered == 0

    # 4. Compute actual measured metrics
    temporal_discrimination_graph = (jan2.graph_verdict != jan5.graph_verdict)
    temporal_discrimination_baseline = (jan2.baseline_verdict != jan5.baseline_verdict)

    assert temporal_discrimination_graph is True, "Graph engine successfully discriminated temporal arrival"
    assert temporal_discrimination_baseline is False, "Flat baseline failed to discriminate temporal arrival"
    return results


def test_controlled_graph_ablation():
    """Pytest test case for controlled graph ablation."""
    run_controlled_ablation()


if __name__ == "__main__":
    print("=" * 65)
    print("  CONTEXTUAL - FALKORDB GRAPH GROUNDING ABLATION EVALUATION")
    print("  Hackathon Rule 3 Verification: Graph vs Isolated Record")
    print("=" * 65)
    trial_results = run_controlled_ablation()
    print(f"\n[SCENARIO 1: {trial_results[0].scenario_name}]")
    print(f"  • Baseline (Flat Record):   Path={trial_results[0].baseline_p1_path}, Verdict={trial_results[0].baseline_verdict}")
    print(f"  • FalkorDB (GraphBLAS):     Path={trial_results[0].graph_p1_path}, Verdict={trial_results[0].graph_verdict} (Hops: {trial_results[0].graph_path_hops_discovered})")
    print(f"\n[SCENARIO 2: {trial_results[1].scenario_name}]")
    print(f"  • Baseline (Flat Record):   Path={trial_results[1].baseline_p1_path}, Verdict={trial_results[1].baseline_verdict} (Failed to discover reachability)")
    print(f"  • FalkorDB (GraphBLAS):     Path={trial_results[1].graph_p1_path}, Verdict={trial_results[1].graph_verdict} (Discovered {trial_results[1].graph_path_hops_discovered} hops to SensitiveAsset)")
    print(f"  • Intermediate Evidence:    {' -> '.join(trial_results[1].graph_material_evidence)}")
    print("\n" + "=" * 65)
    print("  EVALUATION OUTCOME: FalkorDB Graph Grounding Confirmed (100% Discrimination)")
    print("=" * 65)
