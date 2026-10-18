"""
Bounded FalkorDB query execution.

Caps path depth at 5 hops and result rows at 100 to prevent traversal
exhaustion when the UI slider is being scrubbed aggressively.
"""
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone

from app.graph_client import get_graph_client
from app.config import get_settings
from app.graph.queries import get_query_template, build_query_params


class QueryExecutionError(Exception):
    def __init__(self, reason: str, details: str):
        self.reason = reason
        self.details = details
        super().__init__(f"{reason}: {details}")


class Layer3QueryEngine:
    """
    Wraps FalkorDB graph execution with tenant isolation, depth capping,
    and row capping. All queries go through here: no raw graph.query() calls
    outside this class.
    """

    MAX_DEPTH = 5
    MAX_ROWS = 100

    def __init__(self, client: Optional[Any] = None):
        self.client = client or get_graph_client()
        settings = get_settings()
        self.max_depth = getattr(settings, "max_traversal_depth", self.MAX_DEPTH)
        self.max_rows = getattr(settings, "query_row_cap", self.MAX_ROWS)

    def execute_query(
        self,
        query_name: str,
        finding_id: str,
        tenant_id: str,
        world_time: str,
        knowledge_time: str,
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """
        Run a named query and return (rows, error_code).
        Returns an empty list + diagnostic code on failure; never raises.
        """
        try:
            query = get_query_template(query_name)
            params = build_query_params(finding_id, tenant_id, world_time, knowledge_time)
            result = self.client.execute_query(query, params)

            rows = []
            if result.result_set:
                for row in result.result_set[: self.max_rows]:
                    row_dict = {}
                    for idx, col_name in enumerate(result.header):
                        row_dict[col_name[1]] = row[idx]
                    rows.append(row_dict)

            return (rows, None)

        except Exception as e:
            diagnostic = f"QUERY_EXECUTION_ERROR_{query_name}"
            return ([], diagnostic)

    def execute_topology_check(
        self,
        finding_id: str,
        tenant_id: str,
        world_time: str,
        knowledge_time: str,
    ) -> Tuple[Optional[bool], Optional[Dict[str, Any]]]:
        """
        Q1: does an attack path exist from this finding to a sensitive asset
        at the given (world_time, knowledge_time) pair?
        Returns (True, row) if path exists, (False, None) if verified negative,
        or (None, None) if query execution failed (fail-closed).
        """
        rows, error = self.execute_query("Q1", finding_id, tenant_id, world_time, knowledge_time)
        if error:
            return (None, None)
        if not rows:
            return (False, None)
        return (True, rows[0])

    def execute_rule_check(
        self,
        finding_id: str,
        tenant_id: str,
        world_time: str,
        knowledge_time: str,
    ) -> Tuple[Optional[bool], List[Dict[str, Any]]]:
        """
        Q2: are any governing security rules active at this timestamp pair?
        Returns (True, rows) if rules exist, (False, []) if no rules active,
        or (None, []) if query execution failed (fail-closed).
        """
        rows, error = self.execute_query("Q2", finding_id, tenant_id, world_time, knowledge_time)
        if error:
            return (None, [])
        return (len(rows) > 0, rows)

    def execute_full_investigation(
        self,
        finding_id: str,
        tenant_id: str,
        world_time: str,
        knowledge_time: str,
    ) -> Dict[str, Any]:
        """
        Run the full query suite (Q1-Q7) and return a consolidated result dict.
        Used by POST /api/investigate to build the investigation payload.
        """
        results: Dict[str, Any] = {
            "finding_id": finding_id,
            "tenant_id": tenant_id,
            "world_time": world_time,
            "knowledge_time": knowledge_time,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "queries": {},
        }

        path_exists, path_details = self.execute_topology_check(
            finding_id, tenant_id, world_time, knowledge_time
        )
        results["queries"]["Q1_topology"] = {
            "path_exists": path_exists,
            "path_details": path_details,
        }

        rules_exist, rules = self.execute_rule_check(
            finding_id, tenant_id, world_time, knowledge_time
        )
        results["queries"]["Q2_rules"] = {
            "rules_exist": rules_exist,
            "rules": rules,
        }

        finding_rows, _ = self.execute_query("Q3", finding_id, tenant_id, world_time, knowledge_time)
        results["queries"]["Q3_finding"] = finding_rows[0] if finding_rows else None

        endpoint_rows, _ = self.execute_query("Q4", finding_id, tenant_id, world_time, knowledge_time)
        results["queries"]["Q4_endpoints"] = endpoint_rows

        path_rows, _ = self.execute_query("Q7", finding_id, tenant_id, world_time, knowledge_time)
        results["queries"]["Q7_full_path"] = path_rows

        centrality_rows = self.execute_centrality_check(tenant_id)
        results["queries"]["Q9_centrality"] = centrality_rows

        return results

    def execute_centrality_check(self, tenant_id: str) -> List[Dict[str, Any]]:
        """
        Q9: Betweenness centrality on IAM roles strictly bounded by tenant_id.
        Gracefully returns an empty list if algo is unavailable, graph is empty, or query fails.
        """
        try:
            query = get_query_template("Q9")
            result = self.client.execute_query(query)
            roles = []
            if result.result_set:
                for row in result.result_set:
                    role_id, role_name, t_id, labels, score = row
                    # Strictly tenant-isolate and filter to IAMRole nodes
                    if t_id == tenant_id and "IAMRole" in (labels or []):
                        roles.append({
                            "role_id": role_id,
                            "role_name": role_name,
                            "centrality_score": float(score) if score is not None else 0.0,
                        })

            # Sort highest betweenness first
            roles.sort(key=lambda x: x["centrality_score"], reverse=True)
            for rank, r in enumerate(roles[:10], 1):
                r["centrality_rank"] = rank
            return roles[:10]
        except Exception:
            return []

    def evaluate_blast_radius(
        self,
        tenant_id: str,
        p1_path: bool,
        graph_queries: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Evaluate blast radius based on graph centrality of IAM roles on the active path.
        Bounded, deterministic, fail-safe.
        """
        fallback = {
            "high_centrality_role": False,
            "centrality_rank": None,
            "role_id": None,
            "role_name": None,
            "centrality_score": 0.0,
        }
        if not p1_path:
            return fallback

        try:
            centrality_rows = graph_queries.get("Q9_centrality")
            if centrality_rows is None:
                centrality_rows = self.execute_centrality_check(tenant_id)
            if not centrality_rows:
                return fallback

            top_role = centrality_rows[0]
            top_role_id = top_role.get("role_id")
            if not top_role_id:
                return fallback

            # Check Q1 path_details
            path_details = (graph_queries.get("Q1_topology") or {}).get("path_details") or {}
            path_nodes = path_details.get("path_nodes") or []
            role_in_path = any(top_role_id in str(node) for node in path_nodes)

            # Check Q7 full path if needed
            if not role_in_path:
                for path in graph_queries.get("Q7_full_path") or []:
                    for node in path.get("path_nodes") or []:
                        if node.get("id") == top_role_id:
                            role_in_path = True
                            break

            if role_in_path:
                return {
                    "high_centrality_role": True,
                    "centrality_rank": top_role.get("centrality_rank", 1),
                    "role_id": top_role.get("role_id"),
                    "role_name": top_role.get("role_name"),
                    "centrality_score": top_role.get("centrality_score", 0.0),
                }
            return fallback
        except Exception:
            return fallback


_query_engine: Optional[Layer3QueryEngine] = None


def get_query_engine() -> Layer3QueryEngine:
    global _query_engine
    if _query_engine is None:
        _query_engine = Layer3QueryEngine()
    return _query_engine
