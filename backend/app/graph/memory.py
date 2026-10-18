"""
Persistent Graph-Backed Investigation Memory for FalkorDB.

Persists investigation decisions as :InvestigationDecision nodes connected to
their subject :Finding nodes via :EVALUATED relationships.
Enables cross-session retrieval of prior investigation decisions with full
provenance, temporal coordinates, and RFC 8785 evidence digests.
"""
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from app.graph_client import get_graph_client

logger = logging.getLogger("contextual.graph.memory")

# Static openCypher query templates: fully parameterized, no f-strings
QUERY_CHECK_EXISTING_DECISION = """
MATCH (d:InvestigationDecision {id: $receipt_id})
RETURN d.id AS id, d.tenant_id AS tenant_id, d.finding_id AS finding_id, d.digest AS digest
LIMIT 1
"""

QUERY_FINDING_EXISTS = """
MATCH (f:Finding {id: $finding_id, tenant_id: $tenant_id})
RETURN f.id AS id
LIMIT 1
"""

QUERY_RECORD_DECISION = """
MATCH (f:Finding {id: $finding_id, tenant_id: $tenant_id})
MERGE (d:InvestigationDecision {id: $receipt_id, tenant_id: $tenant_id})
ON CREATE SET
    d.finding_id = $finding_id,
    d.verdict = $verdict,
    d.reason = $reason,
    d.investigator = $investigator,
    d.world_time = $world_time,
    d.knowledge_time = $knowledge_time,
    d.digest = $digest,
    d.created_at = $created_at
MERGE (d)-[r:EVALUATED {tenant_id: $tenant_id}]->(f)
RETURN d.id AS id, f.id AS finding_id
"""

QUERY_PRIOR_DECISIONS = """
MATCH (d:InvestigationDecision {tenant_id: $tenant_id})-[r:EVALUATED {tenant_id: $tenant_id}]->(f:Finding {id: $finding_id, tenant_id: $tenant_id})
RETURN
    d.id AS receipt_id,
    d.finding_id AS finding_id,
    d.tenant_id AS tenant_id,
    d.verdict AS verdict,
    d.reason AS reason,
    d.investigator AS investigator,
    d.world_time AS world_time,
    d.knowledge_time AS knowledge_time,
    d.digest AS evidence_digest,
    d.created_at AS created_at
ORDER BY d.created_at DESC
LIMIT $limit
"""


@dataclass
class GraphMemoryRecord:
    receipt_id: str
    tenant_id: str
    finding_id: str
    verdict: str
    reason: Optional[str]
    investigator: Optional[str]
    world_time: str
    knowledge_time: str
    digest: str
    created_at: str


@dataclass
class GraphMemoryResult:
    success: bool
    decision_id: Optional[str] = None
    error: Optional[str] = None
    conflict: bool = False


class GraphMemoryManager:
    """
    Manages persistent investigation memory nodes and relationships in FalkorDB.
    Maintains strict multi-tenant fences and parameterization on all operations.
    """

    def __init__(self):
        self.client = get_graph_client()

    def finding_exists(self, finding_id: str, tenant_id: str) -> bool:
        """Verify whether a finding node exists for the given tenant."""
        try:
            res = self.client.execute_query(
                QUERY_FINDING_EXISTS,
                {"finding_id": finding_id, "tenant_id": tenant_id},
            )
            return bool(res.result_set)
        except Exception as exc:
            logger.error("Failed to check finding existence: %s", exc)
            raise

    def record_decision(self, record: GraphMemoryRecord) -> GraphMemoryResult:
        """
        Persist an investigation decision node and link it to the finding.
        Idempotent on identical receipt_id; rejects conflicting associations.
        """
        try:
            # 1. Check if a decision with this receipt_id already exists
            existing = self.client.execute_query(
                QUERY_CHECK_EXISTING_DECISION,
                {"receipt_id": record.receipt_id},
            )
            if existing.result_set:
                row = existing.result_set[0]
                # Header mapping
                header_names = [col[1] for col in existing.header]
                row_dict = dict(zip(header_names, row))

                # Check for conflicts
                if (
                    row_dict.get("tenant_id") != record.tenant_id
                    or row_dict.get("finding_id") != record.finding_id
                    or row_dict.get("digest") != record.digest
                ):
                    logger.warning(
                        "Conflicting decision record for receipt %s", record.receipt_id
                    )
                    return GraphMemoryResult(
                        success=False,
                        error="CONFLICT_EXISTING_DECISION",
                        conflict=True,
                    )
                # Exact match - idempotent success
                return GraphMemoryResult(success=True, decision_id=record.receipt_id)

            # 2. Check if the target finding exists for this tenant
            if not self.finding_exists(record.finding_id, record.tenant_id):
                logger.warning(
                    "Target finding %s does not exist for tenant %s",
                    record.finding_id,
                    record.tenant_id,
                )
                return GraphMemoryResult(
                    success=False,
                    error="FINDING_NOT_FOUND",
                )

            # 3. Write decision node and evaluated relationship
            params = {
                "receipt_id": record.receipt_id,
                "tenant_id": record.tenant_id,
                "finding_id": record.finding_id,
                "verdict": record.verdict,
                "reason": record.reason or "",
                "investigator": record.investigator or "",
                "world_time": record.world_time,
                "knowledge_time": record.knowledge_time,
                "digest": record.digest,
                "created_at": record.created_at,
            }

            res = self.client.execute_query(QUERY_RECORD_DECISION, params)
            if res.result_set:
                return GraphMemoryResult(success=True, decision_id=record.receipt_id)

            return GraphMemoryResult(
                success=False,
                error="FAILED_TO_CREATE_DECISION",
            )

        except Exception as exc:
            logger.error(
                "Graph memory persistence error for receipt %s: %s",
                record.receipt_id,
                exc,
            )
            return GraphMemoryResult(
                success=False,
                error=f"GRAPH_PERSISTENCE_ERROR: {str(exc)}",
            )

    def get_finding_history(
        self,
        finding_id: str,
        tenant_id: str,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve prior investigation decisions for a finding under the authenticated tenant.
        Raises an exception if the database query fails.
        """
        limit = max(1, min(limit, 100))
        params = {
            "finding_id": finding_id,
            "tenant_id": tenant_id,
            "limit": limit,
        }

        res = self.client.execute_query(QUERY_PRIOR_DECISIONS, params)
        records = []
        if res.result_set:
            header_names = [col[1] for col in res.header]
            for row in res.result_set:
                records.append(dict(zip(header_names, row)))

        return records


_graph_memory_manager: Optional[GraphMemoryManager] = None


def get_graph_memory_manager() -> GraphMemoryManager:
    global _graph_memory_manager
    if _graph_memory_manager is None:
        _graph_memory_manager = GraphMemoryManager()
    return _graph_memory_manager
