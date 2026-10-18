"""
Cypher queries for the bitemporal graph engine.
Each query takes explicit world_time (vt) and knowledge_time (kt) parameters
so we can reconstruct exactly what was visible at any historical point in time.
"""
from typing import Dict, Any


# Path traversal: walks up to 5 hops from a finding to a sensitive asset.
# We need ALL() on relationships because FalkorDB evaluates path predicates
# differently than Neo4j; using relationships(path) is the correct syntax here.
TOPOLOGY_ATTACK_PATH = """
MATCH path = (f:Finding {id: $finding_id, tenant_id: $tenant_id})-[*1..5]->(a:SensitiveAsset {tenant_id: $tenant_id})
WHERE ALL(rel IN relationships(path) WHERE
    rel.tenant_id = $tenant_id
    AND rel.valid_from <= $vt
    AND (rel.valid_to IS NULL OR rel.valid_to > $vt)
    AND rel.learned_at <= $kt
)
RETURN
    f.id AS finding_id,
    a.id AS asset_id,
    length(path) AS path_length,
    [node IN nodes(path) | labels(node)[0] + ':' + node.id] AS path_nodes
LIMIT 1
"""

# Checks whether any security rule was actively governing the relevant target
# at the given timestamp pair. "Active" means the rule's GOVERNS edge existed
# in world time and we had learned about it by knowledge time.
GOVERNING_RULE_CHECK = """
MATCH (rule:SecurityRule {tenant_id: $tenant_id})-[r:GOVERNS {tenant_id: $tenant_id}]->(target)
WHERE
    r.valid_from <= $vt
    AND (r.valid_to IS NULL OR r.valid_to > $vt)
    AND r.learned_at <= $kt
    AND target.tenant_id = $tenant_id
RETURN
    rule.id AS rule_id,
    rule.rule_name AS rule_name,
    rule.policy_type AS policy_type,
    target.id AS target_id
LIMIT 10
"""

# Simple metadata pull for the finding node itself.
FINDING_METADATA = """
MATCH (f:Finding {id: $finding_id, tenant_id: $tenant_id})
WHERE
    f.valid_from <= $vt
    AND (f.valid_to IS NULL OR f.valid_to > $vt)
    AND f.learned_at <= $kt
RETURN
    f.id AS finding_id,
    f.severity AS severity,
    f.description AS description,
    f.source AS source,
    f.valid_from AS valid_from,
    f.learned_at AS learned_at
"""

# Endpoints the finding directly touches. Used to build the chain visualization.
CONNECTED_ENDPOINTS = """
MATCH (f:Finding {id: $finding_id, tenant_id: $tenant_id})-[r:AFFECTS {tenant_id: $tenant_id}]->(e:Endpoint {tenant_id: $tenant_id})
WHERE
    r.valid_from <= $vt
    AND (r.valid_to IS NULL OR r.valid_to > $vt)
    AND r.learned_at <= $kt
RETURN
    e.id AS endpoint_id,
    e.hostname AS hostname,
    e.ip_address AS ip_address,
    e.environment AS environment
LIMIT 100
"""

# Which services are currently assuming which IAM roles at (vt, kt).
IAM_ROLE_ASSUMPTIONS = """
MATCH (s:Service {tenant_id: $tenant_id})-[r:ASSUMES {tenant_id: $tenant_id}]->(role:IAMRole {tenant_id: $tenant_id})
WHERE
    r.valid_from <= $vt
    AND (r.valid_to IS NULL OR r.valid_to > $vt)
    AND r.learned_at <= $kt
RETURN
    s.id AS service_id,
    s.name AS service_name,
    role.id AS role_id,
    role.role_name AS role_name,
    r.permission_type AS permission_type
LIMIT 100
"""

# IAM roles that can read/write sensitive assets.
SENSITIVE_ASSET_ACCESS = """
MATCH (role:IAMRole {tenant_id: $tenant_id})-[r:ACCESSES {tenant_id: $tenant_id}]->(asset:SensitiveAsset {tenant_id: $tenant_id})
WHERE
    r.valid_from <= $vt
    AND (r.valid_to IS NULL OR r.valid_to > $vt)
    AND r.learned_at <= $kt
RETURN
    role.id AS role_id,
    role.role_name AS role_name,
    asset.id AS asset_id,
    asset.asset_name AS asset_name,
    asset.classification AS classification,
    r.access_level AS access_level
LIMIT 100
"""

# Full multi-hop path enumeration used for the graph canvas visualization.
# Filters by both tenant fence AND time fence on every node and edge.
FULL_PATH_ENUMERATION = """
MATCH path = (f:Finding {id: $finding_id, tenant_id: $tenant_id})-[*1..5]->(target)
WHERE
    ALL(rel IN relationships(path) WHERE
        rel.tenant_id = $tenant_id
        AND rel.valid_from <= $vt
        AND (rel.valid_to IS NULL OR rel.valid_to > $vt)
        AND rel.learned_at <= $kt
    )
    AND ALL(node IN nodes(path) WHERE node.tenant_id = $tenant_id)
RETURN
    [node IN nodes(path) | {
        label: labels(node)[0],
        id: node.id,
        name: COALESCE(node.name, node.hostname, node.role_name, node.asset_name, node.rule_name, node.id)
    }] AS path_nodes,
    [rel IN relationships(path) | type(rel)] AS relationship_types,
    length(path) AS path_length
ORDER BY path_length ASC
LIMIT 100
"""

# Prior decisions retrieved from graph memory for the requested finding.
# Enforces tenant-isolation on both the decision node and the evaluated finding.
PRIOR_DECISIONS = """
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

# Q9: Native betweenness centrality algorithm in FalkorDB.
# Computes graph-wide node betweenness to quantify topological blast-radius.
IAM_CENTRALITY = """
CALL algo.betweenness() YIELD node, score
RETURN
    node.id AS role_id,
    COALESCE(node.role_name, node.id) AS role_name,
    node.tenant_id AS tenant_id,
    labels(node) AS labels,
    score AS centrality_score
"""

_QUERY_MAP = {
    "Q1": TOPOLOGY_ATTACK_PATH,
    "Q2": GOVERNING_RULE_CHECK,
    "Q3": FINDING_METADATA,
    "Q4": CONNECTED_ENDPOINTS,
    "Q5": IAM_ROLE_ASSUMPTIONS,
    "Q6": SENSITIVE_ASSET_ACCESS,
    "Q7": FULL_PATH_ENUMERATION,
    "Q8": PRIOR_DECISIONS,
    "Q9": IAM_CENTRALITY,
}



def get_query_template(query_name: str) -> str:
    if query_name not in _QUERY_MAP:
        raise ValueError(f"No query registered for '{query_name}'. Available: {list(_QUERY_MAP.keys())}")
    return _QUERY_MAP[query_name]


def build_query_params(
    finding_id: str,
    tenant_id: str,
    world_time: str,
    knowledge_time: str
) -> Dict[str, Any]:
    return {
        "finding_id": finding_id,
        "tenant_id": tenant_id,
        "vt": world_time,
        "kt": knowledge_time,
    }
