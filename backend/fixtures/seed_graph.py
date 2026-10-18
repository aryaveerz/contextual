"""
Graph topology seeder for contextual security investigation and policy verification.

Run with --dry-run (default) to preview generated Cypher queries.
Run with --write to commit nodes and edges to FalkorDB.

Topology models cross-tier access paths, policy definitions, and IAM roles across
isolated tenant namespaces to evaluate bitemporal path traversals and policy compliance.
"""
import argparse
import os
import sys
from datetime import datetime
from typing import Dict, List

from falkordb import FalkorDB


FALKORDB_HOST = os.environ.get("FALKORDB_HOST", "127.0.0.1")
FALKORDB_PORT = int(os.environ.get("FALKORDB_PORT", "6379"))
GRAPH_NAME = os.environ.get("FALKORDB_GRAPH_NAME", "contextual_security_graph")

TENANT_ALPHA = "tenant-corp-alpha"
TENANT_BETA = "tenant-corp-beta"

# Bitemporal coordinates for validation scenarios
# Incident occurrence timestamp
T_INCIDENT = "2026-01-01T00:00:00Z"
# Scanner ingestion timestamp (delayed detection boundary)
T_SCANNER_RUN = "2026-01-02T00:00:00Z"
# Correlation analysis timestamp
T_CORRELATION = "2026-01-05T00:00:00Z"


def get_seed_queries() -> List[Dict]:
    queries = []

    core_nodes = [
        ("Finding", {
            "id": "finding-priv-esc-01",
            "tenant_id": TENANT_ALPHA,
            "severity": "HIGH",
            "description": "Privilege escalation via unrestricted AssumeRole on DataReaderRole",
            "source": "AWS Access Analyzer",
            "valid_from": T_INCIDENT,
            "learned_at": T_INCIDENT,
        }),
        ("Finding", {
            "id": "finding-stale-key-02",
            "tenant_id": TENANT_ALPHA,
            "severity": "MEDIUM",
            "description": "Stale API access key unused for >90 days on legacy worker",
            "source": "IAM Credential Report",
            "valid_from": T_INCIDENT,
            "learned_at": T_INCIDENT,
        }),
        ("Endpoint", {
            "id": "endpoint-api-gw-prod",
            "tenant_id": TENANT_ALPHA,
            "hostname": "api.acme-corp.internal",
            "ip_address": "10.12.4.50",
            "environment": "production",
            "valid_from": T_INCIDENT,
            "learned_at": T_SCANNER_RUN,   # scanner ran on Jan 2
        }),
        ("Service", {
            "id": "service-customer-api",
            "tenant_id": TENANT_ALPHA,
            "name": "CustomerDataAPI",
            "type": "REST_API",
            "owner": "platform-team",
            "valid_from": T_INCIDENT,
            "learned_at": T_INCIDENT,
        }),
        ("IAMRole", {
            "id": "role-data-reader-prod",
            "tenant_id": TENANT_ALPHA,
            "role_name": "DataReaderRole",
            "arn": "arn:aws:iam::847291036584:role/DataReaderRole",
            "valid_from": T_INCIDENT,
            "learned_at": T_INCIDENT,
        }),
        ("IAMRole", {
            "id": "role-legacy-worker-alpha",
            "tenant_id": TENANT_ALPHA,
            "role_name": "LegacyWorkerRole",
            "arn": "arn:aws:iam::847291036584:role/LegacyWorkerRole",
            "valid_from": T_INCIDENT,
            "learned_at": T_INCIDENT,
        }),
        ("SensitiveAsset", {
            "id": "asset-pii-rds-prod",
            "tenant_id": TENANT_ALPHA,
            "asset_name": "CustomerPIIDatabase",
            "classification": "CONFIDENTIAL",
            "valid_from": T_INCIDENT,
            "learned_at": T_CORRELATION,   # we only learned about this on Jan 5
        }),
        ("SecurityRule", {
            "id": "rule-iam-least-priv-001",
            "tenant_id": TENANT_ALPHA,
            "rule_name": "IAM Least Privilege",
            "policy_type": "ACCESS_CONTROL",
            "valid_from": T_INCIDENT,
            "learned_at": T_INCIDENT,
        }),
    ]

    for label, props in core_nodes:
        set_clause = ", ".join([f"n.{k} = ${k}" for k in props.keys() if k not in ("id", "tenant_id")])
        queries.append({
            "query": f"MERGE (n:{label} {{id: $id, tenant_id: $tenant_id}}) SET {set_clause} RETURN n.id",
            "params": props,
        })

    relationships = [
        ("Finding", "finding-priv-esc-01", "AFFECTS", "Endpoint", "endpoint-api-gw-prod",
         {"valid_from": T_INCIDENT, "learned_at": T_SCANNER_RUN}),
        ("Endpoint", "endpoint-api-gw-prod", "ROUTES_TO", "Service", "service-customer-api",
         {"protocol": "HTTPS", "valid_from": T_INCIDENT, "learned_at": T_INCIDENT}),
        ("Service", "service-customer-api", "ASSUMES", "IAMRole", "role-data-reader-prod",
         {"permission_type": "AssumeRole", "valid_from": T_INCIDENT, "learned_at": T_INCIDENT}),
        ("IAMRole", "role-data-reader-prod", "ACCESSES", "SensitiveAsset", "asset-pii-rds-prod",
         {"access_level": "READ", "valid_from": T_INCIDENT, "learned_at": T_CORRELATION}),
        ("SecurityRule", "rule-iam-least-priv-001", "GOVERNS", "IAMRole", "role-data-reader-prod",
         {"enforcement": "MANDATORY", "valid_from": T_INCIDENT, "learned_at": T_INCIDENT}),
        ("Finding", "finding-stale-key-02", "AFFECTS", "IAMRole", "role-legacy-worker-alpha",
         {"valid_from": T_INCIDENT, "learned_at": T_INCIDENT}),
        ("SecurityRule", "rule-iam-least-priv-001", "GOVERNS", "IAMRole", "role-legacy-worker-alpha",
         {"enforcement": "MANDATORY", "valid_from": T_INCIDENT, "learned_at": T_INCIDENT}),
    ]

    for from_label, from_id, rel_type, to_label, to_id, rel_props in relationships:
        set_clause = ", ".join([f"r.{k} = ${k}" for k in rel_props.keys()])
        queries.append({
            "query": f"""
                MATCH (a:{from_label} {{id: $from_id, tenant_id: $tenant_id}})
                MATCH (b:{to_label} {{id: $to_id, tenant_id: $tenant_id}})
                MERGE (a)-[r:{rel_type} {{tenant_id: $tenant_id}}]->(b)
                SET {set_clause}
                RETURN r
            """,
            "params": {"from_id": from_id, "to_id": to_id, "tenant_id": TENANT_ALPHA, **rel_props},
        })

    # Background infrastructure components within the tenant topology namespace.
    background_services = [
        ("auth-service", "AuthenticationService", "GRPC"),
        ("billing-api", "BillingAPI", "REST_API"),
        ("notification-worker", "NotificationWorker", "WORKER"),
        ("config-service", "ConfigurationService", "REST_API"),
        ("audit-logger", "AuditLogger", "WORKER"),
        ("cache-proxy", "RedisProxyService", "INTERNAL_API"),
        ("file-storage-svc", "FileStorageService", "REST_API"),
        ("search-indexer", "SearchIndexer", "WORKER"),
        ("email-gateway", "EmailGateway", "SMTP"),
        ("webhook-dispatcher", "WebhookDispatcher", "WORKER"),
        ("metrics-collector", "MetricsCollector", "INTERNAL_API"),
        ("session-manager", "SessionManager", "REST_API"),
        ("rate-limiter", "RateLimiter", "INTERNAL_API"),
        ("feature-flags-svc", "FeatureFlagService", "REST_API"),
        ("report-generator", "ReportGenerator", "WORKER"),
    ]

    for svc_id, svc_name, svc_type in background_services:
        queries.append({
            "query": (
                "MERGE (n:Service {id: $id, tenant_id: $tenant_id}) "
                "SET n.name = $name, n.type = $type, n.valid_from = $valid_from, n.learned_at = $learned_at "
                "RETURN n.id"
            ),
            "params": {
                "id": f"svc-{svc_id}",
                "tenant_id": TENANT_ALPHA,
                "name": svc_name,
                "type": svc_type,
                "valid_from": T_INCIDENT,
                "learned_at": T_INCIDENT,
            },
        })

    # Tenant beta: isolated namespace to validate multi-tenant boundary enforcement
    beta_nodes = [
        ("Finding", {
            "id": "finding-beta-01",
            "tenant_id": TENANT_BETA,
            "severity": "HIGH",
            "description": "Federation token leak exposing partner data lake",
            "source": "Partner Gateway Monitor",
            "valid_from": T_INCIDENT,
            "learned_at": T_INCIDENT,
        }),
        ("Endpoint", {
            "id": "endpoint-beta-portal",
            "tenant_id": TENANT_BETA,
            "hostname": "portal.partner-beta.internal",
            "ip_address": "10.20.1.15",
            "environment": "partner-production",
            "valid_from": T_INCIDENT,
            "learned_at": T_INCIDENT,
        }),
        ("Service", {
            "id": "service-partner-gateway",
            "tenant_id": TENANT_BETA,
            "name": "PartnerGatewayService",
            "type": "REST_API",
            "owner": "partner-integration",
            "valid_from": T_INCIDENT,
            "learned_at": T_INCIDENT,
        }),
        ("SensitiveAsset", {
            "id": "asset-partner-vault",
            "tenant_id": TENANT_BETA,
            "asset_name": "PartnerFinancialVault",
            "classification": "CONFIDENTIAL",
            "valid_from": T_INCIDENT,
            "learned_at": T_CORRELATION,
        }),
        ("SecurityRule", {
            "id": "rule-partner-zero-trust",
            "tenant_id": TENANT_BETA,
            "rule_name": "Partner Zero-Trust Isolation",
            "policy_type": "ACCESS_CONTROL",
            "valid_from": T_INCIDENT,
            "learned_at": T_INCIDENT,
        }),
    ]

    for label, props in beta_nodes:
        set_clause = ", ".join([f"n.{k} = ${k}" for k in props.keys() if k not in ("id", "tenant_id")])
        queries.append({
            "query": f"MERGE (n:{label} {{id: $id, tenant_id: $tenant_id}}) SET {set_clause} RETURN n.id",
            "params": props,
        })

    beta_relationships = [
        ("Finding", "finding-beta-01", "AFFECTS", "Endpoint", "endpoint-beta-portal",
         {"valid_from": T_INCIDENT, "learned_at": T_INCIDENT}),
        ("Endpoint", "endpoint-beta-portal", "ROUTES_TO", "Service", "service-partner-gateway",
         {"protocol": "HTTPS", "valid_from": T_INCIDENT, "learned_at": T_INCIDENT}),
        ("Service", "service-partner-gateway", "ACCESSES", "SensitiveAsset", "asset-partner-vault",
         {"access_level": "READ", "valid_from": T_INCIDENT, "learned_at": T_CORRELATION}),
        ("SecurityRule", "rule-partner-zero-trust", "GOVERNS", "Service", "service-partner-gateway",
         {"enforcement": "MANDATORY", "valid_from": T_INCIDENT, "learned_at": T_INCIDENT}),
    ]

    for from_label, from_id, rel_type, to_label, to_id, rel_props in beta_relationships:
        set_clause = ", ".join([f"r.{k} = ${k}" for k in rel_props.keys()])
        queries.append({
            "query": f"""
                MATCH (a:{from_label} {{id: $from_id, tenant_id: $tenant_id}})
                MATCH (b:{to_label} {{id: $to_id, tenant_id: $tenant_id}})
                MERGE (a)-[r:{rel_type} {{tenant_id: $tenant_id}}]->(b)
                SET {set_clause}
                RETURN r
            """,
            "params": {"from_id": from_id, "to_id": to_id, "tenant_id": TENANT_BETA, **rel_props},
        })

    return queries


def seed_graph(write: bool = False):
    print(f"[{datetime.utcnow().isoformat()}] Starting graph seed")
    print(f"Target: {FALKORDB_HOST}:{FALKORDB_PORT} / {GRAPH_NAME}")
    print(f"Mode: {'WRITE' if write else 'DRY-RUN (pass --write to commit)'}")
    print("-" * 60)

    queries = get_seed_queries()

    if not write:
        print(f"\n  {len(queries)} queries ready. Nothing written.\n")
        return

    try:
        client = FalkorDB(host=FALKORDB_HOST, port=FALKORDB_PORT)
        graph = client.select_graph(GRAPH_NAME)
        print("Connected to FalkorDB\n")
    except Exception as e:
        print(f"Connection failed: {e}")
        sys.exit(1)

    ok = 0
    for idx, q in enumerate(queries, 1):
        try:
            graph.query(q["query"], q["params"])
            ok += 1
            if idx % 5 == 0:
                print(f"  {idx}/{len(queries)} done")
        except Exception as e:
            print(f"  Query {idx} failed: {e}")

    print(f"\nDone: {ok}/{len(queries)} queries succeeded\n")

    try:
        r = graph.query(
            "MATCH (n {tenant_id: $tid}) RETURN count(n) AS cnt",
            {"tid": TENANT_ALPHA}
        )
        alpha_count = r.result_set[0][0] if r.result_set else 0
        r = graph.query(
            "MATCH (n {tenant_id: $tid}) RETURN count(n) AS cnt",
            {"tid": TENANT_BETA}
        )
        beta_count = r.result_set[0][0] if r.result_set else 0
        print(f"Node counts: {TENANT_ALPHA}={alpha_count}, {TENANT_BETA}={beta_count}\n")
    except Exception as e:
        print(f"Verification step failed: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="Commit writes to FalkorDB")
    args = parser.parse_args()
    seed_graph(write=args.write)
