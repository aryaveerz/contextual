#!/usr/bin/env python3
"""
Contextual: Container Port & URL Discovery Tool.

Queries running Docker Compose containers for their dynamically allocated
host ports and reports the accessible loopback URLs for the Web UI and API.
Also verifies container readiness via HTTP health checks.
"""
import subprocess
import sys
import urllib.request


def get_container_port(service: str, container_port: int) -> str:
    """Query Docker Compose for the host loopback port mapped to a container port."""
    try:
        res = subprocess.run(
            ["docker", "compose", "port", service, str(container_port)],
            capture_output=True,
            text=True,
            check=True,
        )
        return res.stdout.strip()
    except Exception:
        return ""


def check_readiness(url: str, timeout: float = 2.0) -> bool:
    """Probe an HTTP endpoint to verify application readiness."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "contextual-healthcheck"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def main():
    print("=" * 65)
    print("  CONTEXTUAL -- Service Port & URL Discovery")
    print("=" * 65)

    frontend_addr = get_container_port("frontend", 80)
    backend_addr = get_container_port("backend", 8000)

    if not frontend_addr and not backend_addr:
        print("\n  [INFO] No running Contextual containers detected.")
        print("  Start the stack with:  docker compose up -d")
        print("  Then run this script to display the assigned URLs.\n")
        sys.exit(0)

    print("\n  Active Services (Loopback Only):")
    if frontend_addr:
        frontend_url = f"http://{frontend_addr}"
        is_ready = check_readiness(f"{frontend_url}/health")
        status_label = "[READY]" if is_ready else "[STARTING]"

        print(f"  • Web UI:      {frontend_url:<30} {status_label}")
        print(f"  • API Proxy:   {frontend_url}/api")
        print(f"  • MCP SSE:     {frontend_url}/mcp/sse")
        print(f"  • Swagger UI:  {frontend_url}/docs")
        print(f"  • Healthcheck: {frontend_url}/health")

    if backend_addr:
        backend_url = f"http://{backend_addr}"
        is_ready = check_readiness(f"{backend_url}/health")
        status_label = "[READY]" if is_ready else "[STARTING]"
        print(f"\n  Direct Backend Access (Optional):")
        print(f"  • Direct API:  {backend_url:<30} {status_label}")

    print("\n  Database Isolation:")
    print("  • FalkorDB:    Internal to Docker bridge network (0 host collisions)")
    print("=" * 65)


if __name__ == "__main__":
    main()
