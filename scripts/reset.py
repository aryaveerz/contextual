#!/usr/bin/env python3
"""
Contextual: Environment & Audit State Reset Utility.

Resets the SQLite audit store and re-initializes FalkorDB graph state
to return the application to a pristine demo baseline.
"""
import glob
import os
import subprocess
import sys


def remove_audit_db():
    pattern = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "audit_store.db*")
    matches = glob.glob(pattern)
    removed = 0
    for f in matches:
        try:
            os.remove(f)
            removed += 1
        except Exception as e:
            print(f"  [WARN] Could not remove {f}: {e}")
    if removed > 0:
        print(f"  • Removed {removed} SQLite audit store file(s).")
    else:
        print("  • SQLite audit store was already clean.")


def clear_falkordb():
    # Attempt to clear InvestigationDecision nodes via docker compose exec if backend is running
    cmd = [
        "docker", "compose", "exec", "-T", "backend",
        "python", "-c",
        "from falkordb import FalkorDB; "
        "g = FalkorDB(host='falkordb', port=6379).select_graph('contextual_security_graph'); "
        "g.query('MATCH (d:InvestigationDecision) DETACH DELETE d'); "
        "print('Cleared')"
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if res.returncode == 0 and "Cleared" in res.stdout:
            print("  • Cleared prior InvestigationDecision nodes from FalkorDB graph memory.")
            return
    except Exception:
        pass

    # Fallback to local python if FalkorDB is on localhost:6379
    try:
        from falkordb import FalkorDB
        g = FalkorDB(host="127.0.0.1", port=6379).select_graph("contextual_security_graph")
        g.query("MATCH (d:InvestigationDecision) DETACH DELETE d")
        print("  • Cleared prior InvestigationDecision nodes from local FalkorDB graph.")
    except Exception:
        print("  • Note: Run 'docker compose exec backend python fixtures/seed_graph.py --write' to re-sync graph.")


def main():
    print("=" * 65)
    print("  CONTEXTUAL -- Clean Baseline State Reset")
    print("=" * 65)

    remove_audit_db()
    clear_falkordb()

    print("\n  [SUCCESS] System reset to clean baseline state.")
    print("=" * 65)


if __name__ == "__main__":
    main()
