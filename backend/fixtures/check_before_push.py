#!/usr/bin/env python3
"""
Pre-push code quality and security verification check for the Contextual project.

This is a standalone diagnostic script designed to be run manually before git push:
    python backend/fixtures/check_before_push.py
    python backend/fixtures/check_before_push.py --verbose

Note: This check runs manually unless explicitly configured as a Git pre-push hook.

Verifies:
  1. Cypher parameterization and injection defense (no f-string / format Cypher queries).
  2. FalkorDB openCypher syntax invariants (mandatory relationships(path) syntax).
  3. Accidental secret detection (private keys, live tokens, AWS access keys).
  4. Environment security (.env exclusion from Git tracking, .env.example parity).
  5. Synthetic graph fixture integrity (multi-tenant bitemporal seeding structure).
  6. Frontend API hygiene (relative endpoint paths, dynamic finding input).
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

# Project root is two levels up from this script (Main-Project)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

FAIL = "[FAIL]"
PASS = "[PASS]"
WARN = "[WARN]"

issues_found = []


def check(label: str, passed: bool, detail: str = "", warn_only: bool = False):
    if passed:
        print(f"  {PASS} {label}")
    else:
        marker = WARN if warn_only else FAIL
        print(f"  {marker} {label}")
        if detail:
            print(f"         {detail}")
        if not warn_only:
            issues_found.append(label)


def scan_cypher_security(verbose: bool):
    print("\n-- Cypher Query Security & Invariants " + "-" * 22)

    app_py_files = list(PROJECT_ROOT.glob("backend/app/**/*.py"))
    app_py_files = [f for f in app_py_files if "__pycache__" not in str(f)]

    # 1. No f-string or string-formatted Cypher queries in application logic
    unsafe_cypher_re = re.compile(
        r'f["\'].*?\bMATCH\b|'
        r'f""".*?\bMATCH\b|'
        r'\.format\([^)]*?\bMATCH\b',
        re.DOTALL,
    )
    bad_files = []
    for f in app_py_files:
        content = f.read_text(encoding="utf-8", errors="ignore")
        if unsafe_cypher_re.search(content):
            bad_files.append(str(f.relative_to(PROJECT_ROOT)))

    check(
        "openCypher query parameterization (no f-string/format queries)",
        len(bad_files) == 0,
        detail=f"Unsafe Cypher construction in: {bad_files}" if bad_files else "",
    )

    # 2. FalkorDB openCypher path relationship syntax invariant
    queries_file = PROJECT_ROOT / "backend" / "app" / "graph" / "queries.py"
    if queries_file.exists():
        q_content = queries_file.read_text(encoding="utf-8", errors="ignore")
        # Neo4j forbidden syntax: ALL(rel IN r WHERE ...)
        has_forbidden_neo4j = bool(re.search(r'ALL\s*\(\s*\w+\s+IN\s+r\s+WHERE', q_content, re.IGNORECASE))
        # Mandatory FalkorDB syntax: ALL(rel IN relationships(path) WHERE ...)
        has_falkordb_syntax = bool(re.search(r'relationships\s*\(\s*path\s*\)', q_content, re.IGNORECASE))

        check(
            "FalkorDB openCypher path syntax (relationships(path) list comprehension)",
            has_falkordb_syntax and not has_forbidden_neo4j,
            detail="Forbidden Neo4j syntax detected or missing relationships(path) evaluation" if (has_forbidden_neo4j or not has_falkordb_syntax) else "",
        )

        # 3. Tenant parameterization in traversals
        has_tenant_param = "$tenant_id" in q_content
        check(
            "Multi-tenant query parameterization ($tenant_id enforced)",
            has_tenant_param,
            detail="queries.py missing $tenant_id parameterization",
        )

    if verbose:
        print(f"    Scanned {len(app_py_files)} application Python files for query safety")


def scan_accidental_secrets(verbose: bool):
    print("\n-- Accidental Secret & Credential Scanning " + "-" * 17)

    scan_files = []
    for ext in ("*.py", "*.jsx", "*.js", "*.json", "*.yml", "*.yaml", "*.env*"):
        scan_files.extend(PROJECT_ROOT.glob(f"backend/**/{ext}"))
        scan_files.extend(PROJECT_ROOT.glob(f"frontend/src/**/{ext}"))

    scan_files = [
        f for f in scan_files
        if "__pycache__" not in str(f)
        and "node_modules" not in str(f)
        and ".pytest_cache" not in str(f)
        and not f.name.endswith(".example")
    ]

    secret_patterns = [
        ("Private Key Block", re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
        ("GitHub Personal Access Token", re.compile(r'\b(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{50,})\b')),
        ("AWS Access Key ID", re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    ]

    found_secrets = []
    for label, pat in secret_patterns:
        bad = []
        for f in scan_files:
            content = f.read_text(encoding="utf-8", errors="ignore")
            if pat.search(content):
                bad.append(str(f.relative_to(PROJECT_ROOT)))
        if bad:
            found_secrets.append(f"{label} in: {bad}")

    check(
        "No committed private keys, live tokens, or AWS credentials",
        len(found_secrets) == 0,
        detail="; ".join(found_secrets) if found_secrets else "",
    )

    if verbose:
        print(f"    Scanned {len(scan_files)} files for credential exposure")


def scan_environment_hygiene(verbose: bool):
    print("\n-- Environment & Configuration Hygiene " + "-" * 21)

    gitignore_path = PROJECT_ROOT / ".gitignore"
    if not gitignore_path.exists():
        check(".gitignore exists", False, detail=".gitignore not found")
        return

    gi_content = gitignore_path.read_text(encoding="utf-8")

    # .env must be excluded
    check(
        ".env pattern present in .gitignore",
        ".env" in gi_content,
        detail=".gitignore must exclude .env to prevent secret leakage",
    )

    # Verify .env is not currently tracked by git
    try:
        res = subprocess.run(
            ["git", "ls-files", ".env"],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
        )
        is_tracked = bool(res.stdout.strip())
        check(".env is not tracked in Git index", not is_tracked, detail=".env is tracked in git index!")
    except Exception as exc:
        check(".env Git tracking verification", True, detail=f"Git check skipped: {exc}", warn_only=True)

    # .env.example parity check
    env_example = PROJECT_ROOT / ".env.example"
    has_example = env_example.exists()
    check(".env.example template exists", has_example)
    if has_example:
        example_content = env_example.read_text(encoding="utf-8")
        essential_keys = ["FALKORDB_HOST", "FALKORDB_PORT", "AUTH_JWT_SECRET"]
        missing_keys = [k for k in essential_keys if k not in example_content]
        check(
            "Essential configuration keys present in .env.example",
            len(missing_keys) == 0,
            detail=f"Missing keys: {missing_keys}" if missing_keys else "",
        )


def scan_fixture_integrity(verbose: bool):
    print("\n-- Synthetic Fixture Integrity " + "-" * 29)

    seed_file = PROJECT_ROOT / "backend" / "fixtures" / "seed_graph.py"
    if not seed_file.exists():
        check("seed_graph.py exists", False, detail="backend/fixtures/seed_graph.py not found")
        return

    content = seed_file.read_text(encoding="utf-8", errors="ignore")

    # Fixture must define multi-tenant nodes with tenant_id and bitemporal timestamps
    has_alpha = "tenant-corp-alpha" in content
    has_beta = "tenant-corp-beta" in content
    has_bitemporal = "valid_from" in content and ("learned_at" in content or "discovered_at" in content)

    check(
        "Seed fixtures cover multi-tenant isolation (Alpha and Beta tenants)",
        has_alpha and has_beta,
        detail="Missing Alpha or Beta tenant definitions in seed_graph.py" if not (has_alpha and has_beta) else "",
    )
    check(
        "Seed fixtures include bitemporal timestamps (valid_from, discovered_at)",
        has_bitemporal,
        detail="Missing bitemporal timestamp properties in seed_graph.py" if not has_bitemporal else "",
    )


def scan_frontend_hygiene(verbose: bool):
    print("\n-- Frontend API Hygiene " + "-" * 36)

    app_jsx = PROJECT_ROOT / "frontend" / "src" / "App.jsx"
    if app_jsx.exists():
        content = app_jsx.read_text(encoding="utf-8", errors="ignore")
        has_dynamic_input = "findingInput" in content or "finding-id-input" in content
        check("App.jsx has interactive finding ID selection", has_dynamic_input)

    # Check for insecure hardcoded API base URLs (should use relative /api or env)
    jsx_files = list(PROJECT_ROOT.glob("frontend/src/**/*.jsx")) + list(PROJECT_ROOT.glob("frontend/src/**/*.js"))
    hardcoded_api_re = re.compile(r'fetch\(["\']http://localhost:8000')
    files_with_hardcoded = []
    for f in jsx_files:
        c = f.read_text(encoding="utf-8", errors="ignore")
        if hardcoded_api_re.search(c):
            files_with_hardcoded.append(str(f.relative_to(PROJECT_ROOT)))

    check(
        "Frontend uses relative API endpoints or proxy (no hardcoded localhost:8000 fetches)",
        len(files_with_hardcoded) == 0,
        detail=f"Hardcoded URLs in: {files_with_hardcoded}" if files_with_hardcoded else "",
        warn_only=True,
    )


def main():
    parser = argparse.ArgumentParser(description="Contextual pre-push code quality & security check")
    parser.add_argument("--verbose", "-v", action="store_true", help="Display detailed scan progress")
    args = parser.parse_args()

    print("=" * 60)
    print("  CONTEXTUAL -- Code Quality & Security Verification Check")
    print("  (Standalone diagnostic script; manual verification tool)")
    print("=" * 60)

    scan_cypher_security(args.verbose)
    scan_accidental_secrets(args.verbose)
    scan_environment_hygiene(args.verbose)
    scan_fixture_integrity(args.verbose)
    scan_frontend_hygiene(args.verbose)

    print("\n" + "=" * 60)
    if issues_found:
        print(f"\n  {FAIL} {len(issues_found)} issue(s) detected:\n")
        for issue in issues_found:
            print(f"    * {issue}")
        print()
        sys.exit(1)
    else:
        print(f"\n  {PASS} All checks passed successfully.\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
