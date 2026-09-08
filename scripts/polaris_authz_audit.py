#!/usr/bin/env python3
"""polaris_authz_audit.py — unified authorization-as-code report (v9.19).

Polaris's authorization model is distributed across four surfaces:
  1. `polaris_web/app.py`  — `@security.login_required` + `@security.require_role(...)` decorators
  2. `polaris_sql/09_grants.sql` — PostgreSQL GRANT statements (table-level)
  3. `IssuerDiscretionPolicy`     — per-agency policy rows (DB; optional)
  4. `AppUser.role` enum         — the role set itself

No single surface answers "who can do what." This script walks all four,
unifies the data, and emits a report.

Output sections:
  §I.  By route: HTTP path + method + required roles
  §II. By role: which routes each role can access
  §III. By table: which roles have which GRANTs
  §IV. Drift / gaps:
        - routes with no authz decorator (anonymous-reachable)
        - routes with role gate but no login gate (suspicious)
        - roles named in routes but absent from AppUser.role CHECK
        - tables in 01_schema.sql with no GRANT in 09_grants.sql

CLI:
    python3 polaris_authz_audit.py             # human-readable
    python3 polaris_authz_audit.py --json      # JSON (audit trail)
    python3 polaris_authz_audit.py --role NAME # filter to one role
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP_PY = ROOT / "polaris_web" / "app.py"
GRANTS_SQL = ROOT / "polaris_sql" / "09_grants.sql"
SCHEMA_SQL = ROOT / "polaris_sql" / "01_schema.sql"
AUTH_SQL = ROOT / "polaris_sql" / "10_auth.sql"

# ANSI colors (off when not a TTY)
if sys.stdout.isatty():
    BOLD = "\033[1m"; G = "\033[0;32m"; Y = "\033[0;33m"; R = "\033[0;31m"
    DIM = "\033[2m"; CYAN = "\033[0;36m"; GOLD = "\033[38;5;220m"
    PURPLE = "\033[0;35m"; NC = "\033[0m"
else:
    BOLD = G = Y = R = DIM = CYAN = GOLD = PURPLE = NC = ""


def parse_app_routes() -> list[dict[str, Any]]:
    """Walk app.py for @app.route decorator + the function below it.

    For each function, collect:
      - path
      - methods
      - login_required (bool)
      - required_roles (list[str]; empty if none)
      - csrf_protect (bool)
      - function_name + line number for citation
    """
    if not APP_PY.exists():
        return []
    src = APP_PY.read_text(errors="replace")
    lines = src.splitlines()

    routes = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m_route = re.match(
            r"^@app\.route\(\s*['\"]([^'\"]+)['\"](?:\s*,\s*methods\s*=\s*\[([^\]]+)\])?",
            line,
        )
        if not m_route:
            i += 1
            continue
        path = m_route.group(1)
        methods_raw = m_route.group(2) or "'GET'"
        methods = [m.strip(" '\"") for m in methods_raw.split(",")]

        # Scan forward for decorators + function def
        login_required = False
        roles: list[str] = []
        csrf_protect = False
        func_name = "<unknown>"
        func_line = i + 1
        j = i + 1
        while j < len(lines):
            ln = lines[j]
            if re.match(r"^@security\.login_required\b", ln):
                login_required = True
            elif re.match(r"^@security\.csrf_protect\b", ln):
                csrf_protect = True
            else:
                m_role = re.match(r"^@security\.require_role\((.+?)\)", ln)
                if m_role:
                    for token in m_role.group(1).split(","):
                        token = token.strip().strip("'\"")
                        if token:
                            roles.append(token)
            m_def = re.match(r"^def\s+(\w+)\s*\(", ln)
            if m_def:
                func_name = m_def.group(1)
                func_line = j + 1
                break
            j += 1

        routes.append({
            "path": path,
            "methods": methods,
            "login_required": login_required,
            "required_roles": roles,
            "csrf_protect": csrf_protect,
            "function": func_name,
            "line": func_line,
        })
        i = j + 1
    return routes


def parse_grants() -> list[dict[str, str]]:
    """Walk 09_grants.sql for GRANT statements.

    Returns: list of {action, target, grantee, raw}.
    """
    if not GRANTS_SQL.exists():
        return []
    src = GRANTS_SQL.read_text(errors="replace")
    grants = []
    # Match: GRANT <actions> ON <target> TO <grantee>;
    grant_re = re.compile(
        r"GRANT\s+([A-Z, ]+?)\s+ON\s+(?:TABLE\s+)?([\w.]+|ALL\s+TABLES.*?)\s+TO\s+(\w+)",
        re.IGNORECASE | re.DOTALL,
    )
    for m in grant_re.finditer(src):
        actions = re.sub(r"\s+", " ", m.group(1)).strip()
        target = re.sub(r"\s+", " ", m.group(2)).strip()
        grantee = m.group(3).strip()
        grants.append({
            "actions": actions,
            "target": target,
            "grantee": grantee,
        })
    return grants


def parse_schema_tables() -> list[str]:
    """List of table names from 01_schema.sql."""
    if not SCHEMA_SQL.exists():
        return []
    src = SCHEMA_SQL.read_text(errors="replace")
    return [m.group(1).lower()
            for m in re.finditer(r"CREATE TABLE\s+(\w+)", src, re.IGNORECASE)]


def parse_role_check() -> set[str]:
    """Extract the role enum from the AppUser CHECK constraint.

    The AppUser table is defined in 01_schema.sql (not 10_auth.sql; 10_auth
    only seeds rows). The CHECK constraint pattern is:
        CHECK (role IN ('admin', 'operator', 'auditor'))
    """
    # Try both files — schema first, auth as fallback.
    for path in (SCHEMA_SQL, AUTH_SQL):
        if not path.exists():
            continue
        src = path.read_text(errors="replace")
        m = re.search(
            r"CHECK\s*\(\s*role\s+IN\s*\(([^)]+)\)",
            src, re.IGNORECASE | re.DOTALL,
        )
        if m:
            roles = set()
            for token in m.group(1).split(","):
                clean = token.strip().strip("'\"")
                if clean:
                    roles.add(clean)
            return roles
    return set()


def build_report(filter_role: str | None = None) -> dict[str, Any]:
    routes = parse_app_routes()
    grants = parse_grants()
    tables = parse_schema_tables()
    role_enum = parse_role_check()

    # By-role inversion
    by_role: dict[str, list[dict[str, Any]]] = {}
    for r in routes:
        if not r["required_roles"]:
            continue
        for role in r["required_roles"]:
            by_role.setdefault(role, []).append(r)

    # Tables with no GRANT
    granted_targets = {g["target"].lower() for g in grants}
    # Heuristic: "ALL TABLES IN SCHEMA public" covers everything
    covers_all = any("all tables" in t for t in granted_targets)
    if covers_all:
        ungranted_tables: list[str] = []
    else:
        ungranted_tables = [t for t in tables if t not in granted_targets]

    # Drift: routes with required_roles but no login_required
    role_without_login = [r for r in routes
                          if r["required_roles"] and not r["login_required"]]

    # Drift: roles named in routes but not in AppUser.role CHECK enum
    referenced_roles = {role for r in routes for role in r["required_roles"]}
    unknown_roles = referenced_roles - role_enum

    # Public (anonymous-reachable) routes: no login_required AND no roles
    public_routes = [r for r in routes
                     if not r["login_required"] and not r["required_roles"]]

    return {
        "routes": routes,
        "grants": grants,
        "tables": tables,
        "role_enum": sorted(role_enum),
        "by_role": by_role,
        "drift": {
            "role_without_login": role_without_login,
            "unknown_roles_referenced": sorted(unknown_roles),
            "tables_without_grant": ungranted_tables,
        },
        "public_routes": public_routes,
        "filter_role": filter_role,
    }


def render_report(report: dict[str, Any]) -> None:
    print(f"{BOLD}{GOLD}═══ POLARIS AUTHORIZATION-AS-CODE AUDIT ═══{NC}")
    print(f"{DIM}Walks: app.py decorators · 09_grants.sql · AppUser.role enum (10_auth.sql){NC}")
    print()

    role_filter = report.get("filter_role")

    # §I — By route
    print(f"{PURPLE}§I. By route ({len(report['routes'])} total){NC}")
    if role_filter:
        relevant = [r for r in report["routes"]
                    if role_filter in r["required_roles"]]
        print(f"  {DIM}(filtered to routes requiring role '{role_filter}'){NC}\n")
    else:
        relevant = report["routes"]
    for r in relevant[:40]:
        methods = ",".join(r["methods"])
        if r["required_roles"]:
            authz = f"roles=[{', '.join(r['required_roles'])}]"
            color = G
        elif r["login_required"]:
            authz = "login-required"
            color = CYAN
        else:
            authz = "public"
            color = Y
        csrf = " csrf" if r["csrf_protect"] else ""
        print(f"  {color}{methods:>10}{NC} {r['path']:<50} {DIM}{authz}{csrf}{NC} {DIM}(app.py:{r['line']}){NC}")
    if not role_filter and len(report["routes"]) > 40:
        print(f"  {DIM}... and {len(report['routes']) - 40} more{NC}")
    print()

    # §II — By role
    print(f"{PURPLE}§II. By role ({len(report['by_role'])} roles referenced in routes){NC}")
    for role in sorted(report["by_role"].keys()):
        if role_filter and role != role_filter:
            continue
        rs = report["by_role"][role]
        in_enum = role in report["role_enum"]
        marker = f"{G}✓{NC}" if in_enum else f"{R}✗ (NOT IN AppUser.role enum!){NC}"
        print(f"  {BOLD}{role}{NC} {marker} → {len(rs)} route(s):")
        for r in rs[:10]:
            print(f"      {DIM}{','.join(r['methods']):>10}{NC} {r['path']}")
        if len(rs) > 10:
            print(f"      {DIM}... and {len(rs) - 10} more{NC}")
    print()

    # §III — By table (GRANTs)
    print(f"{PURPLE}§III. PostgreSQL GRANTs ({len(report['grants'])} GRANT statements){NC}")
    for g in report["grants"][:20]:
        print(f"  {DIM}GRANT{NC} {CYAN}{g['actions']}{NC} ON {g['target']} TO {BOLD}{g['grantee']}{NC}")
    if len(report["grants"]) > 20:
        print(f"  {DIM}... and {len(report['grants']) - 20} more{NC}")
    print()

    # §IV — Drift / gaps
    print(f"{PURPLE}§IV. Drift / gaps{NC}")
    drift = report["drift"]

    if drift["role_without_login"]:
        print(f"  {Y}⚠ Routes with role-gate but no login-gate (suspicious):{NC}")
        for r in drift["role_without_login"]:
            print(f"      {r['path']}  roles={r['required_roles']}  {DIM}(app.py:{r['line']}){NC}")
    else:
        print(f"  {G}✓{NC} No routes have role-gate without login-gate.")

    if drift["unknown_roles_referenced"]:
        print(f"  {R}✗ Roles referenced in routes but NOT in AppUser.role CHECK enum:{NC}")
        for role in drift["unknown_roles_referenced"]:
            print(f"      {role}")
    else:
        print(f"  {G}✓{NC} All roles referenced in routes are in the AppUser.role enum.")

    if drift["tables_without_grant"]:
        print(f"  {Y}⚠ Tables in 01_schema.sql with no GRANT in 09_grants.sql:{NC}")
        for t in drift["tables_without_grant"][:15]:
            print(f"      {t}")
        if len(drift["tables_without_grant"]) > 15:
            print(f"      {DIM}... and {len(drift['tables_without_grant']) - 15} more{NC}")
    else:
        print(f"  {G}✓{NC} Every schema table is covered by a GRANT (or by ALL TABLES IN SCHEMA).")

    if report["public_routes"]:
        print(f"  {DIM}ℹ Public (anonymous-reachable) routes:{NC} {len(report['public_routes'])} route(s)")
        for r in report["public_routes"][:8]:
            print(f"      {DIM}{','.join(r['methods']):>10}  {r['path']}{NC}")
        if len(report["public_routes"]) > 8:
            print(f"      {DIM}... and {len(report['public_routes']) - 8} more{NC}")
    print()

    # Summary
    n_locked = sum(1 for r in report["routes"] if r["required_roles"])
    n_login_only = sum(1 for r in report["routes"]
                       if r["login_required"] and not r["required_roles"])
    n_public = len(report["public_routes"])
    print(f"{DIM}Summary: {n_locked} role-gated · {n_login_only} login-only · {n_public} public{NC}")


def main(argv: list[str]) -> int:
    json_out = "--json" in argv
    role_filter = None
    if "--role" in argv:
        idx = argv.index("--role")
        if idx + 1 < len(argv):
            role_filter = argv[idx + 1]

    report = build_report(filter_role=role_filter)

    if json_out:
        # Drop the colorized strings; serialize raw structures.
        out = {
            "routes": report["routes"],
            "grants": report["grants"],
            "tables": report["tables"],
            "role_enum": report["role_enum"],
            "by_role": {k: [r["path"] for r in v]
                        for k, v in report["by_role"].items()},
            "drift": {
                "role_without_login_count": len(report["drift"]["role_without_login"]),
                "role_without_login_paths": [r["path"] for r in report["drift"]["role_without_login"]],
                "unknown_roles_referenced": report["drift"]["unknown_roles_referenced"],
                "tables_without_grant": report["drift"]["tables_without_grant"],
            },
            "public_routes": [r["path"] for r in report["public_routes"]],
        }
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        render_report(report)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
