# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""config_schema.py: every POLARIS_* setting the application reads, in one place.

Lab record 017, phase 1 (the configuration contract). Each setting declares its type, its
default, whether it is a secret, and what production requires of it. Three things use it:

  - app.py, under POLARIS_ENV=production, calls `production_problems()` at boot and refuses to
    start with one report naming every wrong setting, instead of failing later on traffic;
  - operators and installers run `python3 polaris_web/config_schema.py check --production`
    (optionally `--env-file FILE`) before deploying;
  - `python3 polaris_web/config_schema.py doc` renders docs/operator/CONFIG.md, and a check
    holds the committed reference to the rendering.

The guards already in app.py stay where they are; this adds the rules they lacked (an
unreadable secret file, the development database password, the placeholder security contact)
and checks the type of every value that is set. Pure Python: no Flask, no database, so a
check, an installer or a container entrypoint can import it.
"""
from __future__ import annotations

import os
import re
import sys
import urllib.parse
from dataclasses import dataclass

_TRUE = ("1", "true", "yes", "on")
_FALSE = ("0", "false", "no", "off", "")


@dataclass(frozen=True)
class Setting:
    name: str
    kind: str = "str"           # str, int, float, bool, enum, csv, file, dir, secret, secret_file
    default: str | None = None  # the value the code uses when unset; None means unset
    group: str = "general"
    doc: str = ""
    choices: tuple = ()
    prod_choices: tuple = ()    # production narrows the accepted values to these
    prod_required: bool = False
    prod_forbidden_values: tuple = ()
    family: bool = False        # a name pattern such as POLARIS_SESSION_MAX_<ROLE>


def _s(name, kind="str", default=None, group="general", doc="", **kw):
    return Setting(name=name, kind=kind, default=default, group=group, doc=doc, **kw)


SETTINGS: tuple[Setting, ...] = (
    # --- core
    _s("POLARIS_ENV", group="core", doc="`production` turns on every production guard, this contract included."),
    _s("POLARIS_SECRET_KEY", "secret", "dev-key-change-in-production", "core",
       "Root secret for sessions and derived tokens. Prefer POLARIS_SECRET_KEY_FILE.",
       prod_forbidden_values=("dev-key-change-in-production", "dev-secret-rotate-in-production")),
    _s("POLARIS_SECRET_KEY_FILE", "secret_file", None, "core", "File holding POLARIS_SECRET_KEY."),
    _s("POLARIS_SECRET_KEY_FALLBACKS_FILE", "secret_file", None, "core",
       "Keys a rotation retired, one per line: they verify what they signed and sign nothing."),
    _s("POLARIS_DOMAIN", group="core", doc="Public domain: the TLS edge's site and the WebAuthn relying-party id."),
    _s("POLARIS_DEPLOYMENT_LABEL", group="core", doc="Provenance label shown by the Atlas."),
    _s("POLARIS_SECURITY_CONTACT", default="mailto:security@example.invalid", group="core",
       doc="security.txt Contact. Unset, it is security@ POLARIS_DOMAIN; production refuses the placeholder.",
       prod_forbidden_values=("mailto:security@example.invalid",)),
    _s("POLARIS_SECURITY_EXPIRES", group="core", doc="security.txt Expires (ISO 8601); default one year ahead."),
    _s("POLARIS_SECURITY_LANG", default="en", group="core", doc="security.txt Preferred-Languages."),
    _s("POLARIS_STATE_DIR", "dir", "/tmp/polaris-state", "core", doc="Launcher heartbeat and disk-check directory."),
    # --- server
    _s("POLARIS_PORT", "int", "5000", "server", "Port the application listens on."),
    _s("POLARIS_WORKERS", "int", "1", "server", "gunicorn workers."),
    _s("POLARIS_TIMEOUT", "int", "30", "server", "gunicorn worker timeout, seconds; the statement timeout derives from it."),
    _s("POLARIS_LOG_LEVEL", "enum", "info", "server", "gunicorn log level.",
       choices=("debug", "info", "warning", "error", "critical")),
    _s("POLARIS_FORWARDED_ALLOW_IPS", default="127.0.0.1", group="server",
       doc="Proxies whose forwarding headers gunicorn trusts."),
    _s("POLARIS_TRUST_PROXY", "bool", "", "server", "Trust the edge's X-Request-ID."),
    # --- database
    _s("POLARIS_DB_HOST", default="localhost", group="database"),
    _s("POLARIS_DB_PORT", "int", "5432", "database"),
    _s("POLARIS_DB_NAME", default="polaris_test", group="database"),
    _s("POLARIS_DB_USER", default="polaris_app", group="database"),
    _s("POLARIS_DB_PASSWORD", "secret", "polaris_dev_password", "database",
       "Prefer POLARIS_DB_PASSWORD_FILE. Production refuses the development default.",
       prod_forbidden_values=("polaris_dev_password",)),
    _s("POLARIS_DB_PASSWORD_FILE", "secret_file", None, "database", "File holding the database password."),
    _s("POLARIS_DB_SSLMODE", "enum", "prefer", "database", "libpq sslmode. Production requires an encrypting mode.",
       choices=("disable", "allow", "prefer", "require", "verify-ca", "verify-full"),
       prod_choices=("require", "verify-ca", "verify-full")),
    _s("POLARIS_DB_SSLROOTCERT", group="database", doc="CA for verify-ca and verify-full; production requires a readable file in those modes."),
    _s("POLARIS_DB_STATEMENT_TIMEOUT_MS", "int", None, "database", "Statement timeout; default derives from POLARIS_TIMEOUT."),
    _s("POLARIS_DB_POOL_SIZE", "int", "0", "database",
       "Connections each worker keeps and reuses, reset on checkout; 0 opens one per request. "
       "Behind pgbouncer (session mode), colours x workers x size must fit its pool."),
    _s("POLARIS_DB_REPLICA_HOST", group="database", doc="Read replica host (optional)."),
    _s("POLARIS_DB_REPLICA_NAME", group="database", doc="Read replica database name (optional)."),
    _s("POLARIS_DB_REPLICA_PORT", "int", None, "database", "Read replica port (optional)."),
    _s("POLARIS_REPLICA_MAX_LAG_S", "float", "10", "database", "Replica staleness limit before reads fall back to the primary."),
    # --- signing and custody
    _s("POLARIS_USE_REAL_PQC", "bool", "0", "signing", "Real ML-DSA signing. Production requires it.",
       prod_choices=("1", "true", "yes", "on")),
    _s("POLARIS_PQC_PROFILE", group="signing", doc="`placeholder` names the development signer and silences its warning."),
    _s("POLARIS_PQC_ALGORITHM", group="signing", doc="Issuer signing algorithm (default ML-DSA-65)."),
    _s("POLARIS_PQC_SIGNING_KEY_FILE", "file", None, "signing", "File custody: the issuer key."),
    _s("POLARIS_PQC_TRUST_ANCHORS_FILE", "file", None, "signing", "Earlier public keys pqc_signing.verify_token_signature accepts; a rotation uses the key register instead (KEY-CEREMONY.md)."),
    _s("POLARIS_MIGRATION_SIGNING_KEY_FILE", "file", None, "signing", "Key for a signature migration's target algorithm."),
    _s("POLARIS_AGENCY_KEYS_DIR", "dir", None, "signing", "Per-agency federation keys."),
    _s("POLARIS_CREDENTIAL_COPY_KEYS_DIR", "dir", None, "signing", "ES256 wallet-copy keys."),
    _s("POLARIS_EXPERIMENTAL_SIGNERS", "csv", None, "signing", "Experimental signers allowed outside production."),
    _s("POLARIS_REQUIRE_HSM_SOLE_SIGNER", "bool", "", "signing", "Refuse any signer outside the HSM."),
    _s("POLARIS_CUSTODY_DRIVER", "enum", "", "signing", "Custody backend; empty means file when a key file is set.",
       choices=("", "file", "pkcs11", "awskms")),
    _s("POLARIS_CUSTODY_PKCS11_MODULE", "file", None, "signing", "PKCS#11 module path."),
    _s("POLARIS_CUSTODY_PKCS11_TOKEN_LABEL", default="polaris", group="signing"),
    _s("POLARIS_CUSTODY_PKCS11_KEY_LABEL", default="polaris-issuer", group="signing"),
    _s("POLARIS_CUSTODY_PKCS11_PIN", "secret", None, "signing", "Refused: the PIN must come from a file."),
    _s("POLARIS_CUSTODY_PKCS11_PIN_FILE", "secret_file", None, "signing", "File holding the token PIN."),
    _s("POLARIS_CUSTODY_AWSKMS_KEY_ID", group="signing"),
    _s("POLARIS_CUSTODY_AWSKMS_REGION", group="signing"),
    _s("POLARIS_CUSTODY_AWSKMS_ENDPOINT_URL", group="signing"),
    _s("POLARIS_NOBLE_DIR", "dir", None, "signing", "Where @noble/post-quantum is installed for the Falcon witness."),
    _s("POLARIS_VERIFY_SAMPLE_RATE", "float", None, "signing", "Share of verifications replayed through the second witness."),
    _s("POLARIS_ZK_BINARY", group="signing", doc="The polaris-zk prover and verifier; missing it degrades health rather than stopping boot."),
    # --- sealed secret store
    _s("POLARIS_SECRETS_BACKEND", "enum", "file", "secrets", choices=("file", "age", "awskms")),
    _s("POLARIS_SECRETS_PLAIN_DIR", "dir", "polaris_web/secrets", "secrets"),
    _s("POLARIS_SECRETS_SEALED_DIR", "dir", "polaris_web/secrets.sealed", "secrets"),
    _s("POLARIS_SECRETS_AGE_IDENTITY", group="secrets"),
    _s("POLARIS_SECRETS_AGE_RECIPIENTS", group="secrets"),
    _s("POLARIS_SECRETS_AWSKMS_KEY_ID", group="secrets"),
    _s("POLARIS_SECRETS_AWSKMS_REGION", group="secrets"),
    _s("POLARIS_SECRETS_AWSKMS_ENDPOINT_URL", group="secrets"),
    # --- sessions, operators and access
    _s("POLARIS_COOKIE_SECURE", "bool", "", "access", "Secure cookies outside production (always on in production)."),
    _s("POLARIS_HSTS", "bool", "", "access", "Strict-Transport-Security from the application."),
    _s("POLARIS_SESSION_MAX", "int", None, "access", "Concurrent sessions per operator."),
    _s("POLARIS_SESSION_MAX_<ROLE>", "int", None, "access", "Per-role session cap.", family=True),
    _s("POLARIS_SESSION_IDLE_MINUTES", "int", None, "access", "Idle timeout."),
    _s("POLARIS_SESSION_IDLE_MINUTES_<ROLE>", "int", None, "access", "Per-role idle timeout.", family=True),
    _s("POLARIS_NETWORK_POLICY", group="access", doc="Default network allow-list."),
    _s("POLARIS_NETWORK_POLICY_<ROLE>", group="access", doc="Per-role network allow-list.", family=True),
    _s("POLARIS_WEBAUTHN_RP_NAME", default="Polaris", group="access"),
    _s("POLARIS_WEBAUTHN_ATTESTATION", "enum", "none", "access",
       choices=("none", "indirect", "direct", "enterprise")),
    _s("POLARIS_WEBAUTHN_USER_VERIFICATION", "enum", "preferred", "access",
       choices=("preferred", "required", "discouraged")),
    _s("POLARIS_WEBAUTHN_HARDWARE_ONLY", "bool", "", "access"),
    _s("POLARIS_WEBAUTHN_REQUIRE_ATTESTATION", "bool", "", "access"),
    _s("POLARIS_WEBAUTHN_ALLOWED_AAGUIDS", "csv", "", "access"),
    # --- rate limiting
    _s("POLARIS_RATE_LIMIT_BACKEND", "enum", "auto", "limits", choices=("auto", "redis", "memory")),
    _s("POLARIS_REDIS_URL", group="limits", doc="Shared rate-limit state; needed when more than one process serves. "
       "Names the user (redis://polaris@host:6379/0), never the password."),
    _s("POLARIS_REDIS_PASSWORD_FILE", "secret_file", None, "limits",
       "File holding the Redis user's password; production requires it when POLARIS_REDIS_URL is set."),
    _s("POLARIS_RATE_LIMIT_LOGIN_MAX", "int", None, "limits"),
    _s("POLARIS_RATE_LIMIT_WRITE_MAX", "int", None, "limits"),
    _s("POLARIS_RATE_LIMIT_WRITE_WINDOW", "int", None, "limits"),
    # --- observability
    _s("POLARIS_OTEL", "bool", "", "observability", "OpenTelemetry tracing."),
    _s("POLARIS_OTEL_EXCLUDE", "csv", "/api/health/live,/api/health/ready", "observability"),
    _s("POLARIS_TRACING_HOOKS_REGISTERED", "bool", None, "internal", "Set by the application itself."),
    # --- relying-party documents and caches
    _s("POLARIS_STATUS_ASSERTION_TTL", "int", "3600", "documents"),
    _s("POLARIS_STATUS_BUNDLE_TTL", "int", "3600", "documents"),
    _s("POLARIS_EPOCH_LEAVES_TTL", "int", "86400", "documents"),
    _s("POLARIS_EPOCH_CHECKPOINT_TTL", "int", "86400", "documents"),
    _s("POLARIS_REVOCATION_FEED_TTL", "int", "86400", "documents"),
    _s("POLARIS_FEDERATION_MANIFEST_TTL", "int", "86400", "documents"),
    _s("POLARIS_TRUST_LIST_TTL", "int", "86400", "documents"),
    _s("POLARIS_REGISTRY_TTL", "int", "86400", "documents"),
    _s("POLARIS_HOLDER_BINDING_TTL", "int", "86400", "documents"),
    _s("POLARIS_MDOC_TTL", "int", "86400", "documents"),
    _s("POLARIS_VC_TTL", "int", "3600", "documents"),
    _s("POLARIS_TRANSPARENCY_ENTRIES_CAP", "int", "1000", "documents"),
    _s("POLARIS_CHAIN_ANCHORS_CAP", "int", "50", "documents",
       "Most Bitcoin anchor records one /api/v1/transparency/anchors call returns."),
    _s("POLARIS_EXCHANGE_UPSTREAMS", group="documents"),
    _s("POLARIS_ATLAS_BASEMAP_STYLE_URL", default="", group="documents"),
    _s("POLARIS_ATLAS_CACHE_TTL", "int", "30", "documents"),
    _s("POLARIS_ATLAS_CACHE_MAX", "int", "256", "documents"),
    # --- development and test only
    _s("POLARIS_DEMO_MODE", "bool", None, "development", "Ignored in production."),
    _s("POLARIS_SIM_MODE", "bool", None, "development", "Ignored in production."),
    _s("POLARIS_LAUNCHER_WATCH", "bool", None, "development", "macOS launcher heartbeat."),
    _s("POLARIS_DURESS_SYNC", "bool", None, "development", "Test-only. Production refuses it.",
       prod_forbidden_values=("1",)),
)

_BY_NAME = {s.name: s for s in SETTINGS if not s.family}
_FAMILIES = [(re.compile("^" + re.escape(s.name.split("<")[0]) + r"[A-Z0-9_]+$"), s)
             for s in SETTINGS if s.family]


def lookup(name: str) -> Setting | None:
    """The declaration for an environment variable name, including family members."""
    if name in _BY_NAME:
        return _BY_NAME[name]
    for pattern, setting in _FAMILIES:
        if pattern.match(name):
            return setting
    return None


def security_contact(env=None) -> str:
    """security.txt's Contact: the operator's value, else security@ the deployment's domain (the
    mailbox RFC 2142 names for it), else the placeholder that production refuses."""
    env = os.environ if env is None else env
    explicit = (env.get("POLARIS_SECURITY_CONTACT") or "").strip()
    if explicit:
        return explicit
    domain = (env.get("POLARIS_DOMAIN") or "").strip()
    return f"mailto:security@{domain}" if domain else "mailto:security@example.invalid"


_DERIVED = {"POLARIS_SECURITY_CONTACT": security_contact}


def _type_problem(s: Setting, raw: str) -> str | None:
    v = raw.strip()
    if v == "" and s.kind in ("int", "float"):
        return None  # empty means unset, as the application reads it (compose passes "${X:-}")
    if s.kind == "int":
        if not re.fullmatch(r"-?\d+", v):
            return f"{raw!r} is not an integer"
    elif s.kind == "float":
        try:
            float(v)
        except ValueError:
            return f"{raw!r} is not a number"
    elif s.kind == "bool":
        if v.lower() not in _TRUE + _FALSE:
            return f"{raw!r} is not a boolean (use 1 or 0)"
    elif s.kind == "enum":
        if v.lower() not in s.choices:
            return f"{raw!r} is not one of {', '.join(c or '(empty)' for c in s.choices)}"
    return None


def problems(env, production: bool) -> list[str]:
    """Every problem with `env` (a mapping), each as 'NAME: reason'. Outside production only
    malformed values count; production adds what a production deployment must hold."""
    out = []
    for name, raw in sorted(env.items()):
        if not name.startswith("POLARIS_"):
            continue
        s = lookup(name)
        if s is None:
            continue  # unknown names are reported by check_config_schema_covers_env, not at boot
        p = _type_problem(s, raw)
        if p:
            out.append(f"{name}: {p}")
    if not production:
        return out
    for s in SETTINGS:
        if s.family:
            continue
        raw = env.get(s.name)
        value = (raw if raw is not None else (s.default or "")).strip()
        if raw is None and s.name in _DERIVED:
            value = _DERIVED[s.name](env)
        companion = (env.get(s.name + "_FILE") or "").strip() if s.kind == "secret" else ""
        if companion:
            # The file supplies the secret; judge what it holds, not the unset variable's default.
            try:
                with open(companion, "r") as fh:
                    raw, value = fh.read(), ""
                value = raw.strip()
            except OSError:
                continue  # reported against the _FILE setting itself
        if s.prod_choices and value.lower() not in s.prod_choices:
            out.append(f"{s.name}: production requires one of {', '.join(s.prod_choices)}, not {value!r}")
        if s.prod_forbidden_values and value in s.prod_forbidden_values:
            why = "is the shipped placeholder" if raw is None else "is a development value"
            out.append(f"{s.name}: {value!r} {why}; production refuses it")
        if raw is None or not raw.strip():
            continue
        if s.kind == "secret_file":
            try:
                with open(raw.strip(), "r") as fh:
                    if not fh.read().strip():
                        out.append(f"{s.name}: {raw.strip()!r} is empty")
            except OSError as exc:
                out.append(f"{s.name}: {raw.strip()!r} is unreadable ({exc.strerror or exc})")
        elif s.kind == "file" and not os.path.isfile(raw.strip()):
            out.append(f"{s.name}: {raw.strip()!r} is not a file")
    sslmode = (env.get("POLARIS_DB_SSLMODE") or "prefer").strip().lower()
    rootcert = (env.get("POLARIS_DB_SSLROOTCERT") or "").strip()
    if sslmode in ("verify-ca", "verify-full") and not (rootcert and os.path.isfile(rootcert)):
        out.append(f"POLARIS_DB_SSLROOTCERT: POLARIS_DB_SSLMODE={sslmode} needs a pinned CA file, "
                   f"and {rootcert or '(unset)'!r} is not one")
    if (env.get("POLARIS_CUSTODY_PKCS11_PIN") or "").strip():
        out.append("POLARIS_CUSTODY_PKCS11_PIN: the PIN must come from POLARIS_CUSTODY_PKCS11_PIN_FILE")
    # Lab record 017, phase 4a: the rate limiter's Redis authenticates, with a password that
    # lives in a file. One in the URL would sit in the environment, where `docker inspect`
    # and /proc/<pid>/environ show it.
    redis_url = (env.get("POLARIS_REDIS_URL") or "").strip()
    if redis_url:
        try:
            url_password = urllib.parse.urlsplit(redis_url).password
        except ValueError:
            url_password = None
        if url_password:
            out.append("POLARIS_REDIS_URL: carries a password; the password must come from "
                       "POLARIS_REDIS_PASSWORD_FILE")
        elif not (env.get("POLARIS_REDIS_PASSWORD_FILE") or "").strip():
            out.append("POLARIS_REDIS_PASSWORD_FILE: POLARIS_REDIS_URL is set, so production "
                       "requires the Redis user's password file")
    return sorted(set(out))


def production_problems(env=None) -> list[str]:
    return problems(os.environ if env is None else env, production=True)


def report(found: list[str]) -> str:
    lines = [f"\n  FATAL: POLARIS_ENV=production and {len(found)} setting(s) are wrong. Refusing to start.\n"]
    lines += [f"    - {p}\n" for p in found]
    lines.append("  Run: python3 polaris_web/config_schema.py check --production\n"
                 "  Reference: docs/operator/CONFIG.md\n\n")
    return "".join(lines)


_GROUP_TITLES = (
    ("core", "Core"), ("server", "Server"), ("database", "Database"), ("signing", "Signing and custody"),
    ("secrets", "Sealed secret store"), ("access", "Sessions, operators and access"),
    ("limits", "Rate limiting"), ("observability", "Observability"),
    ("documents", "Relying-party documents and caches"), ("development", "Development and test only"),
    ("internal", "Internal"),
)


def render_doc() -> str:
    """docs/operator/CONFIG.md, generated from SETTINGS."""
    out = ["# Configuration reference\n\n",
           "Generated from `polaris_web/config_schema.py` (`python3 polaris_web/config_schema.py doc`); "
           "`check_config_doc_current` holds this file to that rendering. Under `POLARIS_ENV=production` "
           "the application validates every setting at boot and refuses to start, naming each one that "
           "is wrong. Validate a deployment before starting it with "
           "`python3 polaris_web/config_schema.py check --production --env-file FILE`.\n\n",
           "A secret is read from its `*_FILE` companion in production. In production a `*_FILE` that "
           "is set must be readable and non-empty, and a `file` setting that is set must exist.\n"]
    for key, title in _GROUP_TITLES:
        rows = [s for s in SETTINGS if s.group == key]
        if not rows:
            continue
        out.append(f"\n## {title}\n\n| Setting | Type | Default | Production | Meaning |\n|---|---|---|---|---|\n")
        for s in rows:
            kind = s.kind + (" (" + ", ".join(c or "(empty)" for c in s.choices) + ")" if s.choices else "")
            default = "`%s`" % s.default if s.default not in (None, "") else ""
            prod = []
            if s.prod_choices:
                prod.append("one of " + ", ".join(s.prod_choices))
            if s.prod_forbidden_values:
                prod.append("refuses " + ", ".join("`%s`" % v for v in s.prod_forbidden_values))
            if s.kind == "secret_file":
                prod.append("readable, non-empty")
            if s.kind == "file":
                prod.append("must exist if set")
            out.append(f"| `{s.name}` | {kind} | {default} | {'; '.join(prod)} | {s.doc} |\n")
    return "".join(out)


def _read_env_file(path: str) -> dict:
    env = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] not in ("check", "doc"):
        print("usage: config_schema.py check [--production] [--env-file FILE] | doc", file=sys.stderr)
        return 64
    if argv[0] == "doc":
        sys.stdout.write(render_doc())
        return 0
    env = dict(os.environ)
    if "--env-file" in argv:
        env.update(_read_env_file(argv[argv.index("--env-file") + 1]))
    production = "--production" in argv or (env.get("POLARIS_ENV", "").strip().lower() == "production")
    found = problems(env, production)
    if found:
        sys.stderr.write(report(found) if production else "".join(f"  - {p}\n" for p in found))
        return 2 if production else 1
    print("configuration OK" + (" for production" if production else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
