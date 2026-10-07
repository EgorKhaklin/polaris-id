# Configuration reference

Generated from `polaris_web/config_schema.py` (`python3 polaris_web/config_schema.py doc`); `check_config_doc_current` holds this file to that rendering. Under `POLARIS_ENV=production` the application validates every setting at boot and refuses to start, naming each one that is wrong. Validate a deployment before starting it with `python3 polaris_web/config_schema.py check --production --env-file FILE`.

A secret is read from its `*_FILE` companion in production. In production a `*_FILE` that is set must be readable and non-empty, and a `file` setting that is set must exist.

## Core

| Setting | Type | Default | Production | Meaning |
|---|---|---|---|---|
| `POLARIS_ENV` | str |  |  | `production` turns on every production guard, this contract included. |
| `POLARIS_SECRET_KEY` | secret | `dev-key-change-in-production` | refuses `dev-key-change-in-production`, `dev-secret-rotate-in-production` | Root secret for sessions and derived tokens. Prefer POLARIS_SECRET_KEY_FILE. |
| `POLARIS_SECRET_KEY_FILE` | secret_file |  | readable, non-empty | File holding POLARIS_SECRET_KEY. |
| `POLARIS_DOMAIN` | str |  |  | Public domain: the TLS edge's site and the WebAuthn relying-party id. |
| `POLARIS_DEPLOYMENT_LABEL` | str |  |  | Provenance label shown by the Atlas. |
| `POLARIS_SECURITY_CONTACT` | str | `mailto:security@example.invalid` | refuses `mailto:security@example.invalid` | security.txt Contact. Unset, it is security@ POLARIS_DOMAIN; production refuses the placeholder. |
| `POLARIS_SECURITY_EXPIRES` | str |  |  | security.txt Expires (ISO 8601); default one year ahead. |
| `POLARIS_SECURITY_LANG` | str | `en` |  | security.txt Preferred-Languages. |
| `POLARIS_STATE_DIR` | dir | `/tmp/polaris-state` |  | Launcher heartbeat and disk-check directory. |

## Server

| Setting | Type | Default | Production | Meaning |
|---|---|---|---|---|
| `POLARIS_PORT` | int | `5000` |  | Port the application listens on. |
| `POLARIS_WORKERS` | int | `1` |  | gunicorn workers. |
| `POLARIS_TIMEOUT` | int | `30` |  | gunicorn worker timeout, seconds; the statement timeout derives from it. |
| `POLARIS_LOG_LEVEL` | enum (debug, info, warning, error, critical) | `info` |  | gunicorn log level. |
| `POLARIS_FORWARDED_ALLOW_IPS` | str | `127.0.0.1` |  | Proxies whose forwarding headers gunicorn trusts. |
| `POLARIS_TRUST_PROXY` | bool |  |  | Trust the edge's X-Request-ID. |

## Database

| Setting | Type | Default | Production | Meaning |
|---|---|---|---|---|
| `POLARIS_DB_HOST` | str | `localhost` |  |  |
| `POLARIS_DB_PORT` | int | `5432` |  |  |
| `POLARIS_DB_NAME` | str | `polaris_test` |  |  |
| `POLARIS_DB_USER` | str | `polaris_app` |  |  |
| `POLARIS_DB_PASSWORD` | secret | `polaris_dev_password` | refuses `polaris_dev_password` | Prefer POLARIS_DB_PASSWORD_FILE. Production refuses the development default. |
| `POLARIS_DB_PASSWORD_FILE` | secret_file |  | readable, non-empty | File holding the database password. |
| `POLARIS_DB_SSLMODE` | enum (disable, allow, prefer, require, verify-ca, verify-full) | `prefer` | one of require, verify-ca, verify-full | libpq sslmode. Production requires an encrypting mode. |
| `POLARIS_DB_SSLROOTCERT` | str |  |  | CA for verify-ca and verify-full; production requires a readable file in those modes. |
| `POLARIS_DB_STATEMENT_TIMEOUT_MS` | int |  |  | Statement timeout; default derives from POLARIS_TIMEOUT. |
| `POLARIS_DB_REPLICA_HOST` | str |  |  | Read replica host (optional). |
| `POLARIS_DB_REPLICA_NAME` | str |  |  | Read replica database name (optional). |
| `POLARIS_DB_REPLICA_PORT` | int |  |  | Read replica port (optional). |
| `POLARIS_REPLICA_MAX_LAG_S` | float | `10` |  | Replica staleness limit before reads fall back to the primary. |

## Signing and custody

| Setting | Type | Default | Production | Meaning |
|---|---|---|---|---|
| `POLARIS_USE_REAL_PQC` | bool | `0` | one of 1, true, yes, on | Real ML-DSA signing. Production requires it. |
| `POLARIS_PQC_PROFILE` | str |  |  | `placeholder` names the development signer and silences its warning. |
| `POLARIS_PQC_ALGORITHM` | str |  |  | Issuer signing algorithm (default ML-DSA-65). |
| `POLARIS_PQC_SIGNING_KEY_FILE` | file |  | must exist if set | File custody: the issuer key. |
| `POLARIS_PQC_TRUST_ANCHORS_FILE` | file |  | must exist if set | Earlier issuer public keys that still verify. |
| `POLARIS_MIGRATION_SIGNING_KEY_FILE` | file |  | must exist if set | Key for a signature migration's target algorithm. |
| `POLARIS_AGENCY_KEYS_DIR` | dir |  |  | Per-agency federation keys. |
| `POLARIS_CREDENTIAL_COPY_KEYS_DIR` | dir |  |  | ES256 wallet-copy keys. |
| `POLARIS_EXPERIMENTAL_SIGNERS` | csv |  |  | Experimental signers allowed outside production. |
| `POLARIS_REQUIRE_HSM_SOLE_SIGNER` | bool |  |  | Refuse any signer outside the HSM. |
| `POLARIS_CUSTODY_DRIVER` | enum ((empty), file, pkcs11, awskms) |  |  | Custody backend; empty means file when a key file is set. |
| `POLARIS_CUSTODY_PKCS11_MODULE` | file |  | must exist if set | PKCS#11 module path. |
| `POLARIS_CUSTODY_PKCS11_TOKEN_LABEL` | str | `polaris` |  |  |
| `POLARIS_CUSTODY_PKCS11_KEY_LABEL` | str | `polaris-issuer` |  |  |
| `POLARIS_CUSTODY_PKCS11_PIN` | secret |  |  | Refused: the PIN must come from a file. |
| `POLARIS_CUSTODY_PKCS11_PIN_FILE` | secret_file |  | readable, non-empty | File holding the token PIN. |
| `POLARIS_CUSTODY_AWSKMS_KEY_ID` | str |  |  |  |
| `POLARIS_CUSTODY_AWSKMS_REGION` | str |  |  |  |
| `POLARIS_CUSTODY_AWSKMS_ENDPOINT_URL` | str |  |  |  |
| `POLARIS_NOBLE_DIR` | dir |  |  | Where @noble/post-quantum is installed for the Falcon witness. |
| `POLARIS_VERIFY_SAMPLE_RATE` | float |  |  | Share of verifications replayed through the second witness. |
| `POLARIS_ZK_BINARY` | str |  |  | The polaris-zk prover and verifier; missing it degrades health rather than stopping boot. |

## Sealed secret store

| Setting | Type | Default | Production | Meaning |
|---|---|---|---|---|
| `POLARIS_SECRETS_BACKEND` | enum (file, age, awskms) | `file` |  |  |
| `POLARIS_SECRETS_PLAIN_DIR` | dir | `polaris_web/secrets` |  |  |
| `POLARIS_SECRETS_SEALED_DIR` | dir | `polaris_web/secrets.sealed` |  |  |
| `POLARIS_SECRETS_AGE_IDENTITY` | str |  |  |  |
| `POLARIS_SECRETS_AGE_RECIPIENTS` | str |  |  |  |
| `POLARIS_SECRETS_AWSKMS_KEY_ID` | str |  |  |  |
| `POLARIS_SECRETS_AWSKMS_REGION` | str |  |  |  |
| `POLARIS_SECRETS_AWSKMS_ENDPOINT_URL` | str |  |  |  |

## Sessions, operators and access

| Setting | Type | Default | Production | Meaning |
|---|---|---|---|---|
| `POLARIS_COOKIE_SECURE` | bool |  |  | Secure cookies outside production (always on in production). |
| `POLARIS_HSTS` | bool |  |  | Strict-Transport-Security from the application. |
| `POLARIS_SESSION_MAX` | int |  |  | Concurrent sessions per operator. |
| `POLARIS_SESSION_MAX_<ROLE>` | int |  |  | Per-role session cap. |
| `POLARIS_SESSION_IDLE_MINUTES` | int |  |  | Idle timeout. |
| `POLARIS_SESSION_IDLE_MINUTES_<ROLE>` | int |  |  | Per-role idle timeout. |
| `POLARIS_NETWORK_POLICY` | str |  |  | Default network allow-list. |
| `POLARIS_NETWORK_POLICY_<ROLE>` | str |  |  | Per-role network allow-list. |
| `POLARIS_WEBAUTHN_RP_NAME` | str | `Polaris` |  |  |
| `POLARIS_WEBAUTHN_ATTESTATION` | enum (none, indirect, direct, enterprise) | `none` |  |  |
| `POLARIS_WEBAUTHN_USER_VERIFICATION` | enum (preferred, required, discouraged) | `preferred` |  |  |
| `POLARIS_WEBAUTHN_HARDWARE_ONLY` | bool |  |  |  |
| `POLARIS_WEBAUTHN_REQUIRE_ATTESTATION` | bool |  |  |  |
| `POLARIS_WEBAUTHN_ALLOWED_AAGUIDS` | csv |  |  |  |

## Rate limiting

| Setting | Type | Default | Production | Meaning |
|---|---|---|---|---|
| `POLARIS_RATE_LIMIT_BACKEND` | enum (auto, redis, memory) | `auto` |  |  |
| `POLARIS_REDIS_URL` | str |  |  | Shared rate-limit state; needed when more than one process serves. |
| `POLARIS_RATE_LIMIT_LOGIN_MAX` | int |  |  |  |
| `POLARIS_RATE_LIMIT_WRITE_MAX` | int |  |  |  |
| `POLARIS_RATE_LIMIT_WRITE_WINDOW` | int |  |  |  |

## Observability

| Setting | Type | Default | Production | Meaning |
|---|---|---|---|---|
| `POLARIS_OTEL` | bool |  |  | OpenTelemetry tracing. |
| `POLARIS_OTEL_EXCLUDE` | csv | `/api/health/live,/api/health/ready` |  |  |

## Relying-party documents and caches

| Setting | Type | Default | Production | Meaning |
|---|---|---|---|---|
| `POLARIS_STATUS_ASSERTION_TTL` | int | `3600` |  |  |
| `POLARIS_STATUS_BUNDLE_TTL` | int | `3600` |  |  |
| `POLARIS_EPOCH_LEAVES_TTL` | int | `86400` |  |  |
| `POLARIS_EPOCH_CHECKPOINT_TTL` | int | `86400` |  |  |
| `POLARIS_REVOCATION_FEED_TTL` | int | `86400` |  |  |
| `POLARIS_FEDERATION_MANIFEST_TTL` | int | `86400` |  |  |
| `POLARIS_TRUST_LIST_TTL` | int | `86400` |  |  |
| `POLARIS_REGISTRY_TTL` | int | `86400` |  |  |
| `POLARIS_HOLDER_BINDING_TTL` | int | `86400` |  |  |
| `POLARIS_MDOC_TTL` | int | `86400` |  |  |
| `POLARIS_VC_TTL` | int | `3600` |  |  |
| `POLARIS_TRANSPARENCY_ENTRIES_CAP` | int | `1000` |  |  |
| `POLARIS_EXCHANGE_UPSTREAMS` | str |  |  |  |
| `POLARIS_ATLAS_BASEMAP_STYLE_URL` | str |  |  |  |
| `POLARIS_ATLAS_CACHE_TTL` | int | `30` |  |  |
| `POLARIS_ATLAS_CACHE_MAX` | int | `256` |  |  |

## Development and test only

| Setting | Type | Default | Production | Meaning |
|---|---|---|---|---|
| `POLARIS_DEMO_MODE` | bool |  |  | Ignored in production. |
| `POLARIS_SIM_MODE` | bool |  |  | Ignored in production. |
| `POLARIS_LAUNCHER_WATCH` | bool |  |  | macOS launcher heartbeat. |
| `POLARIS_DURESS_SYNC` | bool |  | refuses `1` | Test-only. Production refuses it. |

## Internal

| Setting | Type | Default | Production | Meaning |
|---|---|---|---|---|
| `POLARIS_TRACING_HOOKS_REGISTERED` | bool |  |  | Set by the application itself. |
