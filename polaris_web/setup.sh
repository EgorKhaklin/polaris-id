#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# Polaris Web Interface — Setup Script
#
# Creates the polaris_app database role and grants the application-layer
# privileges. Idempotent: safe to re-run after schema changes or full reloads.
#
# Usage:
#     ./setup.sh                              # Uses default password
#     POLARIS_DB_PASSWORD='...' ./setup.sh    # Custom password
#     POLARIS_DB_NAME='polaris' ./setup.sh    # Custom database
#
# Requires: PostgreSQL running, polaris_test database loaded with the SQL
# package (../polaris_sql/00_load_all.sql), ability to run psql as postgres.
# ============================================================================

set -e

PASSWORD="${POLARIS_DB_PASSWORD:-polaris_dev_password}"
DB="${POLARIS_DB_NAME:-polaris_test}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GRANTS_SQL="$SCRIPT_DIR/../polaris_sql/09_grants.sql"

echo "Creating polaris_app role on database $DB..."

if [ -f "$GRANTS_SQL" ]; then
    # Apply the canonical grants file from the SQL package
    su - postgres -c "psql -d $DB -f $GRANTS_SQL"
else
    # Fallback: inline grants if the SQL package isn't co-located
    su - postgres -c "psql -d $DB" <<EOF
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='polaris_app') THEN
        CREATE ROLE polaris_app WITH LOGIN PASSWORD '$PASSWORD';
    END IF;
END\$\$;
GRANT CONNECT ON DATABASE $DB TO polaris_app;
GRANT USAGE ON SCHEMA public TO polaris_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO polaris_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO polaris_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO polaris_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO polaris_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO polaris_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT EXECUTE ON FUNCTIONS TO polaris_app;
EOF
fi

# If the user provided a custom password, update the role
if [ "$PASSWORD" != "polaris_dev_password" ]; then
    su - postgres -c "psql -d $DB -c \"ALTER ROLE polaris_app WITH PASSWORD '$PASSWORD'\""
fi

echo ""
echo "Verifying connection..."
PGPASSWORD="$PASSWORD" psql -h localhost -U polaris_app -d "$DB" \
    -c "SELECT COUNT(*) AS tables_visible FROM information_schema.tables WHERE table_schema='public';" \
    || (echo "Connection test failed — check pg_hba.conf allows password auth from localhost" && exit 1)

echo ""
echo "Setup complete. To start the app:"
echo "    pip3 install --break-system-packages flask psycopg2-binary"
echo "    python3 app.py"
echo ""
echo "Then open http://localhost:5000"
