# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris-id-cli — Command-line interface to the Polaris Identity Token System.

The package exposes a single console script (``polaris-id``) that wraps the
Polaris use-case stored procedures (UC-1 / UC-4 / UC-5 / UC-6 / UC-7 / UC-8 /
UC-9-initiate / UC-9-complete) plus utility commands (``health``, ``list``,
``inspect``, ``query``, ``transition``, ``user-*``, ``audit-log``).

The CLI talks to a running Polaris database via psycopg2. Configuration is
read from the same ``POLARIS_DB_*`` environment variables the Flask web app
uses — see the package README for the matrix.

``polaris_id_cli.main`` is the programmatic entry point if you want to invoke
the CLI from another Python process:

    from polaris_cli.polaris import main
    main(["health"])

is equivalent to running ``polaris-id health`` at the shell.

License: Apache-2.0. Upstream repository: https://github.com/EgorKhaklin/polaris
"""

__version__ = "9.30.0"
__all__ = ["__version__"]
