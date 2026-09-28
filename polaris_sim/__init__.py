"""polaris_sim - the national simulation and benchmark harness.

A seeded, deterministic simulation of a synthetic United States driven through
the REAL Polaris procedures, constraints, zero-knowledge path, and Atlas, so the
system can be exercised, benchmarked, and hardened at national scale. Notional
data only, run against an expendable database.
"""

import os


class SimulationRefused(RuntimeError):
    """Raised when the simulation would run against a production deployment."""


def assert_expendable() -> None:
    """Refuse to run against production. The simulation writes NOTIONAL events
    through the REAL procedures, so it must only ever touch an expendable
    database. ``POLARIS_ENV=production`` is the web app's own production signal
    (app.py: default SECRET_KEY, plaintext DB and the demo gate all fail-close on
    it); the sim honours the same signal and refuses. This is the hard isolation
    gate the harness was missing: a default test DB name was its only safeguard.
    The web app's live-simulation mode adds its own SIM_MODE gate, likewise
    force-off in production, on top of this."""
    if os.environ.get("POLARIS_ENV", "").lower() == "production":
        raise SimulationRefused(
            "polaris_sim refuses to run under POLARIS_ENV=production: it writes "
            "notional events through the real paths and must only ever touch an "
            "expendable database. Point it at a test deployment (unset POLARIS_ENV).")
