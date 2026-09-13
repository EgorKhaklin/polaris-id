"""polaris-verify: a detached verifier for Polaris credentials and signed artifacts.

The primary external door. It runs with no Polaris server, no database and no operator
console: a relying party installs it, configures a trust root, and decides for itself
whether material is authentic.

    pip install polaris-verify
    polaris-verify --pqc-provider auto --pack credential.json

It refuses to start unless the run says what cryptography it is doing (`--pqc-provider`
or `--dev-placeholder`). There is no default and no environment variable for that choice,
because a verifier that quietly stopped verifying still answers every question.
"""
from .verifier import (  # noqa: F401
    CRYPTO_DEV_PLACEHOLDER,
    REAL_PROVIDERS,
    main,
    resolve_crypto_mode,
    stamp_crypto,
)

__version__ = "0.1.0"
