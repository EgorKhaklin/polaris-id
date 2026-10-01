# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""lab/strategy/007/grants.py -- a holder's agent grant, minted for the gate's tests and demo.

Three ML-DSA-65 keys, as WIRE-SPEC 3.17 has them:
- an issuer, which signs a credential and binds a holder key to it;
- the holder, who signs a grant naming an agent key and the actions it may take, and who alone
  can revoke it;
- the agent, which signs a proof naming one action and the gate's nonce.

The statements are the ones polaris-verify checks, built with its own canonical forms.

    python3 grants.py mint --out DIR --actions read:status,write:config

writes DIR/issuer.pub (the issuer key the gate trusts, hex), DIR/chain.json (credential, binding
and grant), and the holder's and the agent's private keys. Lab keys, made fresh on each run.
"""
import argparse
import datetime
import hashlib
import json
import pathlib
import secrets
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "packages" / "polaris-verify"))

from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: E402

from polaris_verify_cli import verifier as polaris_verify  # noqa: E402

ALG = "ML-DSA-65"


def _iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _now(now=None):
    return now or datetime.datetime.now(datetime.timezone.utc)


class Key:
    def __init__(self, private=None):
        self.private = private or mldsa.MLDSA65PrivateKey.generate()
        self.public_hex = self.private.public_key().public_bytes_raw().hex()

    @classmethod
    def load(cls, path):
        return cls(mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(pathlib.Path(path).read_text().strip())))

    def save(self, path):
        pathlib.Path(path).write_text(self.private.private_bytes_raw().hex() + "\n")

    def sign(self, statement, canonical):
        """Sign SHA3-256 of the canonical statement, as polaris-verify checks it."""
        statement["signature_hex"] = self.private.sign(hashlib.sha3_256(canonical(statement)).digest()).hex()
        statement["public_key_hex"] = self.public_hex
        return statement


def chain(issuer, holder, agent, actions, *, grant_id="grant-0001", limits=None, hours=6,
          binding_hours=24, now=None):
    """A credential, the issuer's binding of the holder key to it, and the holder's grant."""
    now = _now(now)
    token_value = "lab-credential-" + secrets.token_hex(8)
    credential = {"format": "polaris-authenticity-pack/1", "token_value": token_value,
                  "algorithm": ALG, "public_key_hex": issuer.public_hex,
                  "signature_hex": issuer.private.sign(
                      hashlib.sha3_256(token_value.encode("utf-8")).digest()).hex()}
    binding = issuer.sign({
        "format": "polaris-holder-binding/1", "token_value": token_value,
        "holder_public_key_hex": holder.public_hex, "holder_algorithm": ALG,
        "bound_at": _iso(now - datetime.timedelta(days=1)), "status": "active",
        "issued_at": _iso(now - datetime.timedelta(minutes=1)),
        "expires_at": _iso(now + datetime.timedelta(hours=binding_hours)), "algorithm": ALG},
        polaris_verify._holder_binding_canonical)
    grant = holder.sign({
        "format": "polaris-agent-grant/1", "grant_id": grant_id,
        "agent_public_key_hex": agent.public_hex, "agent_algorithm": ALG,
        "actions": list(actions), "limits": dict(limits or {}), "context_id": 1,
        "issued_at": _iso(now - datetime.timedelta(minutes=1)),
        "expires_at": _iso(now + datetime.timedelta(hours=hours)), "algorithm": ALG},
        polaris_verify._agent_grant_canonical)
    return {"credential": credential, "binding": binding, "grant": grant}


def proof(agent, grant, action, nonce, now=None):
    """The agent's proof that it holds the key the grant names, for one action at one nonce."""
    return agent.sign({
        "format": "polaris-agent-proof/1", "grant_id": grant["grant_id"], "action": action,
        "service_nonce": nonce, "issued_at": _iso(_now(now)), "algorithm": ALG},
        polaris_verify._agent_proof_canonical)


def revocation(holder, grant, now=None):
    """The holder ends the grant. It names the grant and the instant, nothing else."""
    return holder.sign({
        "format": "polaris-grant-revocation/1", "grant_id": grant["grant_id"],
        "revoked_at": _iso(_now(now)), "algorithm": ALG},
        polaris_verify._grant_revocation_canonical)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Mint a lab agent grant chain under fresh ML-DSA-65 keys.")
    sub = ap.add_subparsers(dest="command", required=True)
    mint = sub.add_parser("mint")
    mint.add_argument("--out", required=True)
    mint.add_argument("--actions", required=True, help="comma-separated, e.g. read:status,write:config")
    args = ap.parse_args(argv)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    issuer, holder, agent = Key(), Key(), Key()
    actions = [a for a in args.actions.split(",") if a]
    (out / "chain.json").write_text(json.dumps(chain(issuer, holder, agent, actions), indent=1))
    (out / "issuer.pub").write_text(issuer.public_hex + "\n")
    holder.save(out / "holder.key")
    agent.save(out / "agent.key")
    print("minted a grant for %s under issuer %s..." % (", ".join(actions), issuer.public_hex[:16]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
