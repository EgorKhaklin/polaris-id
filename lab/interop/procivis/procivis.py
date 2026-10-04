# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Drives Procivis One Core's REST API: the calls an operator would make, nothing more.

One core-server instance holds two organisations, an issuer and a holder. Procivis does the
protocol work on both sides; this program only makes the requests and prints what came back.

  procivis.py issue API TOKEN STATE ISSUER_CA HOST
      issuer: a key, a certificate for it (Procivis makes the CSR, ISSUER_CA certifies it,
      naming HOST), an SD-JWT VC schema (vct urn:eudi:pid:1); holder: a key. Then the issuer
      offers the credential over OpenID4VCI and the holder accepts the offer.
  procivis.py present API TOKEN STATE LAUNCH_URI
      the holder handles the OpenID4VP launch URI and submits the stored credential.
"""
import json
import sys
import urllib.error
import urllib.request

import pki


class Refused(Exception):
    def __init__(self, status, body):
        super().__init__("%s %s" % (status, body))
        self.status, self.body = status, body


def call(api, token, method, path, body=None):
    request = urllib.request.Request(
        api + path, method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        raise Refused(exc.code, exc.read().decode(errors="replace")) from None
    return json.loads(raw) if raw else {}


def refusal(exc):
    """The error code and message Procivis answered with, on one line."""
    try:
        body = json.loads(exc.body)
        cause = body.get("cause") or {}
        text = "%s %s: %s (%s)" % (exc.status, body.get("code"), body.get("message"),
                                   cause.get("message", ""))
    except ValueError:
        text = "%s %s" % (exc.status, exc.body)
    return " ".join(text.split())


def issue(api, token, state_path, issuer_ca, host):
    api_call = lambda method, path, body=None: call(api, token, method, path, body)  # noqa: E731
    issuer_org = api_call("POST", "/api/organisation/v1", {})["id"]
    holder_org = api_call("POST", "/api/organisation/v1", {})["id"]

    def key(org, name):
        return api_call("POST", "/api/key/v1", {
            "organisationId": org, "keyType": "ECDSA", "keyParams": {}, "name": name,
            "storageType": "INTERNAL", "storageParams": {}})["id"]

    issuer_key = key(issuer_org, "issuer")
    csr = api_call("POST", "/api/key/v1/%s/generate-csr" % issuer_key, {
        "profile": "GENERIC", "subject": {"commonName": "Procivis walk issuer"}})["content"]
    with open("issuer.csr", "w") as f:
        f.write(csr)
    pki.sign(issuer_ca, "issuer.csr", host, "issuer-cert")
    with open("issuer-cert.pem") as f:
        chain = f.read()
    issuer = api_call("POST", "/api/identifier/v1", {
        "name": "issuer", "organisationId": issuer_org,
        "certificates": [{"keyId": issuer_key, "chain": chain, "roles": ["ASSERTION_METHOD"]}]})["id"]

    schema = api_call("POST", "/api/credential-schema/v1", {
        "name": "PID", "format": "SD_JWT_VC", "organisationId": issuer_org,
        "schemaId": "urn:eudi:pid:1", "layoutType": "CARD",
        "requiresWalletInstanceAttestation": False,
        "claims": [{"key": k, "datatype": "STRING", "required": True, "claims": []}
                   for k in ("given_name", "family_name")]})["id"]
    claim_ids = {c["key"]: c["id"] for c in api_call(
        "GET", "/api/credential-schema/v1/%s" % schema)["claims"]}

    holder_key = key(holder_org, "holder")
    holder = api_call("POST", "/api/identifier/v1", {
        "name": "holder", "organisationId": holder_org, "key": {"keyId": holder_key}})["id"]

    issued = api_call("POST", "/api/credential/v1", {
        "credentialSchemaId": schema, "issuer": issuer, "protocol": "OPENID4VCI_FINAL1",
        "claimValues": [{"claimId": claim_ids[k], "path": k, "value": v}
                        for k, v in (("given_name", "Erika"), ("family_name", "Mustermann"))]})["id"]
    offer = api_call("POST", "/api/credential/v1/%s/share" % issued)["url"]
    print("OFFERED    " + offer.split("?")[0] + "?...")
    interaction = api_call("POST", "/api/interaction/v1/handle-invitation",
                           {"url": offer, "organisationId": holder_org})["interactionId"]
    held = api_call("POST", "/api/interaction/v1/issuance-accept",
                    {"interactionId": interaction, "identifierId": holder})["credentialIds"][0]
    stored = api_call("GET", "/api/credential/v1/%s" % held)
    print("ISSUED     holder credential %s, state %s" % (held, stored["state"]))
    with open(state_path, "w") as f:
        json.dump({"holder_org": holder_org, "credential": held, "issuer": issuer}, f)


def present(api, token, state_path, uri):
    with open(state_path) as f:
        state = json.load(f)
    try:
        invitation = call(api, token, "POST", "/api/interaction/v1/handle-invitation",
                          {"url": uri, "organisationId": state["holder_org"]})
    except Refused as exc:
        print("REQUEST REFUSED " + refusal(exc))
        return
    interaction, proof = invitation["interactionId"], invitation["proofId"]
    print("REQUEST    %s, protocol %s" % (invitation["interactionType"], invitation.get("protocol")))
    definition = call(api, token, "GET", "/api/proof-request/v2/%s/presentation-definition" % proof)
    # One DCQL credential query, answered with the one stored credential.
    submission = {query: [{"credentialId": state["credential"]}]
                  for query in definition["credentialQueries"]}
    try:
        call(api, token, "POST", "/api/interaction/v2/presentation-submit",
             {"interactionId": interaction, "submission": submission})
    except Refused as exc:
        print("DISPATCH FAILED " + refusal(exc))
        return
    print("DISPATCHED proof %s, state %s" % (
        proof, call(api, token, "GET", "/api/proof-request/v1/%s" % proof)["state"]))


if __name__ == "__main__":
    command, args = sys.argv[1], sys.argv[2:]
    try:
        {"issue": issue, "present": present}[command](*args)
    except Refused as exc:
        sys.exit("procivis.py %s: %s" % (command, refusal(exc)))
