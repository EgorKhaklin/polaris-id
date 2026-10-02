# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
#
# lab/strategy/007/Dockerfile -- the gate (and the agent driver) in one image, for the
# container-only demo (compose.yaml). Build context is the repository root:
#   docker build -f lab/strategy/007/Dockerfile -t polaris-gate .
#
# The image carries only `cryptography` (which brings ML-DSA and ES256); the detached verifier
# needs no second backend here, since cryptography is a witness on its own. Lab image, not a
# product artifact. The base image is pinned by digest and the dependency by hash
# (requirements.txt), so a rebuild gets exactly these bytes.
FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016

COPY lab/strategy/007/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt

WORKDIR /app
COPY packages/polaris-oid4vp /app/packages/polaris-oid4vp
COPY packages/polaris-verify /app/packages/polaris-verify
COPY lab/strategy/007 /app/lab/strategy/007

ENV PYTHONPATH=/app/packages/polaris-oid4vp:/app/packages/polaris-verify:/app/lab/strategy/007 \
    PYTHONUNBUFFERED=1
WORKDIR /app/lab/strategy/007
