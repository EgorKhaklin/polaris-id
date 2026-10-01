# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
#
# lab/strategy/007/Dockerfile -- the gate (and the agent driver) in one image, for the
# container-only demo (compose.yaml). Build context is the repository root:
#   docker build -f lab/strategy/007/Dockerfile -t polaris-gate .
#
# The image carries only `cryptography` (which brings ML-DSA and ES256); the detached verifier
# needs no second backend here, since cryptography is a witness on its own. Lab image, not a
# product artifact.
FROM python:3.12-slim

RUN pip install --no-cache-dir cryptography

WORKDIR /app
COPY packages/polaris-oid4vp /app/packages/polaris-oid4vp
COPY packages/polaris-verify /app/packages/polaris-verify
COPY lab/strategy/007 /app/lab/strategy/007

ENV PYTHONPATH=/app/packages/polaris-oid4vp:/app/packages/polaris-verify:/app/lab/strategy/007 \
    PYTHONUNBUFFERED=1
WORKDIR /app/lab/strategy/007
