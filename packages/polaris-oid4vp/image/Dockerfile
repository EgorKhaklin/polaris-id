# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
#
# The polaris-oid4vp verifier as an image: the released package from PyPI, installed by hash on a
# base pinned by digest, run as a user that is not root. Nothing in it is built from this tree;
# the entrypoint is the package's own command.
#
#   docker build -t polaris-oid4vp packages/polaris-oid4vp/image
#
# README.md beside this file has the two commands a verifier is started with.
FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70

LABEL org.opencontainers.image.title="polaris-oid4vp"
LABEL org.opencontainers.image.description="OpenID4VP 1.0 + HAIP verifier: the released polaris-oid4vp package and its command"
LABEL org.opencontainers.image.source="https://github.com/EgorKhaklin/polaris-id"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# The base's packages brought up to date, so a fixed vulnerability in one is not shipped.
RUN apt-get -o Acquire::Retries=3 update \
    && apt-get -o Acquire::Retries=3 -y upgrade \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Wheels only, each by hash: no source distribution is built in the image.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary :all: -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

# /data is the working directory and the one place the user can write: a volume mounted there
# holds the certificates keygen makes and the result file serve keeps.
RUN useradd --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin verifier \
    && mkdir /data \
    && chown verifier:verifier /data

USER 10001:10001
WORKDIR /data
EXPOSE 9443

ENTRYPOINT ["polaris-oid4vp"]
CMD ["--help"]
