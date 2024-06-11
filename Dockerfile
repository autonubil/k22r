FROM ubuntu:22.04
ARG BUILD_ID
ARG CI_REGISTRY

LABEL maintainer="carsten.zeumer@autonubil.de"


COPY config/k22r.yaml /config/k22r.yaml
COPY k22r /k22r

RUN apt-get update && apt-get install  ca-certificates libpcap0.8 -y && apt-get clean autoclean && apt-get autoremove --yes && rm -rf /var/lib/{apt,dpkg,cache,log}/ && update-ca-certificates

EXPOSE 9843

ENV SENTRY_DSN=https://7bdf42f8a6a0f6842cdc6a6decaba3b5@sentry.genesis.exanio.cloud/31

ENTRYPOINT ["/codex-rimor", "-c", "/config/k22r.yaml"]
