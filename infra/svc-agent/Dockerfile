# svc-agent — tiny HMAC-authenticated container start/stop agent.
# python:3.12-slim + the STATIC docker CLI binary only (no dockerd, no docker.io
# daemon package). It talks to the locked-down docker-socket-proxy over tcp via
# DOCKER_HOST; the raw socket is never mounted here.
FROM python:3.12-slim

ARG DOCKER_VERSION=27.3.1
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && curl -fsSL "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_VERSION}.tgz" \
    | tar -xz --strip-components=1 -C /usr/local/bin docker/docker \
 && apt-get purge -y curl \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

COPY svc-agent.py /app/svc-agent.py

ENV DOCKER_HOST=tcp://docker-socket-proxy:2375 \
    SVC_AGENT_PORT=8899

# Non-root: the agent only needs to run `docker` against a tcp endpoint.
USER nobody

EXPOSE 8899
CMD ["python", "/app/svc-agent.py"]
