# provisioner: template-enforced create/delete of per-project DB stacks.
# Talks to docker ONLY via provisioner-proxy (DOCKER_HOST); no socket mount.
FROM python:3.12-alpine
RUN apk add --no-cache docker-cli openssl \
 && (apk add --no-cache postgresql17-client || apk add --no-cache postgresql-client)
COPY provisioner.py /app/provisioner.py
COPY aux-bootstrap.sql /app/aux-bootstrap.sql
COPY neon-auth-bootstrap.sql /app/neon-auth-bootstrap.sql
ENV PYTHONUNBUFFERED=1
CMD ["python3", "/app/provisioner.py"]
