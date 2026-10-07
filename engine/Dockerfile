FROM node:24.21.0-bookworm-slim@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20
RUN apt-get update && apt-get install -y --no-install-recommends python3 git ca-certificates ripgrep && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/security
COPY --chmod=0644 package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY --chmod=0644 runner.mjs token.mjs models.json ./
RUN mkdir /repo /state /scratch && chown node:node /state /scratch
USER node
WORKDIR /scratch
ENV HOME=/scratch/home CODEX_HOME=/scratch/codex CODEX_SECURITY_STATE_DIR=/state PYTHON=/usr/bin/python3 CI=1 NO_UPDATE_NOTIFIER=1 CODEX_SECURITY_NO_UPDATE_NOTICE=1
ENTRYPOINT ["node", "/opt/security/runner.mjs"]
