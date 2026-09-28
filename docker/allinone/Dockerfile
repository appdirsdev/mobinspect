# All-in-one MobInspect image: Postgres + Ollama (Granite models baked in)
# + Django app (gunicorn) + django-q worker + nginx, all managed by
# supervisord inside a single container. Build context must be the repo
# root, e.g.:
#   docker buildx build --platform linux/amd64 -f docker/allinone/Dockerfile -t mobinspect-allinone:latest .
#
# Persistent state lives in three volumes (see VOLUME below):
#   /var/lib/postgresql/data     - the database
#   /usr/share/ollama/.ollama    - Ollama models (pre-seeded from this image)
#   /home/mobinspect/.MobInspect - uploads/downloads/tools/secrets/config
FROM python:3.13-slim-bookworm

LABEL \
    name="MobInspect (all-in-one)" \
    description="MobInspect — Mobile Application Security Inspector, single-container build with Postgres, Ollama/Granite AI, and nginx bundled in."

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=en_US.UTF-8 \
    LANGUAGE=en_US:en \
    LC_ALL=en_US.UTF-8 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    MOBINSPECT_USER=mobinspect \
    USER_ID=9901 \
    MOBINSPECT_PLATFORM=docker \
    MOBINSPECT_ADB_BINARY=/usr/bin/adb \
    JAVA_HOME=/jdk-22.0.2 \
    PATH=/jdk-22.0.2/bin:/root/.local/bin:/usr/local/bin:$PATH \
    PGDATA=/var/lib/postgresql/data \
    OLLAMA_MODELS=/usr/share/ollama/.ollama/models
# Initial admin credentials are NOT baked into the image. At first boot
# entrypoint.sh/run-django-init.sh runs `manage.py bootstrap_admin`, which
# reads MOBINSPECT_ADMIN_USERNAME / MOBINSPECT_ADMIN_PASSWORD from the
# container env, or generates a 24-char password and writes it to
# ~/.MobInspect/initial-admin-password.txt inside the container. Likewise
# the Postgres app-role password is either MOBINSPECT-operator-supplied
# (POSTGRES_PASSWORD) or auto-generated + persisted on first boot.

RUN apt update -y && \
    apt install -y --no-install-recommends \
    android-sdk-build-tools \
    android-tools-adb \
    build-essential \
    ca-certificates \
    curl \
    fontconfig \
    fontconfig-config \
    git \
    libfontconfig1 \
    libjpeg62-turbo \
    libxext6 \
    libxrender1 \
    locales \
    nginx-light \
    openssl \
    postgresql \
    procps \
    python3-dev \
    sqlite3 \
    supervisor \
    unzip \
    wget \
    xfonts-75dpi \
    xfonts-base \
    zstd && \
    echo "en_US.UTF-8 UTF-8" > /etc/locale.gen && \
    locale-gen en_US.UTF-8 && \
    update-locale LANG=en_US.UTF-8 && \
    apt upgrade -y && \
    curl -sSL https://install.python-poetry.org | python3 - && \
    apt autoremove -y && apt clean -y && rm -rf /var/lib/apt/lists/* /tmp/*

ARG TARGETPLATFORM

# Install wkhtmltopdf and OpenJDK (jadx is installed later, after COPY . .
# makes the mobinspect package importable — see tools_download.py)
COPY scripts/dependencies.sh ./
RUN ./dependencies.sh

# Install Python dependencies
COPY pyproject.toml .
RUN poetry config virtualenvs.create false && \
  poetry lock && \
  poetry install --only main --no-root --no-interaction --no-ansi && \
  poetry cache clear . --all --no-interaction && \
  rm -rf /root/.cache/

# Cleanup
RUN \
    apt remove -y \
        git \
        python3-dev \
        wget && \
    apt clean && \
    apt autoclean && \
    apt autoremove -y && \
    rm -rf /var/lib/apt/lists/* /tmp/* > /dev/null 2>&1

# Create mobinspect user
RUN groupadd --gid $USER_ID $MOBINSPECT_USER && \
    useradd $MOBINSPECT_USER --uid $USER_ID --gid $MOBINSPECT_USER --shell /bin/false --create-home && \
    mkdir -p /home/mobinspect/mobinspect && \
    chown -R $MOBINSPECT_USER:$MOBINSPECT_USER /home/mobinspect

# Copy source code
WORKDIR /home/mobinspect/mobinspect
COPY . .

# Build the Tailwind CSS bundle (see the multi-container Dockerfile for why
# this has to happen after COPY . . and why the CLI binary is removed
# again immediately after — same reasoning applies here verbatim).
RUN ./scripts/install-tailwind.sh && \
    ./scripts/tailwind-build.sh --minify && \
    rm -rf tools/tailwindcss tools/tailwindcss-* && \
    chown -R $MOBINSPECT_USER:$MOBINSPECT_USER /home/mobinspect/mobinspect

# Install JADX now that the mobinspect package is importable — see the
# matching comment in the repo-root Dockerfile for why the explicit
# `test -d` check matters (install_jadx() swallows its own exceptions).
RUN python3 -c "from mobinspect.MobInspect.tools_download import install_jadx; install_jadx('/home/mobinspect/.MobInspect')" && \
    test -x /home/mobinspect/.MobInspect/tools/jadx/jadx-1.5.0/bin/jadx && \
    chown -R $MOBINSPECT_USER:$MOBINSPECT_USER /home/mobinspect/.MobInspect

# --- Ollama + Granite models, baked into the image -------------------------
# The official install script only creates the `ollama` system user + a
# systemd service when it detects systemd, which a Docker build context
# never has — so create the user explicitly rather than depend on that.
RUN useradd --system --home-dir /usr/share/ollama --create-home --shell /usr/sbin/nologin ollama && \
    curl -fsSL https://ollama.com/install.sh | sh

# Model weights are copied in from a local Ollama model cache rather than
# `ollama pull`-ed here: under QEMU emulation (cross-platform buildx builds,
# e.g. building linux/amd64 on an arm64 Mac) the ~5GB granite4.1:8b pull
# reproducibly died with "Error: unexpected EOF" partway through on this
# project (2/2 attempts, same byte range) — a real emulated-network
# reliability issue, not transient flakiness. Model blobs are pure content-
# addressed data (sha256-named), not architecture-specific, so copying an
# already-pulled local cache is both faster and fully reliable. Provide one
# via: docker buildx build --build-context ollama-cache=~/.ollama/models ...
# (any local `ollama pull granite4.1:3b` / `:8b` populates this layout:
# models/manifests/registry.ollama.ai/library/granite4.1/{3b,8b} +
# models/blobs/sha256-<digest> for each layer the manifests reference).
COPY --from=ollama-cache . /usr/share/ollama/.ollama/models
RUN chown -R ollama:ollama /usr/share/ollama && \
    (su ollama -s /bin/bash -c "OLLAMA_HOST=127.0.0.1:11434 /usr/local/bin/ollama serve" > /tmp/ollama-build.log 2>&1 &) && \
    for i in $(seq 1 60); do curl -sf http://127.0.0.1:11434/api/tags >/dev/null 2>&1 && break; sleep 2; done && \
    curl -sf http://127.0.0.1:11434/api/tags | grep -q 'granite4.1:3b' && \
    curl -sf http://127.0.0.1:11434/api/tags | grep -q 'granite4.1:8b' && \
    (pkill -x ollama || true) && sleep 2 && \
    chown -R ollama:ollama /usr/share/ollama

# --- Supervisor-managed multi-process runtime -------------------------------
COPY docker/allinone/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY docker/allinone/run-postgres.sh /usr/local/bin/run-postgres.sh
COPY docker/allinone/run-ollama.sh /usr/local/bin/run-ollama.sh
COPY docker/allinone/run-django-init.sh /usr/local/bin/run-django-init.sh
COPY docker/allinone/run-web.sh /usr/local/bin/run-web.sh
COPY docker/allinone/run-worker.sh /usr/local/bin/run-worker.sh
COPY docker/allinone/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY docker/allinone/nginx.conf /etc/nginx/nginx.conf
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/run-*.sh && \
    mkdir -p /var/lib/postgresql/data /home/mobinspect/.MobInspect && \
    chown -R postgres:postgres /var/lib/postgresql && \
    chown -R $MOBINSPECT_USER:$MOBINSPECT_USER /home/mobinspect/.MobInspect

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=5 \
    CMD curl --fail http://localhost/healthz/ || exit 1

# Web dashboard (via nginx) + dynamic-analysis proxy
EXPOSE 80 1337

# Persistent state — named volumes so first-mount preserves the baked-in
# Ollama models / JADX+tools content (bind mounts do NOT get that
# copy-on-first-mount behavior; see docker/allinone notes in the repo memory
# if migrating an existing bind-mounted deployment).
VOLUME ["/var/lib/postgresql/data", "/usr/share/ollama/.ollama", "/home/mobinspect/.MobInspect"]

# Runs as root: supervisord must be able to launch postgres (as `postgres`),
# ollama (as `ollama`), nginx (root master / www-data workers), and the
# Django processes (as `mobinspect`, dropped via supervisord's per-program
# `user=` directive) — this is the standard, accepted tradeoff for a
# multi-process supervisor container.
CMD ["/usr/local/bin/entrypoint.sh"]
