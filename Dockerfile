# Base image
FROM python:3.13-slim-bookworm

LABEL \
    name="MobInspect" \
    description="MobInspect — Mobile Application Security Inspector with a modern UI, dynamic RBAC, and analytics for static, dynamic, and malware analysis of mobile apps."

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
    PATH=/jdk-22.0.2/bin:/root/.local/bin:$PATH
# Initial admin credentials are NOT baked into the image. At first boot
# entrypoint.sh runs `manage.py bootstrap_admin`, which reads
# MOBINSPECT_ADMIN_USERNAME / MOBINSPECT_ADMIN_PASSWORD from the
# container env (mount them as docker secrets in production) or
# generates a 24-char password and writes it to
# ~/.MobInspect/initial-admin-password.txt inside the container.

# See https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run
RUN apt update -y && \
    apt install -y --no-install-recommends \
    android-sdk-build-tools \
    android-tools-adb \
    build-essential \
    curl \
    fontconfig \
    fontconfig-config \
    git \
    libfontconfig1 \
    libjpeg62-turbo \
    libxext6 \
    libxrender1 \
    locales \
    python3-dev \
    sqlite3 \
    unzip \
    wget \
    xfonts-75dpi \
    xfonts-base && \
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

# Copy source code
WORKDIR /home/mobinspect/mobinspect
COPY . .

# Build the Tailwind CSS bundle. mobinspect/static/mobinspect/css/dist/ is
# gitignored (generated output, never committed — see
# mobinspect/static/mobinspect/.gitignore), so it does NOT exist in a fresh
# checkout; without this step the image serves the app with no CSS at all
# (a 404 on app.css that browsers reject as the wrong MIME type). The
# Tailwind CLI itself (tools/tailwindcss, ~40MB) is a build-time-only tool —
# remove it once the CSS is built so it doesn't bloat the runtime image.
RUN ./scripts/install-tailwind.sh && \
    ./scripts/tailwind-build.sh --minify && \
    rm -rf tools/tailwindcss tools/tailwindcss-*

# Install JADX now that the mobinspect package (COPY . . above) is
# importable. install_jadx() catches its own exceptions (by design, so a
# transient network blip never crashes the app's runtime fallback thread —
# see mobinspect/MobInspect/init.py), so a failed download would otherwise
# report success here too; the explicit `test -d` makes a build-time
# failure loud instead of silently shipping an image with no JADX (the
# app would then fall back to downloading it on first container start,
# which defeats the point of an offline-capable image).
RUN python3 -c "from mobinspect.MobInspect.tools_download import install_jadx; install_jadx('/home/mobinspect/.MobInspect')" && \
    test -x /home/mobinspect/.MobInspect/tools/jadx/jadx-1.5.0/bin/jadx
# NOTE: do NOT chown /home/mobinspect/.MobInspect here — the mobinspect
# user/group are not created until the RUN below, so a chown at this point
# fails the build with "invalid user". The recursive `chown -R ...
# /home/mobinspect` in that RUN already covers .MobInspect. (The `test -x`
# above asserts the actual jadx launcher, not just the dir, since
# install_jadx() swallows its own exceptions and a corrupt download can
# leave an empty jadx-1.5.0/ that a bare `test -d` would wrongly accept.)

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl --fail http://localhost:8000/healthz/ || exit 1

# Expose MobInspect Port and Proxy Port
EXPOSE 8000 1337

# Create mobinspect user
RUN groupadd --gid $USER_ID $MOBINSPECT_USER && \
    useradd $MOBINSPECT_USER --uid $USER_ID --gid $MOBINSPECT_USER --shell /bin/false && \
    chown -R $MOBINSPECT_USER:$MOBINSPECT_USER /home/mobinspect

# Switch to mobinspect user
USER $MOBINSPECT_USER

# Run MobInspect
CMD ["/home/mobinspect/mobinspect/scripts/entrypoint.sh"]
