#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${CRTWATCH_REPO_URL:-https://github.com/brightcolor/crt.watch.git}"
INSTALL_DIR="${CRTWATCH_INSTALL_DIR:-/opt/crt.watch}"
APP_PORT="${CRTWATCH_PORT:-8080}"
CONTAINER_PORT="${CRTWATCH_CONTAINER_PORT:-8080}"
# The container runs as the unprivileged user "node" (uid 1000, gid 1000) and must own its data.
DATA_UID="${CRTWATCH_DATA_UID:-1000}"
DATA_GID="${CRTWATCH_DATA_GID:-1000}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run this script as root, for example: sudo bash scripts/quickstart.sh"
  exit 1
fi

need_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1"
    echo "Install it first, then rerun this script."
    exit 1
  fi
}

random_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 64
  fi
}

need_command git
need_command docker

if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required. Install the Docker Compose plugin and rerun this script."
  exit 1
fi

if [[ -d "${INSTALL_DIR}/.git" ]]; then
  echo "Updating existing checkout in ${INSTALL_DIR}"
  git -C "${INSTALL_DIR}" pull --ff-only
else
  echo "Cloning crt.watch into ${INSTALL_DIR}"
  mkdir -p "$(dirname "${INSTALL_DIR}")"
  git clone "${REPO_URL}" "${INSTALL_DIR}"
fi

cd "${INSTALL_DIR}"
mkdir -p data
# Also hands over data that an older, root-run container created.
chown -R "${DATA_UID}:${DATA_GID}" data

if [[ ! -f .env ]]; then
  SESSION_SECRET="${CRTWATCH_SESSION_SECRET:-$(random_secret)}"
  cat > .env <<ENV
NODE_ENV=production
TZ=${CRTWATCH_TZ:-Europe/Berlin}
PORT=${CONTAINER_PORT}
HOST_PORT=${APP_PORT}
BASE_URL=http://localhost:${APP_PORT}
DATA_DIR=./data
DATABASE_PATH=/data/crtwatch.sqlite
SESSION_SECRET=${SESSION_SECRET}
TRUST_PROXY=true
COOKIE_SECURE=false
FRONT_PAGE_ENABLED=true
PUBLIC_REGISTRATION_ENABLED=true
ALLOW_PRIVATE_TARGETS=false
ALLOW_PRIVATE_NOTIFICATION_TARGETS=false
CHECK_CONCURRENCY=4
DEFAULT_INTERVAL_SECONDS=3600
DEFAULT_WARNING_DAYS=30
DEFAULT_CRITICAL_DAYS=7
ENV
  chmod 600 .env
  echo "Created ${INSTALL_DIR}/.env"
  echo "Create the first admin account in the web setup screen."
else
  echo "Using existing ${INSTALL_DIR}/.env"
fi

docker compose pull crt-watch
docker compose up -d

echo
echo "crt.watch is starting."
echo "Open: http://localhost:${APP_PORT}"
echo "First run: create the admin account in the browser."
echo "Data bind mount: ${INSTALL_DIR}/data -> /data"
echo
echo "Useful commands:"
echo "  cd ${INSTALL_DIR}"
echo "  docker compose logs -f"
echo "  docker compose pull && docker compose up -d"
