#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/release-docker.sh <version> [repository]

Example:
  scripts/release-docker.sh 0.1.1 cikichen/resource-sentinel

Notes:
  1) Push version tag first
  2) Update latest at the end (delete then recreate), so latest appears newest in Docker Hub tag list
EOF
}

if [[ $# -ge 1 ]]; then
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
  esac
fi

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
  exit 1
fi

VERSION="$1"
REPO="${2:-cikichen/resource-sentinel}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi
if ! command -v docker-credential-desktop >/dev/null 2>&1; then
  echo "docker-credential-desktop is required for Docker Hub API auth" >&2
  exit 1
fi

echo "==> Building and pushing ${REPO}:${VERSION} (${PLATFORMS})"
docker buildx build \
  --platform "${PLATFORMS}" \
  -t "${REPO}:${VERSION}" \
  --push \
  .

echo "==> Refreshing ${REPO}:latest at the very end"
CREDS="$(echo "https://index.docker.io/v1/" | docker-credential-desktop get)"
USER_NAME="$(echo "${CREDS}" | jq -r '.Username')"
USER_PASS="$(echo "${CREDS}" | jq -r '.Secret')"
JWT_TOKEN="$(curl -fsSL \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${USER_NAME}\",\"password\":\"${USER_PASS}\"}" \
  https://hub.docker.com/v2/users/login/ | jq -r '.token')"

DELETE_CODE="$(curl -sS -o /dev/null -w "%{http_code}" \
  -X DELETE \
  -H "Authorization: JWT ${JWT_TOKEN}" \
  "https://hub.docker.com/v2/repositories/${REPO}/tags/latest/")"
echo "delete latest HTTP status: ${DELETE_CODE}"

docker buildx imagetools create \
  -t "${REPO}:latest" \
  "${REPO}:${VERSION}"

echo "==> Current tags"
curl -fsSL "https://hub.docker.com/v2/repositories/${REPO}/tags?page_size=20" \
  | jq -r '.results[] | "\(.name)\t\(.last_updated)"'
