#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

die() {
  printf 'Codex setup error: %s\n' "$*" >&2
  exit 1
}

command -v python3 >/dev/null 2>&1 || die "python3 is required"
command -v node >/dev/null 2>&1 || die "Node.js is required"
command -v npm >/dev/null 2>&1 || die "npm is required"

python3 - <<'PY'
import sys

if sys.version_info[:2] != (3, 12):
    raise SystemExit(
        f"Traceless requires Python 3.12; found "
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )
PY

node_major="$(node -p 'process.versions.node.split(".")[0]')"
[[ "$node_major" == "22" ]] || die "Traceless requires Node.js 22; found $(node --version)"

python3 -m pip install \
  --disable-pip-version-check \
  --user \
  "uv==0.11.28"

user_bin="$(python3 - <<'PY'
import site
print(site.USER_BASE + "/bin")
PY
)"
path_line="export PATH=\"${user_bin}:\$PATH\""

case ":${PATH}:" in
  *":${user_bin}:"*) ;;
  *)
    export PATH="${user_bin}:${PATH}"
    touch "$HOME/.bashrc"
    if ! grep -Fqx "$path_line" "$HOME/.bashrc"; then
      printf '\n%s\n' "$path_line" >> "$HOME/.bashrc"
    fi
    ;;
esac

command -v uv >/dev/null 2>&1 || die "uv was installed but is not available on PATH"
uv_version="$(uv --version | awk '{print $2}')"
[[ "$uv_version" == "0.11.28" ]] || die "uv 0.11.28 is required; found $(uv --version)"

export UV_LINK_MODE="${UV_LINK_MODE:-copy}"
export PIP_DISABLE_PIP_VERSION_CHECK=1

printf 'Installing locked API dependencies...\n'
(
  cd apps/api
  uv sync --locked --extra dev
)

printf 'Installing locked customer-web dependencies...\n'
(
  cd apps/web
  npm ci --no-audit --no-fund
)

printf 'Installing locked publisher-web dependencies...\n'
(
  cd apps/publisher-web
  npm ci --no-audit --no-fund
)

printf 'Codex cloud environment is ready.\n'
printf 'Python: %s\n' "$(python3 --version)"
printf 'Node: %s\n' "$(node --version)"
printf 'uv: %s\n' "$(uv --version)"
