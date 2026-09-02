#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# A cached Codex container may resume on a commit with changed lock files.
# Re-run the deterministic setup so all three workspaces match the checked-out commit.
bash .codex/setup.sh
