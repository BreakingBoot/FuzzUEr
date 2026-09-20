#!/usr/bin/env bash
#
# Register this machine as the self-hosted runner .github/workflows/fuzz-edk2.yml needs.
#
#   scripts/setup_gh_runner.sh <registration-token> [repo-url]
#
# The workflow asks for a runner labelled [self-hosted, linux, x64]. Without one the
# weekly sweep has nothing to execute on and simply never starts -- which is how a
# scheduled job that could never have run stayed unnoticed: with no runner, there is no
# failed run to look at either.
#
# The token is a REGISTRATION token, not a personal access token, and it expires about an
# hour after it is issued:
#
#   Settings -> Actions -> Runners -> New self-hosted runner, copy the --token value
#   or:  gh api -X POST repos/<owner>/<repo>/actions/runners/registration-token --jq .token
#
# Idempotent in the ways that matter: an already-configured runner is left alone, and the
# download is skipped when the version asked for is already unpacked.
set -euo pipefail

TOKEN="${1:-${RUNNER_TOKEN:-}}"
REPO_URL="${2:-https://github.com/BreakingBoot/FuzzUEr}"
RUNNER_VERSION="${RUNNER_VERSION:-2.319.1}"
RUNNER_DIR="${RUNNER_DIR:-$HOME/actions-runner}"
LABELS="${RUNNER_LABELS:-self-hosted,linux,x64}"

if [ -z "$TOKEN" ]; then
    echo "usage: $0 <registration-token> [repo-url]" >&2
    echo "  get one from Settings -> Actions -> Runners -> New self-hosted runner," >&2
    echo "  or: gh api -X POST repos/<owner>/<repo>/actions/runners/registration-token --jq .token" >&2
    exit 2
fi

if [ -f "$RUNNER_DIR/.runner" ]; then
    echo "=== a runner is already configured in $RUNNER_DIR ==="
    echo "    remove it first with: (cd $RUNNER_DIR && ./config.sh remove --token <token>)"
    exit 0
fi

mkdir -p "$RUNNER_DIR"
cd "$RUNNER_DIR"

TARBALL="actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
if [ ! -x ./config.sh ]; then
    echo "=== downloading runner ${RUNNER_VERSION} ==="
    curl -fsSL -o "$TARBALL" \
        "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${TARBALL}"
    tar xzf "$TARBALL"
    rm -f "$TARBALL"
fi

echo "=== configuring against $REPO_URL with labels $LABELS ==="
# --unattended so it never stops for a prompt, --replace so re-registering the same name
# does not fail after a machine is rebuilt.
./config.sh --url "$REPO_URL" --token "$TOKEN" \
            --name "$(hostname)" --labels "$LABELS" \
            --work _work --unattended --replace

echo "=== installing the service ==="
# As a service, not ./run.sh: a runner in a terminal dies with the terminal, and a weekly
# job that fires at 03:00 needs the machine to answer without anyone logged in.
sudo ./svc.sh install "$(whoami)"
sudo ./svc.sh start
sudo ./svc.sh status || true

cat <<'DONE'

=== next ===
  1. scripts/bootstrap_runner.sh          builds the images the sweep needs (slow, once)
  2. Run the workflow manually with qualify_only = true first. Ten stages, minutes, and
     it exercises everything except the fuzzing -- far better than discovering a problem
     seventeen hours into a full sweep.
  3. The schedule (Sundays 03:00 UTC) then needs nothing further.
DONE
