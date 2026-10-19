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

# Default to the repository this checkout belongs to, not a fixed one. A registration token
# is scoped to a single repository, so pointing a fork's runner at someone else's URL fails
# inside config.sh with "Invalid configuration provided for url" -- which reads as a bad
# token rather than a wrong target. SSH remotes are rewritten to https because config.sh
# wants a web URL.
default_repo_url() {
    local origin
    origin=$(git -C "$(dirname "$0")/.." remote get-url origin 2>/dev/null) || origin=''
    # git@host:owner/repo -> https://host/owner/repo. Strip the user, turn the single
    # host/path colon into a slash, and only then add the scheme: prefixing first makes
    # "https:" the first colon in the string and the replacement mangles that instead.
    case "$origin" in
        git@*:*)
            origin="${origin#git@}"
            origin="https://${origin/://}"
            ;;
    esac
    origin="${origin%.git}"
    if [ -n "$origin" ]; then
        printf '%s' "$origin"
    else
        # No origin: a tarball or a detached copy. There is nothing to infer, so say what to
        # pass rather than guessing a repository.
        printf ''
    fi
}
REPO_URL="${2:-$(default_repo_url)}"
RUNNER_VERSION="${RUNNER_VERSION:-2.319.1}"
RUNNER_DIR="${RUNNER_DIR:-$HOME/actions-runner}"
LABELS="${RUNNER_LABELS:-self-hosted,linux,x64}"

if [ -z "$REPO_URL" ]; then
    echo "this checkout has no git remote, so the repository to register against cannot" >&2
    echo "be inferred. Pass it: $0 <registration-token> https://github.com/<owner>/<repo>" >&2
    exit 1
fi

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
#
# sudo -n first, and say what to do rather than blocking. Called from a script or a CI step
# there is no tty, and plain sudo then stops with "a terminal is required to read the
# password" AFTER the runner has already registered -- leaving a configured runner with no
# service, which looks like the whole thing failed.
if sudo -n true 2>/dev/null; then
    sudo ./svc.sh install "$(whoami)"
    sudo ./svc.sh start
    sudo ./svc.sh status || true
else
    echo "    The runner is registered, but installing the service needs sudo and this"
    echo "    shell cannot prompt for it. Finish with:"
    echo
    echo "      cd $RUNNER_DIR && sudo ./svc.sh install \$(whoami) && sudo ./svc.sh start"
    echo
    echo "    Until then the runner is configured but offline, so a job queued for it waits."
    exit 3
fi

cat <<'DONE'

=== next ===
  1. scripts/bootstrap_runner.sh          builds the images the sweep needs (slow, once)
  2. Run the workflow manually with qualify_only = true first. Ten stages, minutes, and
     it exercises everything except the fuzzing -- far better than discovering a problem
     seventeen hours into a full sweep.
  3. The schedule (Sundays 03:00 UTC) then needs nothing further.
DONE
