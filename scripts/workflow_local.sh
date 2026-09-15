#!/usr/bin/env bash
# Run the GitHub workflow's steps against a local edk2 checkout.
#
# The action cannot be proven by reading it: every step is a build or a boot, and the ways
# they fail -- a submodule missing, a sanitizer that initialises and never reports, a
# protocol nobody calls generating an empty harness -- all look like success from outside.
# This runs the same sequence locally so a tree can be qualified before a runner tries it.
#
#   scripts/workflow_local.sh <host tree> <tree inside fwbuild-stack> <label> [budget]
#
# Two paths because the build runs in a container that mounts its own copy: discovery reads
# the host tree, the build reads the container's.
set -uo pipefail

TREE=${1:?usage: workflow_local.sh <host tree> <container tree> <label> [budget]}
TREE_IN=${2:?}
LABEL=${3:?}
BUDGET=${4:-300}

REPO=$(cd "$(dirname "$0")/.." && pwd)
OUT="$REPO/results/workflow-$LABEL"
mkdir -p "$OUT"
STEP=0
pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; FAILED=1; }
FAILED=0

echo "=== workflow: $LABEL ($TREE) ==="

# 1. the tree must have its submodules, because the build fails three different ways
#    without them and none of the messages name the submodule
STEP=$((STEP+1)); echo "[$STEP] submodules"
missing=0
while read -r sub; do
  [ -n "$sub" ] || continue
  [ -n "$(ls -A "$TREE/$sub" 2>/dev/null)" ] || { echo "      empty: $sub"; missing=1; }
done < <(sed -n 's/^[[:space:]]*path[[:space:]]*=[[:space:]]*//p' "$TREE/.gitmodules" 2>/dev/null)
[ "$missing" -eq 0 ] && pass "vendored dependencies present" || fail "submodules missing"

# 2. apply ASan and build. ASAN_SCOPE=full is what instruments every DXE module.
STEP=$((STEP+1)); echo "[$STEP] build with AddressSanitizer"
docker exec fwbuild-stack bash -lc "
  export WORKSPACE=$TREE_IN EDK_TOOLS_PATH=$TREE_IN/BaseTools CONF_PATH=$TREE_IN/Conf
  export CLANGSAN_BIN=/workspace/llvm-15.0.7/build/bin/ PYTHON_COMMAND=\$(command -v python3)
  cd \$WORKSPACE && source edksetup.sh >/dev/null 2>&1
  build -a X64 -b DEBUG -t CLANGSAN -p OvmfPkg/OvmfPkgX64.dsc \
    -D ASAN_SCOPE=full -D ASAN_FUZZER=qemu -D FIRNESS_QEMU_CRASH=TRUE \
    -D FD_SIZE_IN_KB=8192 -n 16" > "$OUT/build.log" 2>&1
if grep -q '^- Done -' "$OUT/build.log"; then pass "firmware built"; else fail "build"; fi

# 3. the instrumentation has to be real, not merely requested
STEP=$((STEP+1)); echo "[$STEP] instrumentation"
INST=$(docker exec fwbuild-stack bash -lc "
  n=0; t=0
  for f in \$(find $TREE_IN/Build/OvmfX64 -name '*.debug' 2>/dev/null); do
    t=\$((t+1)); nm \$f 2>/dev/null | grep -qE '__asan_(load|store|gen_)' && n=\$((n+1))
  done; echo \"\$n/\$t\"")
echo "      $INST modules carry ASan checks"
case "$INST" in 0/*|/) fail "nothing instrumented";; *) pass "instrumented";; esac

# 4. discovery: protocols from headers, SMI handlers from registration call sites
STEP=$((STEP+1)); echo "[$STEP] discovery"
python3 "$REPO/scripts/gen_protocol_inputs.py" -s "$TREE" -o "$OUT/evalset" -m 1 \
  > "$OUT/discover.log" 2>&1
python3 "$REPO/scripts/discover_smi.py" -s "$TREE" -o "$OUT/evalset/DiscoveredSmi.txt" \
  --with-source >> "$OUT/discover.log" 2>&1
NP=$(ls "$OUT/evalset"/*.txt 2>/dev/null | wc -l)
NS=$(grep -cv '^$' "$OUT/evalset/DiscoveredSmi.txt" 2>/dev/null || echo 0)
echo "      $NP protocol request files, $NS SMI handlers"
[ "$NP" -gt 0 ] && pass "protocols discovered" || fail "no protocols"
[ "$NS" -gt 0 ] && pass "SMI handlers discovered" || fail "no SMI handlers"

echo "$LABEL,$NP,$NS,$INST" >> "$REPO/results/workflow-summary.csv"
echo "=== $LABEL: $([ $FAILED -eq 0 ] && echo OK || echo FAILED) ==="
exit $FAILED
