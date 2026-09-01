#!/bin/bash
# Everything that needs a container, in one pass. Run after "sudo systemctl restart docker".
#
#   scripts/verify_all.sh [output_root]
#
# Stages, in order, each skipped if its result is already present:
#   1. analysis for protocols that have a request but no cached call database
#   2. harness generation and a real edk2 CLANGSAN build of one harness
#   3. a short fuzzing campaign per protocol, several at a time
#   4. a coverage summary across every campaign
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-$ROOT/eval_source/verify}
IMAGE=fuzzuer-cur:latest
JOBS=${JOBS:-8}
BUDGET=${BUDGET:-600}

mkdir -p "$OUT"
echo "== output: $OUT"

echo "== 0. docker health"
# -k so a wedged docker run is killed rather than ignoring the term signal
if ! timeout -k 10 120 docker run --rm "$IMAGE" true 2>/dev/null; then
  echo "   docker still cannot start a container from $IMAGE -- stopping here."
  echo "   (container creation was wedged at the storage layer; a daemon restart clears it)"
  exit 1
fi
echo "   ok"

echo "== 1. analysis for protocols missing a call database"
need=()
for req in "$ROOT"/eval_source/evalset/*.txt; do
  name=$(basename "$req" .txt)
  [ -f "$ROOT/eval_source/anacache/$name/call-database.json" ] || need+=("$name")
done
echo "   ${#need[@]} protocol(s) to analyse"
if [ ${#need[@]} -gt 0 ]; then
  mkdir -p "$ROOT/eval_source/sweep"
  printf '%s.txt\n' "${need[@]}" > "$ROOT/eval_source/sweep/verify.lst"
  split -n "l/$JOBS" -d "$ROOT/eval_source/sweep/verify.lst" "$ROOT/eval_source/sweep/v_"
  for part in "$ROOT"/eval_source/sweep/v_*; do
    [ -s "$part" ] || continue
    docker run -d --rm -v "$ROOT/eval_source:/input" "$IMAGE" bash -c "
      while read q; do
        name=\${q%.txt}
        out=/input/anacache/\$name
        [ -f \$out/call-database.json ] && continue
        mkdir -p \$out
        rm -f /workspace/firness_output/*.json
        firness -p /workspace/tmp -o /workspace/firness_output -i /input/evalset/\$q dummyfile >/dev/null 2>&1
        cp /workspace/firness_output/*.json \$out/ 2>/dev/null
      done < /input/sweep/$(basename "$part")" >/dev/null
  done
  while [ "$(docker ps -q --filter ancestor=$IMAGE | wc -l)" -gt 0 ]; do sleep 60; done
fi

echo "== 2. generation and a real edk2 build"
# in the container: the generator imports fuzzywuzzy, which is installed in the image and
# not on the host, and clang there matches the toolchain the harness is really built with
mkdir -p "$OUT/generated"
docker run --rm \
  -v "$ROOT/firness/harness_generator:/workspace/harness_generator:ro" \
  -v "$ROOT/firness/HarnessHelpers:/workspace/HarnessHelpers:ro" \
  -v "$ROOT/scripts:/w/scripts:ro" \
  -v "$ROOT/eval_source/anacache:/w/cache:ro" \
  -v "$ROOT/eval_source/evalset:/w/inputs:ro" \
  -v "$ROOT/eval_source/edk2:/w/edk2:ro" \
  -v "$ROOT/eval_source/edk2-platforms:/w/platforms:ro" \
  -v "$OUT/generated:/w/out" \
  "$IMAGE" python3 /w/scripts/check_generation.py -c /w/cache -i /w/inputs \
    --edk2 /w/edk2 --platforms /w/platforms -o /w/out | tail -8

first=$(ls "$OUT/generated" 2>/dev/null | head -1)
if [ -n "$first" ] && [ -d "$OUT/generated/$first/Firness" ]; then
  echo "   building $first with the production CLANGSAN toolchain"
  docker run --rm -v "$OUT/generated/$first/Firness:/hin:ro" "$IMAGE" bash -c '
    rm -rf /workspace/tmp/edk2/Firness && mkdir -p /workspace/tmp/edk2/Firness
    cp /hin/* /workspace/tmp/edk2/Firness/ 2>/dev/null
    cd /workspace/tmp/edk2
    export WORKSPACE=/workspace/tmp/edk2 EDK_TOOLS_PATH=/workspace/tmp/edk2/BaseTools \
           CONF_PATH=/workspace/tmp/edk2/Conf CLANGSAN_BIN=/usr/bin/
    source edksetup.sh >/dev/null 2>&1
    build -a X64 -b DEBUG -p Firness/Firness.dsc -t CLANGSAN >/tmp/b.log 2>&1
    echo "   build rc=$?"
    grep -E "^- (Done|Failed) -" /tmp/b.log | tail -1
    ls -la /workspace/tmp/edk2/Build/Firness/DEBUG_CLANGSAN/X64/Firness.efi 2>/dev/null || echo "   no efi produced"'
fi

echo "== 3. fuzzing campaigns ($JOBS at a time, ${BUDGET}s each)"
python3 "$ROOT/scripts/fuzz_batch.py" -o "$OUT/campaigns" -j "$JOBS" -t "$BUDGET" \
  --image "$IMAGE" --cpus 4

echo "== 4. coverage summary"
python3 "$ROOT/scripts/coverage_matrix.py" -r "$OUT/campaigns" -o "$OUT/coverage_matrix.csv"

echo "== done. results under $OUT"
