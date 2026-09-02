#!/bin/bash
# Build every protocol's harness with the real edk2 toolchain and report what links.
#
# scripts/check_generation.py compiles the harness sources with clang and a set of -I
# flags, which catches syntax and type errors but not a missing declaration behind a
# warning, and never links. A harness can pass that check and still fail the build it
# actually has to survive -- EfiAtaPassThru did. This runs `build -p Firness/Firness.dsc`,
# the same command the campaigns run, so OK here means the harness really compiles.
#
#   scripts/build_sweep.sh [jobs] [image]
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
JOBS=${1:-4}
IMAGE=${2:-fuzzuer-run:latest}
OUT=$ROOT/eval_source/verify/buildsweep
rm -rf "$OUT"; mkdir -p "$OUT"

mapfile -t ALL < <(ls "$ROOT/eval_source/evalset"/*.txt | xargs -n1 basename | sed 's/\.txt$//')
echo "== building ${#ALL[@]} protocol(s), $JOBS at a time, image $IMAGE"

for ((i = 0; i < JOBS; i++)); do
  slice=""
  for ((j = i; j < ${#ALL[@]}; j += JOBS)); do slice="$slice ${ALL[$j]}"; done
  [ -n "$slice" ] || continue
  docker run -d --rm --name "bsweep-$i" \
    -v "$ROOT/eval_source:/input:ro" -v "$OUT:/out" "$IMAGE" bash -c "
    cd /workspace/tmp/edk2
    export WORKSPACE=/workspace/tmp/edk2 EDK_TOOLS_PATH=/workspace/tmp/edk2/BaseTools \
           CONF_PATH=/workspace/tmp/edk2/Conf CLANGSAN_BIN=/usr/bin/
    source edksetup.sh >/dev/null 2>&1
    for p in $slice; do
      cd /workspace && rm -rf firness_output && mkdir -p firness_output
      cp /input/anacache/\$p/*.json firness_output/ 2>/dev/null || { echo \"\$p NO_CACHE\" >> /out/results.txt; continue; }
      python3 /workspace/harness_generator/main.py -d firness_output/call-database.json \
        -g firness_output/generator-database.json -gd firness_output/generators.json \
        -t firness_output/types.json -a firness_output/aliases.json -m firness_output/macros.json \
        -e firness_output/enums.json -i /input/evalset/\$p.txt -s firness_output/cast-map.json \
        -in firness_output/includes.json -f firness_output/functions.json \
        --edk2 /workspace/tmp/edk2 -o firness_output > /out/\$p.gen.log 2>&1
      rm -rf /workspace/tmp/edk2/Build/Firness /workspace/tmp/edk2/Firness
      if ! cp -r firness_output/Firness /workspace/tmp/edk2/ 2>/dev/null; then
        echo \"\$p GEN_FAIL\" >> /out/results.txt; continue
      fi
      cd /workspace/tmp/edk2
      build -a X64 -b DEBUG -p Firness/Firness.dsc -t CLANGSAN > /out/\$p.build.log 2>&1
      rc=\$?
      sz=\$(stat -c%s Build/Firness/DEBUG_CLANGSAN/X64/Firness.efi 2>/dev/null || echo 0)
      if [ \$rc -eq 0 ] && [ \$sz -gt 0 ]; then
        echo \"\$p OK \$sz\" >> /out/results.txt
        rm -f /out/\$p.gen.log /out/\$p.build.log
      else
        echo \"\$p BUILD_FAIL\" >> /out/results.txt
      fi
    done" >/dev/null
done

while [ "$(docker ps -q --filter 'name=bsweep-' | wc -l)" -gt 0 ]; do sleep 60; done
echo "== results"
awk '{print $2}' "$OUT/results.txt" | sort | uniq -c | sort -rn
grep -v ' OK ' "$OUT/results.txt" 2>/dev/null | head -20
