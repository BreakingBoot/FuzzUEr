#!/bin/bash
# Re-run the static analysis for every protocol with the current analyzer.
#
# The caches under anacache/ are only as good as the binary that produced them: a cache
# written before a pass existed simply lacks its fields, and nothing downstream complains.
# Results go to a staging directory so the working caches survive a bad run; promote them
# with a move once the output looks right.
#
#   scripts/reanalyze.sh [jobs] [image] [output]
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
JOBS=${1:-16}
IMAGE=${2:-fuzzuer-analyzer:latest}
OUT=${3:-$ROOT/eval_source/anacache_new}
rm -rf "$OUT"; mkdir -p "$OUT"

mapfile -t ALL < <(ls "$ROOT/eval_source/evalset"/*.txt | xargs -n1 basename | sed 's/\.txt$//')
echo "== re-analysing ${#ALL[@]} protocol(s), $JOBS at a time"

for ((i = 0; i < JOBS; i++)); do
  slice=""
  for ((j = i; j < ${#ALL[@]}; j += JOBS)); do slice="$slice ${ALL[$j]}"; done
  [ -n "$slice" ] || continue
  docker run -d --rm --name "reana-$i" --cpus 2 \
    -v "$ROOT/eval_source:/input:ro" -v "$OUT:/out" "$IMAGE" bash -c "
    for p in $slice; do
      cd /workspace && rm -rf firness_output && mkdir -p firness_output
      timeout 3000 firness -p /workspace/tmp -o /workspace/firness_output \
        -i /input/evalset/\$p.txt dummyfile > /tmp/\$p.log 2>&1
      rc=\$?
      mkdir -p /out/\$p
      cp /workspace/firness_output/*.json /out/\$p/ 2>/dev/null
      n=\$(python3 -c \"
import json;print(len(json.load(open('/out/\$p/call-database.json')) or []))\" 2>/dev/null || echo 0)
      ctx=\$(python3 -c \"
import json;d=json.load(open('/out/\$p/call-database.json')) or [];print(sum(1 for r in d if isinstance(r,dict) and r.get('EnclosingFunction')))\" 2>/dev/null || echo 0)
      echo \"\$p rc=\$rc records=\$n context=\$ctx\" >> /out/results.txt
    done" >/dev/null
done

while [ "$(docker ps -q --filter 'name=reana-' | wc -l)" -gt 0 ]; do sleep 60; done
echo "== results"
awk '{print ($2=="rc=0" ? "ok" : $2)}' "$OUT/results.txt" | sort | uniq -c
echo "  protocols with call-site context: $(awk -F'context=' '$2>0' "$OUT/results.txt" | wc -l)"
grep -v 'rc=0' "$OUT/results.txt" 2>/dev/null | head -5
