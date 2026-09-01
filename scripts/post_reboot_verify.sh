#!/bin/bash
# Runs the whole container verification after a reboot, once docker is actually able to
# start a container. Installs the packages the native and container builds need first.
# Log: /home/gl055/research/tianoshield/FuzzUEr/post_reboot.log
exec >> /home/gl055/research/tianoshield/FuzzUEr/post_reboot.log 2>&1
echo "=== $(date) post-reboot verification starting ==="
cd /home/gl055/research/tianoshield/FuzzUEr || exit 1

for i in $(seq 1 60); do
  if timeout -k 5 60 docker run --rm hello-world >/dev/null 2>&1; then
    echo "docker healthy after ${i} attempt(s)"; break
  fi
  sleep 20
done

# no host packages are installed here: the container image already carries nasm, iasl and
# the clang toolchain, and the native build was only ever a workaround for docker being down
echo "--- running verify_all ---"
./scripts/verify_all.sh /home/gl055/research/tianoshield/FuzzUEr/eval_source/verify
echo "=== $(date) done ==="
