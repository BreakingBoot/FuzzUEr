#!/bin/bash

# cargo run --release --features=6.0.169 -- \
#   -c /tmp/corpus/ -o /tmp/solution/ -l ERROR -t -C 1 \
#   -P 2096:6.0.70 \
#   -f Harness/BBClient.efi:%simics%/targets/Harness/BBClient.efi \
#   -f Harness/app.py:%simics%/scripts/app.py \
#   -f Harness/app.yml:%simics%/scripts/app.yml \
#   -f Harness/run_uefi_app.nsh:%simics%/targets/Harness/run_uefi_app.nsh \
#   -f Harness/run-uefi-app.simics:%simics%/targets/Harness/run-uefi-app.simics \
#   -x CONFIG:%simics%/scripts/app.yml


  cargo run --release --features=6.0.169 -- \
    --corpus /tmp/corpus --solutions solution --log-level INFO --cores 1  \
    --file Harness/BBClient.efi:%simics%/BBClient.efi \
    --file Harness/fuzz.simics:%simics%/fuzz.simics \
    --file Harness/BOARDX58ICH10.fd:%simics%/BOARDX58ICH10.fd \
    --file "Harness/minimal_boot_disk.craff:%simics%/minimal_boot_disk.craff" \
    --package 2096:6.0.70 \
    --command 'COMMAND:run-script "%simics%/fuzz.simics"'