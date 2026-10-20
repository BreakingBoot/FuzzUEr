# Benchmark scoreboard

One boot per class, so the two destructive cases do not take the rest of the run with them.
Regenerate with

```
python3 scripts/fuzz_edk2.py --ref <ref> --bench --skip-fuzz --out results/bench
```

which builds the SanBench drivers into the firmware and scores them in the `detects` stage.

Measured on `edk2-stable202511`, 2026-10-20:

| class | verdict | evidence |
|---|---|---|
| `control` | PASS | silent, as it should be |
| `heap-buffer-overflow` | PASS | bug_descr=heap-buffer-overflow in file: /workspace/tmp/edk2-edk2-stable202511/MdePkg/Lib |
| `heap-buffer-underflow` | PASS | ASAN MEMORY ACCESS check fail! __asan_load0x04 is called |
| `tlv-overread` | PASS | ASAN MEMORY ACCESS check fail! __asan_load0x02 is called |
| `foreign-pointer` | PASS | FWSAN: foreign-region access -- a region this driver does not own |
| `double-fetch` | PASS | FWSAN: double-fetch -- untrusted word read twice in one call |
| `stale-interface` | PASS | FWSAN: interface uninstalled, storage poisoned |
| `boot-service-after-exit` | N/A | needs the runtime phase |
| `variable-size-trusted` | PASS | FWSAN: variable-size-trusted -- GetVariable reissued into a destination already known to |
| `use-after-free` | PASS | ASAN MEMORY ACCESS check fail! __asan_load0x04 is called |
| `double-free` | PASS | bug_descr=double-free in file: /workspace/tmp/edk2-edk2-stable202511/MdeModulePkg/Core/D |
| `size-overflow` | PASS | ASAN MEMORY ACCESS check fail! __asan_store0x02 is called |

**11 of 11 scorable classes detected**

not scorable here: boot-service-after-exit

`control` is a real row: it exercises correct code and passes by staying silent. A runtime
that reports on it is reporting on anything, and the ten detections beside it would look
exactly the same -- which is why it is scored rather than assumed.
