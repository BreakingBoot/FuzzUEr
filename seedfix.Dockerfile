# A campaign image whose fuzzer imports every seed.
#
# The stock binary calls load_initial_inputs, which keeps only the seeds the coverage
# feedback finds novel. On a protocol whose members share most of their edges that is the
# first one: every campaign log under results/ says "Imported 1 input(s) from disk" from a
# corpus of twenty, so nineteen members began with no entry and were reachable only if
# havoc rewrote the selector byte. This one calls load_initial_inputs_forced.
#
# Layered rather than rebuilt into the base because the fuzzer needs a QEMU build
# environment the campaign image does not want, and rebuilding the bridge is the better
# part of an hour; fuzzer.Dockerfile owns that and this just carries the result.
FROM fuzzuer-master:latest
COPY ./seedstage/firness_qemu /workspace/qemu_fuzzer/target/release/firness_qemu
RUN chmod +x /workspace/qemu_fuzzer/target/release/firness_qemu
