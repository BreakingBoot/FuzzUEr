# A campaign image for measuring coverage, not for finding bugs. DrCovModule records every
# translated block, which is what a per-driver percentage needs and what a bug-finding run
# should not pay for; a module in LibAFL's tuple always runs its hooks, so "off" means a
# different binary rather than a filter.
FROM fuzzuer-iconly:latest
COPY ./covstage/firness_qemu /workspace/qemu_fuzzer/target/release/firness_qemu
RUN chmod +x /workspace/qemu_fuzzer/target/release/firness_qemu
