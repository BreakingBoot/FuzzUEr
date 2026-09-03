# The run image with the rebuilt analyzer, which records where each call sits so dataflow
# between calls can be derived soundly.
FROM fuzzuer-run:latest
COPY ./fwstage/firness /workspace/llvm-15.0.7/build/bin/firness
