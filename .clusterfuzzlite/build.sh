#!/bin/bash
set -euo pipefail

# Build all source objects
for src in src/*.c; do
    obj="${src%.c}.o"
    $CC $CFLAGS -Iinclude -Isrc -c "$src" -o "$obj"
done

# Build the fuzzer
$CXX $CFLAGS $LIB_FUZZING_ENGINE \
    -Iinclude -Isrc \
    fuzz/meridian_fuzzer.cc \
    src/*.o \
    -lm \
    -o "$OUT/meridian_fuzzer"

# Copy corpus
cp -r fuzz/corpus/meridian_fuzzer "$OUT/meridian_fuzzer_seed_corpus" 2>/dev/null || true

# Copy dictionary
cp fuzz/dictionary.txt "$OUT/meridian_fuzzer.dict" 2>/dev/null || true
