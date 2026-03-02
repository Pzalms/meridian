# Seed Corpus — meridian_fuzzer

This directory contains binary seed inputs for the `meridian_fuzzer` target.
Each file represents a valid or edge-case `.mdn` document that exercises a
distinct code path through the parser and policy engine.

## Naming Convention

Files are named by their primary characteristic:

- `empty_*`     — minimum-length headers with no sections
- `one_zone_*`  — single SECT_ZONE payload
- `nat_*`       — NAT bucket with varying slot counts
- `crc_bad_*`   — intentionally mismatched CRC in non-strict mode
- `multi_*`     — multiple section types in a single document

## Adding New Seeds

Generate a valid seed from test output:

```sh
./tests/test_main --dump-seeds fuzz/corpus/meridian_fuzzer/
```

Or write a minimal conforming buffer by hand and drop it here. The fuzzer
picks up all files in this directory automatically at startup.
