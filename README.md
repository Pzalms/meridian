# Meridian

Meridian is a binary network policy compiler written in C11. It parses a compact binary format that encodes zone definitions, prefix tables, NAT allocation pools, session tracking rules, packet templates, audit windows, and export profiles into a unified policy context. The compiled context can then be executed to enforce network access decisions across multi-zone topologies.

## Overview

Network operators define policy as a sequence of typed sections in a binary `.mdn` file. Meridian loads that file, validates the section layout against an optional capability token, links rule nodes into an ordered decision list, and runs the policy engine to produce permit/deny/redirect outcomes. The library exposes a minimal public API so it can be embedded in routers, firewalls, and test harnesses without external dependencies beyond libc.

Key design choices:

- **Single-pass parsing.** The loader walks the section table once, allocating nothing from the heap except for variable-length subdirectories. All fixed-size structures live inside `mdn_ctx_t`.
- **Zone-scoped rules.** Every rule belongs to exactly one zone. Zone identifiers are 32-bit integers assigned by the policy author; the engine enforces no ordering constraint between zones, letting operators compose partial policies independently.
- **Prefix pages with kind tagging.** Each prefix page carries a `kind` field (`PREFIX_KIND_V4`, `PREFIX_KIND_V6`, or `PREFIX_KIND_MIXED`) so the lookup path can skip address-family conversion for homogeneous pages.
- **NAT bucket pools.** Source-address translation is modelled as a set of buckets; each bucket owns a pool address and a port range. Session cursors iterate over active sessions within a bucket for age-out and statistics.
- **Audit ring buffer.** Policy decisions are written into a fixed-capacity ring buffer. When capacity is exhausted the oldest entry is overwritten, keeping memory bounded.
- **Export profiles.** A profile describes how to serialise selected packet fields for telemetry. Each field entry specifies offset, length, and an encoding hint (raw bytes, variable-length integer, or null-terminated string).

## Binary Format

An `.mdn` file begins with a four-byte magic sequence followed by a one-byte version. The remaining bytes are a sequence of sections, each with a one-byte type identifier, a four-byte length, and a type-specific payload.

| Offset | Size | Field         |
|--------|------|---------------|
| 0      | 3    | Magic `MDN`   |
| 3      | 1    | Version       |
| 4      | …    | Sections      |

Each section starts with:

| Offset | Size | Field   |
|--------|------|---------|
| 0      | 1    | Type    |
| 1      | 4    | Length  |
| 5      | N    | Payload |

Defined section types:

| Type | ID   | Description                    |
|------|------|--------------------------------|
| CAP          | 0x01 | Capability token        |
| ZONE         | 0x02 | Zone definition         |
| RULE         | 0x03 | Policy rule node        |
| PREFIX       | 0x04 | Address prefix page     |
| NAT          | 0x05 | NAT bucket              |
| SESSION      | 0x06 | Session record          |
| TEMPLATE     | 0x07 | Packet template         |
| AUDIT        | 0x08 | Audit window config     |
| EXPORT       | 0x09 | Export profile          |
| POLICY_PATCH | 0x0A | Incremental rule update |

## CLI Usage

The `mdntool` command-line utility loads an `.mdn` file and runs the policy engine:

```
mdntool <policy.mdn>
```

Options:

| Flag        | Effect                                          |
|-------------|-------------------------------------------------|
| `--strict`  | Enable `MDN_FLAG_STRICT`; reject unknown types  |
| `--dump`    | Print parsed section table to stdout            |
| `--zones`   | List zone names and rule counts                 |
| `--query`   | Run a single query and print the action         |

Exit codes: `0` = policy accepted, `1` = policy rejected, `2` = parse error.

## Building

Requirements: a C11-capable compiler (GCC ≥ 7 or Clang ≥ 5) and GNU Make.

```sh
make            # builds mdntool and tests/test_main
make test       # runs the unit test suite
make clean      # removes build artefacts
make install    # installs mdntool to /usr/local/bin
```

Set `CC` and `CFLAGS` to override the compiler and flags:

```sh
CC=clang CFLAGS="-O0 -g3" make
```

For a debug build with address sanitisation:

```sh
CC=clang CFLAGS="-O1 -g -fsanitize=address,undefined" make
./tests/test_main
```

## Testing

The `tests/test_main` binary runs all unit tests and reports a pass/fail count. A zero exit code means all tests passed.

```sh
make test
```

Tests cover: header validation, section parsing, zone resolution, prefix lookup, NAT bucket assignment, session cursor iteration, audit ring-buffer wrap, and export field encoding.

## License

MIT — see `LICENSE`.
