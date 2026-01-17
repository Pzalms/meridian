# Contributing

## Code Style

- All source files use C11 (`-std=c11`).
- Indent with tabs; keep lines under 100 columns.
- Function names use `snake_case`; type names use `snake_case_t`.
- Every public function must have a brief block comment explaining its contract.
- Return `-1` on error, `0` on success. Never return arbitrary negative codes.

## Module Layout

Each module consists of a header (`src/<module>.h`) and an implementation (`src/<module>.c`).
Headers expose only the public interface. Internal helpers are declared `static`.

## Commit Messages

Use the imperative mood in commit messages: "add bounds check", not "added" or "adds".
Keep the subject line under 72 characters. Reference relevant section types where applicable.

## Testing

All changes must keep `./tests/test_main` at zero failures before submission.
Add new assertions for every new code path. Prefer table-driven tests that
exercise boundary values explicitly.

## Formatting Changes

Reformatting commits must not mix logic changes. Keep them separate.
