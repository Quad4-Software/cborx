# Changelog

## [0.2.3] - 2026-09-22

Fix a crash in the compiled encoder's canonical map handling and
extend platform coverage.

- Canonical encoding sorted (length, key bytes, value) tuples, so two
  keys with identical encodings (distinct NaN objects) fell through to
  comparing map values and raised TypeError for unorderable types.
  The sort now uses (length, key bytes) only, matching the pure
  encoder. Found by hypothesis during wheel testing.
- Property tests now skip objects whose map keys collide under
  canonical encoding: strict canonical decode rejects duplicate keys
  in both backends, so such objects cannot round trip.
- CI runs the test suite on Windows, macOS (arm64) and Linux aarch64
  in addition to Linux x86_64.
- Release wheels now cover Linux aarch64 and Windows ARM64.

## [0.2.2] - 2026-09-22

Fix a stack overflow in the compiled encoder on Windows. When nesting
exceeded the internal C recursion cap, the remaining tail was
delegated to the Python encoder, which recursed on top of thousands
of retained C frames and exhausted the 1MB thread stack before
RecursionError could fire. The cap is lowered to 2000 and delegation
now fails fast: containers beyond the cap raise CBOREncodeError
immediately, while scalar leaves at any depth still encode normally.

## [0.2.1] - 2026-09-22

Release pipeline fixes. No library changes.

- Wheel testing no longer installs cbor2, which has no wheels for some
  build targets and fails to build from source without a Rust
  toolchain. Differential coverage still runs in CI on Linux.
- The encoder recursion guard test caps the interpreter recursion
  limit so RecursionError fires at a shallow depth. On Windows the
  default limit already exceeds what the 1MB C stack survives, so the
  test crashed the interpreter instead of raising.

## [0.2.0] - 2026-09-22

Optional Cython accelerator, correctness fixes found by differential
testing against cbor2, and a performance pass on the encoder and
decoder hot paths.

Performance: wheels now ship a compiled `_fast` extension used for all
supported operations. On local benchmarks against cbor2's native
extension, encoding is 1.2x to 11x faster and decoding is on par to
2x faster depending on payload shape, with byte-identical output. When
no compiler or wheel is
available the package falls back to the pure-Python codec with
identical behavior. Set CBORX_DISABLE_FAST=1 to force the fallback.
The pure path also gained the optimizations described below: the
decoder works directly on bytes instead of a memoryview, inlines the
common one-byte head forms and uses precompiled struct formats for
multi-byte arguments, and the encoder dispatches on exact types before
falling back to isinstance checks. Output bytes are unchanged.

Correctness fixes:

- `date` now encodes as tag 1004 wrapping an RFC 3339 text string per
  RFC 8943, matching cbor2. The integer day-count form emitted by
  0.1.1 still decodes, and tag 100 (epoch-based date) now decodes to
  `date` as well.
- The decoder rejects reserved simple values 24 through 31.
- NaN always encodes as the preferred form 0xf97e00. Infinity uses
  float16 and other floats use float64 in non-canonical mode, matching
  cbor2.
- The accelerator clamps declared array and map counts that exceed the
  remaining input, fixing an item-counter overflow that could crash on
  hostile length fields. Found by bit-flip fuzzing, covered by a
  regression test.

Added a cbor2 differential test suite: byte-identical canonical and
default encodings, cross-decoding in both directions, decode agreement
on random and mutated inputs, indefinite-length interoperability and
documented divergence coverage. cbor2 is a dev-only dependency.

## [0.1.1] - Unreleased

Fix the release workflow's package-name placeholder. No library
changes.

## [0.1.0] - Unreleased

Initial release.

- Full RFC 8949 codec: all major types, definite and indefinite
  lengths, half/single/double floats, bignum tags for integers beyond
  the 64-bit range.
- `dumps`, `loads`, `dump`, `load` plus `CBOREncoder` and
  `CBORDecoder` classes.
- Deterministic encoding via `canonical=True` (RFC 8949 section 4.2:
  shortest-form integers and floats, map keys ordered by encoded key
  bytes) and strict canonical validation on decode.
- Built-in semantic tags 0, 1, 2, 3, 32, 1004 and 55799. `tag_hook`
  for custom handling, `CBORTag` for unhandled tags.
- `CBORSimpleValue` for unassigned simple values and an `undefined`
  sentinel.
- `default` callback for encoding unknown types, mirroring cbor2.
- Hardened iterative decoder: declared lengths are checked against
  remaining input before use, nesting is bounded by a configurable
  `max_depth`, and truncated or malformed input always raises
  `CBORDecodeError`.
- Decode options: `strict_utf8`, `allow_indefinite`,
  `duplicate_keys` ("last", "first", "error") and `allow_trailing`.
- Typed throughout, zero runtime dependencies.
