# Changelog

## [0.1.2] - Unreleased

Correctness fixes found by differential testing against cbor2, plus a
performance pass on the encoder and decoder hot paths.

Performance: encoding is roughly 1.4x to 3.2x faster and decoding 1.1x
to 2.2x faster than 0.1.1 depending on payload shape. The decoder now
works directly on bytes instead of a memoryview, inlines the common
one-byte head forms and uses precompiled struct formats for multi-byte
arguments. The encoder dispatches on exact types before falling back to
isinstance checks and no longer wraps stream writes in an extra call
layer. Output bytes are unchanged.

Correctness fixes:

- `date` now encodes as tag 1004 wrapping an RFC 3339 text string per
  RFC 8943, matching cbor2. The integer day-count form emitted by
  0.1.1 still decodes, and tag 100 (epoch-based date) now decodes to
  `date` as well.
- The decoder rejects reserved simple values 24 through 31.
- NaN always encodes as the preferred form 0xf97e00. Infinity uses
  float16 and other floats use float64 in non-canonical mode, matching
  cbor2.

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
