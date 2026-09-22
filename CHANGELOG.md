# Changelog

## [Unreleased]

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
