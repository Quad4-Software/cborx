# SPDX-License-Identifier: 0BSD
"""Exception hierarchy for cborx."""


class CBORError(Exception):
    """Base class for all cborx errors."""


class CBOREncodeError(CBORError):
    """Raised when an object cannot be encoded as CBOR."""


class CBORDecodeError(CBORError):
    """Raised when input bytes cannot be decoded as CBOR."""
