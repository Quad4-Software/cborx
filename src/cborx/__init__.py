# SPDX-License-Identifier: 0BSD
"""Pure-Python CBOR (RFC 8949) encoder/decoder. No dependencies, no Rust."""

from .decoder import CBORDecoder, DuplicateMode, TagHook, load, loads
from .encoder import CBOREncoder, DefaultCallback, dump, dumps
from .exceptions import CBORDecodeError, CBOREncodeError, CBORError
from .types import CBORSimpleValue, CBORTag, UndefinedType, undefined

__version__ = "0.2.4"

__all__ = [
    "CBORDecodeError",
    "CBORDecoder",
    "CBOREncodeError",
    "CBOREncoder",
    "CBORError",
    "CBORSimpleValue",
    "CBORTag",
    "DefaultCallback",
    "DuplicateMode",
    "TagHook",
    "UndefinedType",
    "dump",
    "dumps",
    "load",
    "loads",
    "undefined",
]
