# SPDX-License-Identifier: 0BSD
"""Public value types for the CBOR codec."""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class CBORTag:
    """A CBOR semantic tag (major type 6) wrapping a value.

    Tags without built-in handling decode to CBORTag. Encoding a CBORTag
    writes the tag header followed by the encoded value.
    """

    tag: int
    value: Any


@dataclass(frozen=True, slots=True)
class CBORSimpleValue:
    """An unassigned CBOR simple value (major type 7).

    Values 20, 21, 22 and 23 are the named simple values false, true, null
    and undefined and are never wrapped: decoding yields False, True, None
    and undefined instead. Values 24 through 31 are reserved by RFC 8949
    and are rejected by the encoder.
    """

    value: int


class UndefinedType:
    """Type of the undefined sentinel."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "undefined"

    def __bool__(self) -> bool:
        return False

    def __eq__(self, other: object) -> bool:
        return isinstance(other, UndefinedType)

    def __hash__(self) -> int:
        return hash(UndefinedType)

    def __copy__(self) -> "UndefinedType":
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> "UndefinedType":
        return self


undefined = UndefinedType()
"""Sentinel for the CBOR simple value undefined (0xf7)."""
