"""One dependency-free strict JSON reader.

``json.loads`` quietly accepts two things a security-relevant reader must not: an object that
repeats a key (the last value wins, so two readers can disagree about the document) and the
non-standard constants ``NaN`` / ``Infinity`` / ``-Infinity`` (which are not JSON and compare
unlike any number). :func:`loads` refuses both at every nesting level and turns every other way a
document can fail to parse into one exception type carrying a stable reason code.

This is the lowest layer of the package: it imports nothing from ``liebert_re`` (so the evidence
layer can use it without depending on ``dynamic``) and only the standard library.

Input policy: ``str`` is parsed as given (a leading BOM character in a ``str`` is malformed, as in
``json.loads``). ``bytes`` / ``bytearray`` are decoded as UTF-8 and ONE leading UTF-8 BOM is
accepted and dropped; undecodable bytes are MALFORMED, never replaced. ``max_bytes`` bounds the
UTF-8 size of the input BEFORE any parsing.

Callers map :attr:`StrictJSONError.reason` to their own codes; this module never changes what a
caller reports.
"""

from __future__ import annotations

import json
from typing import Any

DUPLICATE_KEY = "DUPLICATE_KEY"
NON_FINITE = "NON_FINITE"
TOO_LARGE = "TOO_LARGE"
TOO_DEEP = "TOO_DEEP"
MALFORMED = "MALFORMED"
REASONS = (DUPLICATE_KEY, NON_FINITE, TOO_LARGE, TOO_DEEP, MALFORMED)

__all__ = ["StrictJSONError", "loads", "REASONS", *REASONS]


class StrictJSONError(ValueError):
    """The input is not strict JSON. ``reason`` is one of :data:`REASONS`."""

    def __init__(self, reason: str, message: str = "") -> None:
        super().__init__(message or reason)
        self.reason = reason


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise StrictJSONError(DUPLICATE_KEY, f"duplicate JSON key {key!r}")
        out[key] = value
    return out


def _refuse_constant(name: str) -> Any:
    raise StrictJSONError(NON_FINITE, f"non-finite JSON number {name}")


def _text(data: Any, max_bytes: int | None) -> str:
    if isinstance(data, (bytes, bytearray)):
        if max_bytes is not None and len(data) > max_bytes:
            raise StrictJSONError(TOO_LARGE, f"{len(data)} bytes exceeds the {max_bytes}-byte limit")
        try:
            return bytes(data).decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise StrictJSONError(MALFORMED, f"not valid UTF-8: {exc.reason}") from None
    if isinstance(data, str):
        if max_bytes is not None:
            # A str cannot be longer in bytes than 4 * len; only encode when the bound is unclear.
            size = len(data) if len(data) * 4 <= max_bytes else len(data.encode("utf-8", "surrogatepass"))
            if size > max_bytes:
                raise StrictJSONError(TOO_LARGE, f"{size} bytes exceeds the {max_bytes}-byte limit")
        return data
    raise TypeError(f"strict_json.loads wants str or bytes, not {type(data).__name__}")


def loads(data: str | bytes | bytearray, *, max_bytes: int | None = None) -> Any:
    """Parse ``data`` as strict JSON; raise :class:`StrictJSONError` (a ``ValueError``) otherwise.

    Duplicate object keys are refused at every depth (DUPLICATE_KEY), as are ``NaN`` /
    ``Infinity`` / ``-Infinity`` (NON_FINITE); there is no switch to allow them. Over-large input is
    TOO_LARGE (exactly ``max_bytes`` is accepted), nesting deeper than the interpreter's recursion
    limit is TOO_DEEP, and anything else unparsable is MALFORMED. A non-str/bytes argument is a
    ``TypeError``: that is a caller bug, not a bad document.
    """
    text = _text(data, max_bytes)
    try:
        return json.loads(text, object_pairs_hook=_no_duplicate_keys, parse_constant=_refuse_constant)
    except StrictJSONError:
        raise
    except RecursionError:
        raise StrictJSONError(TOO_DEEP, "JSON nesting is too deep") from None
    except ValueError as exc:  # JSONDecodeError, or an over-long integer literal
        raise StrictJSONError(MALFORMED, str(exc)) from None
