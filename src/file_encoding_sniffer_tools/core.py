# Core guessing logic.
#
# Decision order:
#   1. BOM check (UTF-8, UTF-16 LE, UTF-16 BE)
#   2. UTF-8 structural validity over the entire sample
#   3. UTF-16 heuristic: many NUL bytes in even or odd positions
#   4. Latin-1 fallback
#
# Why this order: BOMs are authoritative when present. After that, UTF-8 has a
# strict structural signature, so validating it is the cheapest reliable
# signal. UTF-16 detection by content is intrinsically fuzzier — we use a
# threshold heuristic and return a plain "utf-16" rather than guessing the
# endianness, so callers can pass encoding= to Python and let it figure out
# the rest. Latin-1 is last because it accepts every byte sequence and
# therefore must be the fallback.

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import IO

# Minimum number of bytes we look at when there is no BOM. 1024 is enough to
# see a representative mix of bytes for the UTF-16 heuristic, without reading
# the whole file for very large inputs.
DEFAULT_SAMPLE_SIZE = 1024

# Minimum number of NUL bytes in the first sample to even consider UTF-16.
# This filters out incidental NULs in Latin-1 text, which are rare but
# possible in files that contain C0 control characters.
#
# We use the number of consecutive NUL-bearing positions as the score. Two or
# more is strong evidence of UTF-16 for realistic text (ASCII characters
# encoded as 2 bytes have a NUL as the high byte).
_UTF16_MIN_NUL_RUN = 2


class _NeedMoreData(Exception):
    """Internal: raised when too few bytes are available to make any claim."""


def _has_bom(data: bytes) -> str | None:
    if len(data) >= 3 and data[0:3] == b"\xef\xbb\xbf":
        return "utf-8-sig"
    if len(data) >= 2 and data[0:2] == b"\xff\xfe":
        return "utf-16-le"
    if len(data) >= 2 and data[0:2] == b"\xfe\xff":
        return "utf-16-be"
    return None


def _looks_like_utf8(data: bytes) -> bool:
    """Return True iff *data* decodes as strict UTF-8.

    Using strict decode is the right tool here: UTF-8's byte structure is
    rigid enough that a wrong guess fails with a clear exception, and we
    want False rather than an exception in that case.
    """
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def _score_utf16(data: bytes) -> tuple[int, int]:
    """Return (odd_nuls, even_nuls) counts in the first 64 byte positions.

    We cap the window so a single NUL in a large file does not move the
    needle too far; the first 64 positions are enough to distinguish UTF-16
    from Latin-1 for any realistic text sample.
    """
    sample = data[:64]
    odd = 0
    even = 0
    for i, b in enumerate(sample):
        if b == 0:
            if i % 2 == 0:
                even += 1
            else:
                odd += 1
    return odd, even


def _utf16_from_pattern(odd: int, even: int) -> str | None:
    if max(odd, even) < _UTF16_MIN_NUL_RUN:
        return None
    if odd >= even:
        return "utf-16-le"
    return "utf-16-be"


def _guess_no_bom(data: bytes) -> str | None:
    if len(data) == 0:
        raise _NeedMoreData()
    if _looks_like_utf8(data):
        return "utf-8"
    odd, even = _score_utf16(data)
    utf16 = _utf16_from_pattern(odd, even)
    if utf16 is not None:
        return utf16
    return "latin-1"


@dataclass(frozen=True)
class EncodingGuess:
    """The result of a sniff.

    Attributes:
        encoding: The guessed Python codec name. Always lower-case.
        bom: True iff a byte-order mark was present and authoritative.
    """

    encoding: str
    bom: bool

    def __repr__(self) -> str:
        return f"EncodingGuess(encoding={self.encoding!r}, bom={self.bom})"


def sniff_bytes(data: bytes) -> EncodingGuess:
    """Guess the encoding of *data*.

    Always returns an ``EncodingGuess`` for non-empty *data*. Returns
    ``EncodingGuess(encoding='latin-1', bom=False)`` for empty input, on the
    principle that a Latin-1 decode of nothing is the safest no-op.

    Raises:
        TypeError: if *data* is not bytes.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    data = bytes(data)
    if len(data) == 0:
        return EncodingGuess(encoding="latin-1", bom=False)
    bom = _has_bom(data)
    if bom is not None:
        return EncodingGuess(encoding=bom, bom=True)
    try:
        enc = _guess_no_bom(data)
    except _NeedMoreData:
        enc = "latin-1"
    assert enc is not None
    return EncodingGuess(encoding=enc, bom=False)


def sniff_file(path: str | os.PathLike, sample_size: int = DEFAULT_SAMPLE_SIZE) -> EncodingGuess:
    """Guess the encoding of the file at *path* by reading its first bytes.

    Args:
        path: Filesystem path.
        sample_size: Maximum number of bytes to read. Must be >= 3 to see the
            UTF-8 BOM; smaller values are clamped up to 3.

    Raises:
        FileNotFoundError, IsADirectoryError, PermissionError, OSError:
            propagated from the underlying open().
    """
    if sample_size < 3:
        sample_size = 3
    with open(path, "rb") as fh:  # type: IO[bytes]
        data = fh.read(sample_size)
    return sniff_bytes(data)
