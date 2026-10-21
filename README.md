# file-encoding-sniffer-tools

Reads the BOM and the first kilobyte of a file to guess whether it is UTF-8, UTF-16, or Latin-1. Returns a Python codec name you can pass straight to `open()` or `bytes.decode()`.

```python
from file_encoding_sniffer_tools import sniff_file, sniff_bytes, EncodingGuess

# Write a sample file first.
with open("some.txt", "w", encoding="utf-8") as fh:
    fh.write("hello world")

guess: EncodingGuess = sniff_file("some.txt")
print(guess.encoding, guess.bom)

with open("some.txt", encoding=guess.encoding) as fh:
    text = fh.read()
```

For bytes already in memory:

```python
from file_encoding_sniffer_tools import sniff_bytes

raw_bytes = b"hello world"
guess = sniff_bytes(raw_bytes)
print(guess.encoding)
```

## Why

Real text files do not always declare their encoding. A BOM, when present, settles the question for UTF-8 and UTF-16. Without one, the cheapest reliable signal is UTF-8's structural byte pattern: strict UTF-8 decode either succeeds or fails with an exception, so we treat that as a yes/no test. If UTF-8 fails and the bytes look like UTF-16 (many NUL bytes at even or odd positions), we return a UTF-16 codec. Everything else falls through to Latin-1, which decodes any byte sequence losslessly and is the conventional last-resort guess for legacy Western European text.

This is a *sniffer*, not a full statistical detector. It exists for the case where you have to open a file you did not produce and need a codec name now, without pulling in a heavier dependency.

## Edge cases you will hit

- The library cannot distinguish Latin-1 from Windows-1252; it always returns `latin-1` for non-UTF-8 Western byte streams. For pure ASCII content that distinction does not matter.
- UTF-16 detection without a BOM is a heuristic. Files containing C0 control characters (including literal NUL bytes outside a UTF-16 context) can produce a false UTF-16 guess. If you control the producer, write a BOM.
- Empty input returns `EncodingGuess(encoding="latin-1", bom=False)`, because decoding zero bytes as Latin-1 is the safest no-op.
- The UTF-8 BOM is reported as `utf-8-sig` so that re-reading the file with the returned codec strips the BOM rather than leaving it in the decoded text.

## API

- `sniff_file(path: str | os.PathLike, sample_size: int = 1024) -> EncodingGuess`
- `sniff_bytes(data: bytes | bytearray) -> EncodingGuess`
- `EncodingGuess` is a frozen dataclass with `encoding: str` and `bom: bool`.
