import os
import tempfile
import unittest

from file_encoding_sniffer_tools import EncodingGuess, sniff_bytes, sniff_file


class TestSniffBytes(unittest.TestCase):
    def test_utf8_no_bom_plain_ascii(self):
        self.assertEqual(
            sniff_bytes(b"hello world"),
            EncodingGuess(encoding="utf-8", bom=False),
        )

    def test_utf8_with_bom(self):
        self.assertEqual(
            sniff_bytes(b"\xef\xbb\xbfhello"),
            EncodingGuess(encoding="utf-8-sig", bom=True),
        )

    def test_utf8_multibyte_no_bom(self):
        # The Euro sign U+20AC encodes as E2 82 AC in UTF-8.
        self.assertEqual(
            sniff_bytes("price: \u20ac5".encode("utf-8")),
            EncodingGuess(encoding="utf-8", bom=False),
        )

    def test_utf16_le_with_bom(self):
        data = b"\xff\xfe" + "hi".encode("utf-16-le")
        self.assertEqual(
            sniff_bytes(data),
            EncodingGuess(encoding="utf-16-le", bom=True),
        )

    def test_utf16_be_with_bom(self):
        data = b"\xfe\xff" + "hi".encode("utf-16-be")
        self.assertEqual(
            sniff_bytes(data),
            EncodingGuess(encoding="utf-16-be", bom=True),
        )

    def test_utf16_le_by_pattern(self):
        # "Aé" as UTF-16-LE: 41 00 E9 00 — NULs at odd indices.
        # The é (U+00E9) ensures the bytes are not valid UTF-8, so the
        # UTF-16 heuristic runs instead of the UTF-8 path.
        data = "Aé".encode("utf-16-le")
        self.assertEqual(
            sniff_bytes(data),
            EncodingGuess(encoding="utf-16-le", bom=False),
        )

    def test_utf16_be_by_pattern(self):
        # "Aé" as UTF-16-BE: 00 41 00 E9 — NULs at even indices.
        data = "Aé".encode("utf-16-be")
        self.assertEqual(
            sniff_bytes(data),
            EncodingGuess(encoding="utf-16-be", bom=False),
        )

    def test_latin1_fallback(self):
        # 0xE9 (é) alone is invalid UTF-8 and has no BOM; should fall back.
        self.assertEqual(
            sniff_bytes(b"caf\xe9"),
            EncodingGuess(encoding="latin-1", bom=False),
        )

    def test_empty_bytes_returns_latin1(self):
        self.assertEqual(
            sniff_bytes(b""),
            EncodingGuess(encoding="latin-1", bom=False),
        )

    def test_type_error_on_non_bytes(self):
        with self.assertRaises(TypeError):
            sniff_bytes("not bytes")  # type: ignore[arg-type]

    def test_bytearray_accepted(self):
        self.assertEqual(
            sniff_bytes(bytearray(b"hello")),
            EncodingGuess(encoding="utf-8", bom=False),
        )

    def test_ambiguous_iso_8859_1_treated_as_latin1(self):
        # High bytes that are valid Latin-1 but not UTF-8 land as Latin-1.
        self.assertEqual(
            sniff_bytes(b"\xe0\xe1\xe2"),
            EncodingGuess(encoding="latin-1", bom=False),
        )

    def test_truncated_utf8_bom(self):
        # Only the first BOM byte — not a full BOM. 0xEF alone is invalid
        # UTF-8, so the result is the Latin-1 fallback rather than utf-8-sig.
        self.assertEqual(
            sniff_bytes(b"\xefhello"),
            EncodingGuess(encoding="latin-1", bom=False),
        )

    def test_repr(self):
        r = repr(sniff_bytes(b"hello"))
        self.assertIn("utf-8", r)
        self.assertIn("bom=False", r)


class TestSniffFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False)
        self.addCleanup(os.unlink, self.tmp.name)
        self.tmp.close()

    def _write(self, data: bytes):
        with open(self.tmp.name, "wb") as fh:
            fh.write(data)

    def test_file_utf8_with_bom(self):
        self._write(b"\xef\xbb\xbfhello")
        self.assertEqual(
            sniff_file(self.tmp.name),
            EncodingGuess(encoding="utf-8-sig", bom=True),
        )

    def test_file_utf16_le_with_bom(self):
        self._write(b"\xff\xfe" + "hi".encode("utf-16-le"))
        self.assertEqual(
            sniff_file(self.tmp.name),
            EncodingGuess(encoding="utf-16-le", bom=True),
        )

    def test_file_utf8_plain(self):
        self._write("plain utf-8 \u2014 text".encode("utf-8"))
        self.assertEqual(
            sniff_file(self.tmp.name),
            EncodingGuess(encoding="utf-8", bom=False),
        )

    def test_file_latin1_fallback(self):
        self._write(b"caf\xe9")
        self.assertEqual(
            sniff_file(self.tmp.name),
            EncodingGuess(encoding="latin-1", bom=False),
        )

    def test_file_missing_raises(self):
        with self.assertRaises(FileNotFoundError):
            sniff_file("does-not-exist-xyz")

    def test_small_sample_size_clamped(self):
        # With sample_size=1, we still read at least 3 bytes (the BOM length).
        self._write(b"\xef\xbb\xbfx")
        self.assertEqual(
            sniff_file(self.tmp.name, sample_size=1),
            EncodingGuess(encoding="utf-8-sig", bom=True),
        )

    def test_pathlike_accepted(self):
        self._write(b"hello")
        result = sniff_file(os.path.join(os.path.dirname(self.tmp.name),
                                          os.path.basename(self.tmp.name)))
        self.assertEqual(result.encoding, "utf-8")


if __name__ == "__main__":
    unittest.main()
