# file-encoding-sniffer-tools
#
# Reads the BOM (and initial bytes when no BOM is present) and guesses whether a
# text file is UTF-8, UTF-16 (LE or BE), or Latin-1. The guess is fast, cheap,
# and deliberately simple; it is not a full encoding detector.

from file_encoding_sniffer_tools.core import EncodingGuess, sniff_bytes, sniff_file

__all__ = ["EncodingGuess", "sniff_bytes", "sniff_file"]

__version__ = "1.0.0"
