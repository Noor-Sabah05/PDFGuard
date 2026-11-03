"""T3: safe decompression and bomb defenses; no real malware."""
import zlib
import pytest
from backend.security_engine.decompression import (
    bounded_flate_decode, DecompressionLimitError,
)


def test_t3_small_normal_stream():
    raw = b'This is a bounded PDFGuard fixture. ' * 3
    assert bounded_flate_decode(zlib.compress(raw)) == raw


def test_t3_large_expansion_rejected():
    bomb = zlib.compress(b'A' * (4 * 1024 * 1024), level=9)
    assert len(bomb) < 10_000
    with pytest.raises(DecompressionLimitError, match='output limit'):
        bounded_flate_decode(bomb)


def test_t3_ratio_limit_rejected():
    bomb = zlib.compress(b'B' * 100000)
    with pytest.raises(DecompressionLimitError, match='ratio limit'):
        bounded_flate_decode(bomb)


def test_t3_truncated_deflate_rejected():
    compressed = zlib.compress(b'example' * 100)
    with pytest.raises(DecompressionLimitError):
        bounded_flate_decode(compressed[:-2])


def test_t3_unsupported_invalid_stream_rejected():
    with pytest.raises(DecompressionLimitError):
        bounded_flate_decode(b'not deflate data')


def test_t3_invalid_limit_rejected():
    with pytest.raises(DecompressionLimitError):
        bounded_flate_decode(zlib.compress(b'hello'), max_output_bytes=10_000_000)


def test_t3_trailing_data_rejected():
    with pytest.raises(DecompressionLimitError, match='trailing'):
        bounded_flate_decode(zlib.compress(b'hello') + b'extra')
