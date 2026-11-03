"""Bounded *optional* Flate decoder for inspection utilities.

The normal PDFGuard detector NEVER decodes PDF stream bodies. This utility
exists to enforce hard output limits if a future feature explicitly needs
Flate data. Unsupported filters must be rejected, not decoded implicitly.
"""
import zlib

MAX_DECOMPRESSED_BYTES = 2 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100


class DecompressionLimitError(ValueError):
    pass


def bounded_flate_decode(data: bytes, max_output_bytes: int = MAX_DECOMPRESSED_BYTES) -> bytes:
    """Decode a zlib/Flate stream with a strict output budget.

    Refuses data beyond output limit, compression ratio limit, invalid streams,
    or trailing compressed bytes. Do not pass arbitrary PDF filters here.
    """
    if not isinstance(data, bytes):
        raise DecompressionLimitError('Compressed data must be bytes')
    if isinstance(max_output_bytes, bool) or not isinstance(max_output_bytes, int) or not 1 <= max_output_bytes <= MAX_DECOMPRESSED_BYTES:
        raise DecompressionLimitError('Invalid decompression output limit')
    if not data:
        raise DecompressionLimitError('Empty compressed stream')
    # Avoid decoding oversized input even if configured output is small.
    if len(data) > MAX_DECOMPRESSED_BYTES:
        raise DecompressionLimitError('Compressed stream exceeds input budget')
    try:
        decompressor = zlib.decompressobj()
        # max_length bounds output regardless of compressed stream expansion.
        result = decompressor.decompress(data, max_output_bytes + 1)
        if len(result) > max_output_bytes:
            raise DecompressionLimitError('Decompression output limit exceeded')
        # Reject any stream that has not entirely decoded within the budget.
        if not decompressor.eof or decompressor.unconsumed_tail:
            raise DecompressionLimitError('Decompression output limit exceeded or incomplete stream')
        if decompressor.unused_data:
            raise DecompressionLimitError('Unexpected trailing compressed data')
        if len(result) > max(1, len(data)) * MAX_COMPRESSION_RATIO:
            raise DecompressionLimitError('Decompression ratio limit exceeded')
        return result
    except zlib.error:
        raise DecompressionLimitError('Invalid Flate stream') from None
