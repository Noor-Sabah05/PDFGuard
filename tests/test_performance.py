"""Repeatable smoke/performance checks, not claims of production throughput."""
import time
from pypdf import PdfWriter
from backend.security_engine.safe_parser import safe_analyze_pdf


def test_safe_process_latency_within_timeout(tmp_path):
    p = tmp_path / 'small.pdf'
    writer = PdfWriter()
    writer.add_blank_page(width=300, height=300)
    writer.write(p)
    start = time.perf_counter()
    result = safe_analyze_pdf(p, timeout_seconds=10)
    elapsed = time.perf_counter() - start
    assert result['status'] == 'completed'
    assert elapsed < 10
