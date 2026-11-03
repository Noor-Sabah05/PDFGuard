"""Additional acceptance/evaluation tests; retains existing tests separately."""
import time
import zlib
import pytest
from pypdf import PdfWriter
from pypdf.generic import DictionaryObject, NameObject, TextStringObject, DecodedStreamObject
from backend.security_engine.analyzer import analyze_pdf
from backend.security_engine.indicators import detect_indicators
from backend.security_engine.validation import validate_pdf, PDFValidationError
from backend.security_engine.risk_score import calculate_risk
from backend.security_engine.safe_parser import safe_analyze_pdf, SafeParserError
from tools.evaluate import evaluate


def make_pdf(path, kind='benign'):
    writer = PdfWriter()
    writer.add_blank_page(width=300, height=300)
    if kind in ('javascript', 'launch'):
        a = DictionaryObject({NameObject('/S'): NameObject('/JavaScript' if kind == 'javascript' else '/Launch')})
        if kind == 'javascript':
            a[NameObject('/JS')] = TextStringObject('harmless-fixture')
        writer._root_object[NameObject('/OpenAction')] = writer._add_object(a)
    if kind == 'embedded':
        writer.add_attachment('safe.txt', b'harmless')
    if kind == 'encrypted':
        writer.encrypt('password')
    with path.open('wb') as out:
        writer.write(out)
    return path


@pytest.mark.parametrize('kind,expected', [('benign', []), ('javascript', ['/JS', '/JavaScript', '/OpenAction']), ('launch', ['/Launch', '/OpenAction']), ('embedded', ['/EmbeddedFile'])])
def test_indicators_by_structure(tmp_path, kind, expected):
    file = make_pdf(tmp_path / (kind + '.pdf'), kind)
    found = {e['indicator'] for e in detect_indicators(file)['indicators']}
    assert set(expected).issubset(found)


def test_encrypted_not_low_risk(tmp_path):
    result = analyze_pdf(make_pdf(tmp_path / 'locked.pdf', 'encrypted'))
    assert result['status'] == 'encrypted'
    assert result['risk'] is None


def test_corrupt_pdf_rejected(tmp_path):
    p = tmp_path / 'broken.pdf'
    p.write_bytes(b'%PDF-1.7\nnot a real PDF\n%%EOF')
    with pytest.raises(ValueError):
        analyze_pdf(p)


def test_repeated_submission_same_fingerprint(tmp_path):
    p = make_pdf(tmp_path / 'a.pdf')
    assert analyze_pdf(p)['sha256'] == analyze_pdf(p)['sha256']


def test_risk_invalid_input():
    with pytest.raises(ValueError):
        calculate_risk([123])


def test_risk_deduplication():
    hits = [{'indicator': '/Launch'}, {'indicator': '/Launch'}]
    assert calculate_risk(hits)['risk_score'] == 45


def test_oversized_rejected_before_parsing(tmp_path):
    p = tmp_path / 'oversized.pdf'
    with p.open('wb') as f:
        f.write(b'%PDF-1.7')
        f.truncate(11 * 1024 * 1024)
    with pytest.raises(PDFValidationError):
        safe_analyze_pdf(p)


def test_stream_is_not_decompressed(tmp_path, monkeypatch):
    p = tmp_path / 'stream.pdf'
    writer = PdfWriter()
    writer.add_blank_page(width=300, height=300)
    stream = DecodedStreamObject()
    stream.set_data(b'A' * 100000)
    compressed = stream.flate_encode()
    writer._root_object[NameObject('/TestStream')] = writer._add_object(compressed)
    with p.open('wb') as out:
        writer.write(out)
    # Engine only walks structural dictionaries; no get_data() call.
    from pypdf.generic import EncodedStreamObject
    def reject_decode(self):
        raise AssertionError('Stream data must not be decompressed')
    monkeypatch.setattr(EncodedStreamObject, 'get_data', reject_decode)
    assert detect_indicators(p)['status'] == 'completed'


def test_safe_process(tmp_path):
    p = make_pdf(tmp_path / 'a.pdf')
    assert safe_analyze_pdf(p)['status'] == 'completed'


def test_safe_process_malformed(tmp_path):
    p = tmp_path / 'broken.pdf'
    p.write_bytes(b'%PDF-1.7\ncorrupt')
    with pytest.raises(SafeParserError):
        safe_analyze_pdf(p)


def test_latency_under_generous_limit(tmp_path):
    p = make_pdf(tmp_path / 'normal.pdf')
    start = time.perf_counter()
    safe_analyze_pdf(p)
    assert time.perf_counter() - start < 10


def test_corpus_results():
    summary = evaluate()
    assert len(summary['cases']) == 10
    assert all(row['pass'] for row in summary['cases'])
