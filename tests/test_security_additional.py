"""Extra error handling, resource limits and T-final local-engine checks."""
import pytest
from pypdf import PdfWriter
from backend.security_engine.safe_parser import safe_analyze_pdf, SafeParserError
from backend.security_engine.validation import validate_pdf, PDFValidationError
from backend.security_engine.risk_score import calculate_risk
from backend.security_engine.indicators import detect_indicators


def test_t2_header_only_is_not_valid_pdf(tmp_path):
    file = tmp_path / 'header_only.pdf'
    file.write_bytes(b'%PDF-1.7\n%%EOF')
    validate_pdf(file)
    with pytest.raises((ValueError, SafeParserError)):
        safe_analyze_pdf(file)


def test_tfinal_repeat_has_stable_hash(tmp_path):
    f = tmp_path / 'repeat.pdf'
    w = PdfWriter()
    w.add_blank_page(width=100, height=100)
    w.write(f)
    one = safe_analyze_pdf(f)
    two = safe_analyze_pdf(f)
    assert one['sha256'] == two['sha256']
    assert one['risk'] == two['risk']


def test_unknown_rule_gives_no_unjustified_critical():
    result = calculate_risk([{'indicator': '/Unknown'}])
    assert result['severity'] == 'low'
    assert result['risk_score'] == 0


def test_tfinal_disallowed_extension(tmp_path):
    f = tmp_path / 'not_pdf.txt'
    f.write_bytes(b'%PDF-1.7\n%%EOF')
    with pytest.raises(PDFValidationError):
        safe_analyze_pdf(f)


def test_finding_evidence_location(tmp_path):
    from pypdf.generic import DictionaryObject, NameObject
    f = tmp_path / 'launch.pdf'
    w = PdfWriter()
    w.add_blank_page(width=100, height=100)
    action = DictionaryObject({NameObject('/S'): NameObject('/Launch')})
    w._root_object[NameObject('/OpenAction')] = w._add_object(action)
    w.write(f)
    result = detect_indicators(f)
    assert any(hit['indicator'] == '/Launch' and hit['location'] for hit in result['indicators'])
