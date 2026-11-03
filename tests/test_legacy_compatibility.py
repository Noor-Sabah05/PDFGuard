"""Rebuild of the 22 previously shown tests' API expectations, to check compatibility.
Does not replace the user's original tests, which the installer preserves.
"""
import pytest
from pypdf import PdfWriter
from pypdf.generic import DictionaryObject, NameObject, TextStringObject
from backend.security_engine.metadata import extract_metadata
from backend.security_engine.indicators import detect_indicators
from backend.security_engine.risk_score import calculate_risk
from backend.security_engine.analyzer import analyze_pdf
from backend.security_engine.validation import validate_pdf, PDFValidationError
from backend.security_engine.safe_parser import safe_analyze_pdf, SafeParserError


def build(p, suspicious=False):
    w = PdfWriter(); w.add_blank_page(width=300, height=300)
    if suspicious:
        a = DictionaryObject({NameObject('/S'):NameObject('/JavaScript'), NameObject('/JS'):TextStringObject('inert-test-marker')})
        w._root_object[NameObject('/OpenAction')] = w._add_object(a)
    w.write(p)
    return p


def test_previous_metadata_and_analysis(tmp_path):
    p=build(tmp_path/'sample.pdf'); assert extract_metadata(p)['pages']==1
    assert analyze_pdf(p)['risk']['risk_score']==0
    assert len(analyze_pdf(p)['sha256'])==64


def test_previous_javascript_and_explanation(tmp_path):
    p=build(tmp_path/'suspicious.pdf',True)
    assert {'/OpenAction','/JS'} <= {x['indicator'] for x in detect_indicators(p)['indicators']}
    assert analyze_pdf(p)['risk']['risk_score'] > 0


def test_previous_risk_weights():
    assert calculate_risk([])['risk_score']==0
    assert calculate_risk([{'indicator':'/JavaScript'},{'indicator':'/JS'}])['risk_score']==45
    assert calculate_risk([{'indicator':'/Launch'},{'indicator':'/OpenAction'}])['risk_score']==70
    assert calculate_risk([{'indicator':'/Launch'},{'indicator':'/Launch'}])['risk_score']==45


def test_previous_validation_messages(tmp_path):
    p=tmp_path/'bad.pdf'; p.write_bytes(b'NOT A PDF')
    with pytest.raises(ValueError,match='Invalid PDF header'): extract_metadata(p)
    with pytest.raises(ValueError,match='Invalid PDF'): validate_pdf(p)
    with pytest.raises(ValueError,match='not found'): extract_metadata(tmp_path/'missing.pdf')
    with pytest.raises(ValueError,match='not found'): safe_analyze_pdf(tmp_path/'missing.pdf')


def test_previous_safe_process(tmp_path):
    p=build(tmp_path/'valid.pdf'); assert safe_analyze_pdf(p)['status']=='completed'
    p=tmp_path/'corrupt.pdf'; p.write_bytes(b'%PDF-1.7\nINVALID STRUCTURE')
    with pytest.raises(SafeParserError): safe_analyze_pdf(p)
    with pytest.raises(ValueError,match='Timeout'):safe_analyze_pdf(p,timeout_seconds=0)
    with pytest.raises(ValueError,match='Memory limit'):safe_analyze_pdf(p,memory_limit_mb=10)
