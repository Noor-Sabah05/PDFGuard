# PDFGuard security-engine tests
import pytest
from pypdf import PdfWriter
from backend.security_engine.metadata import extract_metadata


def test_valid_pdf(tmp_path):
    file = tmp_path / "normal.pdf"

    writer = PdfWriter()
    writer.add_blank_page(width=595, height=842)
    writer.add_metadata({
        "/Title": "Test Document",
        "/Author": "PDFGuard Test"
    })

    with file.open("wb") as output:
        writer.write(output)

    result = extract_metadata(file)

    assert result["status"] == "completed"
    assert result["pages"] == 1
    assert result["title"] == "Test Document"
    assert result["encrypted"] is False


def test_invalid_pdf(tmp_path):
    file = tmp_path / "invalid.pdf"
    file.write_bytes(b"NOT A PDF")

    with pytest.raises(ValueError, match="Invalid PDF header"):
        extract_metadata(file)


def test_missing_pdf():
    with pytest.raises(ValueError, match="PDF file not found"):
        extract_metadata("missing.pdf")


def test_oversized_pdf(tmp_path):
    file = tmp_path / "large.pdf"

    with file.open("wb") as output:
        output.write(b"%PDF-")
        output.truncate(11 * 1024 * 1024)

    with pytest.raises(ValueError, match="10 MB limit"):
        extract_metadata(file)

#-----------------------------------------
from pypdf.generic import (
    DictionaryObject,
    NameObject,
    TextStringObject,
)

from backend.security_engine.indicators import detect_indicators


def test_benign_pdf_indicators(tmp_path):
    file = tmp_path / "benign.pdf"

    writer = PdfWriter()
    writer.add_blank_page(width=300, height=300)

    with file.open("wb") as output:
        writer.write(output)

    result = detect_indicators(file)

    assert result["status"] == "completed"
    assert result["indicators"] == []


def test_javascript_indicators(tmp_path):
    file = tmp_path / "suspicious.pdf"

    writer = PdfWriter()
    writer.add_blank_page(width=300, height=300)

    action = DictionaryObject({
        NameObject("/S"): NameObject("/JavaScript"),
        NameObject("/JS"): TextStringObject(
            "inert-test-marker"
        ),
    })

    writer._root_object[NameObject("/OpenAction")] = (
        writer._add_object(action)
    )

    with file.open("wb") as output:
        writer.write(output)

    result = detect_indicators(file)

    names = {
        item["indicator"]
        for item in result["indicators"]
    }

    assert "/OpenAction" in names
    assert "/JS" in names

#--------------------------------

from backend.security_engine.risk_score import calculate_risk


def test_low_risk():
    result = calculate_risk([])

    assert result["risk_score"] == 0
    assert result["severity"] == "low"


def test_medium_risk():
    indicators = [
        {
            "indicator": "/JavaScript",
            "reason": "JavaScript action"
        },
        {
            "indicator": "/JS",
            "reason": "JavaScript code entry"
        }
    ]

    result = calculate_risk(indicators)

    assert result["risk_score"] == 45
    assert result["severity"] == "medium"


def test_high_risk():
    indicators = [
        {"indicator": "/Launch"},
        {"indicator": "/OpenAction"}
    ]

    result = calculate_risk(indicators)

    assert result["risk_score"] == 70
    assert result["severity"] == "high"


def test_duplicate_indicators():
    indicators = [
        {"indicator": "/Launch"},
        {"indicator": "/Launch"}
    ]

    result = calculate_risk(indicators)

    assert result["risk_score"] == 45

#---------------------------------------
from backend.security_engine.analyzer import analyze_pdf


def test_complete_benign_analysis(tmp_path):
    file = tmp_path / "normal.pdf"

    writer = PdfWriter()
    writer.add_blank_page(width=300, height=300)

    with file.open("wb") as output:
        writer.write(output)

    result = analyze_pdf(file)

    assert result["status"] == "completed"
    assert result["metadata"]["pages"] == 1
    assert result["risk"]["risk_score"] == 0
    assert len(result["sha256"]) == 64


def test_complete_suspicious_analysis(tmp_path):
    file = tmp_path / "suspicious.pdf"

    writer = PdfWriter()
    writer.add_blank_page(width=300, height=300)

    action = DictionaryObject({
        NameObject("/S"): NameObject("/JavaScript"),
        NameObject("/JS"): TextStringObject(
            "inert-test-marker"
        ),
    })

    writer._root_object[NameObject("/OpenAction")] = (
        writer._add_object(action)
    )

    with file.open("wb") as output:
        writer.write(output)

    result = analyze_pdf(file)

    assert result["status"] == "completed"
    assert result["risk"]["risk_score"] > 0
    assert len(result["indicators"]) > 0

#------------------------------------------
from backend.security_engine.analyzer import analyze_pdf


def test_complete_benign_analysis(tmp_path):
    file = tmp_path / "normal.pdf"

    writer = PdfWriter()
    writer.add_blank_page(width=300, height=300)

    with file.open("wb") as output:
        writer.write(output)

    result = analyze_pdf(file)

    assert result["status"] == "completed"
    assert result["metadata"]["pages"] == 1
    assert result["risk"]["risk_score"] == 0
    assert len(result["sha256"]) == 64


def test_complete_suspicious_analysis(tmp_path):
    file = tmp_path / "suspicious.pdf"

    writer = PdfWriter()
    writer.add_blank_page(width=300, height=300)

    action = DictionaryObject({
        NameObject("/S"): NameObject("/JavaScript"),
        NameObject("/JS"): TextStringObject(
            "inert-test-marker"
        ),
    })

    writer._root_object[NameObject("/OpenAction")] = (
        writer._add_object(action)
    )

    with file.open("wb") as output:
        writer.write(output)

    result = analyze_pdf(file)

    assert result["status"] == "completed"
    assert result["risk"]["risk_score"] > 0
    assert len(result["indicators"]) > 0
