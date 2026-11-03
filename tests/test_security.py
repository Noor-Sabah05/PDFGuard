import pytest

from backend.security_engine.validation import (
    validate_pdf,
    PDFValidationError,
)


def test_empty_pdf(tmp_path):
    file = tmp_path / "empty.pdf"
    file.write_bytes(b"")

    with pytest.raises(PDFValidationError, match="Empty"):
        validate_pdf(file)


def test_invalid_file_type(tmp_path):
    file = tmp_path / "malware.exe"
    file.write_bytes(b"not a pdf")

    with pytest.raises(PDFValidationError, match="Only PDF"):
        validate_pdf(file)


def test_fake_pdf(tmp_path):
    file = tmp_path / "fake.pdf"
    file.write_bytes(b"NOT_A_REAL_PDF")

    with pytest.raises(PDFValidationError, match="Invalid PDF"):
        validate_pdf(file)


def test_oversized_file(tmp_path):
    file = tmp_path / "large.pdf"

    with file.open("wb") as f:
        f.write(b"%PDF-1.7")
        f.truncate(11 * 1024 * 1024)

    with pytest.raises(PDFValidationError, match="10 MB"):
        validate_pdf(file)


def test_valid_pdf_header(tmp_path):
    file = tmp_path / "sample.pdf"
    file.write_bytes(b"%PDF-1.7\n%%EOF")

    result = validate_pdf(file)

    assert result["valid"] is True
    assert result["file_type"] == "application/pdf"

from pypdf import PdfWriter

from backend.security_engine.safe_parser import (
    safe_analyze_pdf,
    SafeParserError,
)


def test_safe_parser_valid_pdf(tmp_path):
    file = tmp_path / "valid.pdf"

    writer = PdfWriter()
    writer.add_blank_page(width=300, height=300)

    with file.open("wb") as output:
        writer.write(output)

    result = safe_analyze_pdf(file)

    assert result["status"] == "completed"
    assert result["risk"]["severity"] == "low"
    assert len(result["sha256"]) == 64


def test_safe_parser_invalid_pdf(tmp_path):
    file = tmp_path / "corrupted.pdf"
    file.write_bytes(b"%PDF-1.7\nINVALID STRUCTURE")

    with pytest.raises(SafeParserError):
        safe_analyze_pdf(file)


def test_safe_parser_missing_file():
    with pytest.raises(ValueError, match="not found"):
        safe_analyze_pdf("missing.pdf")


def test_safe_parser_invalid_timeout():
    with pytest.raises(ValueError, match="Timeout"):
        safe_analyze_pdf("sample.pdf", timeout_seconds=0)


def test_safe_parser_invalid_memory_limit():
    with pytest.raises(ValueError, match="Memory limit"):
        safe_analyze_pdf("sample.pdf", memory_limit_mb=10)
