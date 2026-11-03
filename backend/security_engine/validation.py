"""Pre-parse validation. Header checks are not proof of a well-formed PDF."""
from pathlib import Path

MAX_FILE_SIZE = 10 * 1024 * 1024
MIN_FILE_SIZE = 8


class PDFValidationError(ValueError):
    pass


def validate_pdf(file_path):
    path = Path(file_path)
    if not path.is_file():
        raise PDFValidationError('PDF file not found')
    if path.suffix.lower() != '.pdf':
        raise PDFValidationError('Only PDF files are allowed')
    size = path.stat().st_size
    if size == 0:
        raise PDFValidationError('Empty PDF file')
    if size > MAX_FILE_SIZE:
        raise PDFValidationError('PDF exceeds 10 MB limit')
    if size < MIN_FILE_SIZE:
        raise PDFValidationError('PDF file is too small')
    with path.open('rb') as f:
        header = f.read(8)
    if len(header) < 8 or header[:5] != b'%PDF-' or header[5:6] not in b'0123456789' or header[6:7] != b'.' or header[7:8] not in b'0123456789':
        raise PDFValidationError('Invalid PDF signature or version')
    return {'valid': True, 'file_size': size, 'file_type': 'application/pdf', 'filename': path.name}
