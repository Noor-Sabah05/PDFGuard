"""Minimal PDF metadata extraction; reads PDFs only, never opens them in a viewer."""
from pathlib import Path
from pypdf import PdfReader
from backend.security_engine.validation import validate_pdf, PDFValidationError


def _clean(value):
    if value is None:
        return ''
    return ''.join(c if c.isprintable() else ' ' for c in str(value))[:200]


def extract_metadata(file_path):
    path = Path(file_path)
    try:
        validate_pdf(path)
    except PDFValidationError as exc:
        # Compatibility with existing Member B tests and legacy API messages.
        if 'signature' in str(exc).lower() or 'version' in str(exc).lower():
            raise ValueError('Invalid PDF header') from None
        raise
    try:
        reader = PdfReader(str(path), strict=True)
        if reader.is_encrypted:
            return {'status': 'encrypted', 'encrypted': True, 'pages': None, 'author': None, 'title': None}
        info = reader.metadata
        return {'status': 'completed', 'encrypted': False, 'pages': len(reader.pages), 'author': _clean(info.author) if info else '', 'title': _clean(info.title) if info else ''}
    except Exception:
        raise ValueError('PDF structure could not be parsed') from None
