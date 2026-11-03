"""CLI example: python -m tools.scan path/to/trusted.pdf"""
import argparse
import json
from backend.security_engine.safe_parser import safe_analyze_pdf


def main():
    parser = argparse.ArgumentParser(description='PDFGuard training-fixture scanner')
    parser.add_argument('pdf', help='PDF path')
    args = parser.parse_args()
    try:
        print(json.dumps(safe_analyze_pdf(args.pdf), indent=2))
    except (ValueError, Exception) as exc:
        # CLI output contains no stack trace, internal paths or user metadata.
        print(json.dumps({'status': 'error', 'message': str(exc) if str(exc) in ('PDF file not found', 'Only PDF files are allowed', 'Empty PDF file', 'PDF exceeds 10 MB limit', 'Invalid PDF signature or version', 'PDF analysis timed out', 'PDF analysis memory limit exceeded') else 'PDF analysis was rejected or failed'}))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
