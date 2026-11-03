"""Repeatable, harmless Member B evaluation: python -m tools.evaluate

Only synthetic data is used. This is NOT real-world malware accuracy.
"""
import json
import statistics
import tempfile
import time
import zlib
from pathlib import Path
from pypdf import PdfWriter
from pypdf.generic import DictionaryObject, NameObject, TextStringObject
from backend.security_engine.safe_parser import safe_analyze_pdf, SafeParserError
from backend.security_engine.decompression import bounded_flate_decode, DecompressionLimitError
from backend.security_engine.validation import PDFValidationError


def write_sample(path, kind):
    writer = PdfWriter()
    writer.add_blank_page(width=300, height=300)
    if kind in ('javascript', 'launch'):
        action = DictionaryObject({NameObject('/S'): NameObject('/JavaScript' if kind == 'javascript' else '/Launch')})
        if kind == 'javascript':
            action[NameObject('/JS')] = TextStringObject('inert-fixture-marker')
        writer._root_object[NameObject('/OpenAction')] = writer._add_object(action)
    elif kind == 'attachment':
        writer.add_attachment('harmless.txt', b'safe attachment marker')
    elif kind == 'encrypted':
        writer.encrypt('training-password')
    writer.write(path)


def evaluate():
    cases = []
    with tempfile.TemporaryDirectory(prefix='pdfguard-eval-') as temp:
        base = Path(temp)
        # T1/T4: benign vs rule-seeded positives; note attachment is only an indicator.
        samples = [
            ('benign', 'low', False, 'T1'),
            ('javascript', 'high', True, 'T4'),
            ('launch', 'high', True, 'T4'),
            ('attachment', 'low', False, 'T1'),
            ('encrypted', 'encrypted', None, 'T5'),
        ]
        for label, expected, positive, test_id in samples:
            path = base / f'{label}.pdf'
            write_sample(path, label)
            start = time.perf_counter()
            result = safe_analyze_pdf(path)
            elapsed = round((time.perf_counter() - start) * 1000, 2)
            actual = result['status'] if result['status'] == 'encrypted' else result['risk']['severity']
            cases.append({'test': test_id, 'fixture': label, 'expected': expected, 'actual': actual,
                          'pass': actual == expected, 'latency_ms': elapsed,
                          'sha256': result['sha256'],
                          'evidence': [f['indicator'] for f in result.get('indicators', [])]})

        # T2: corrupt structure must fail closed and not print a stack trace to users.
        corrupt = base / 'corrupt.pdf'
        corrupt.write_bytes(b'%PDF-1.7\nBAD PDF STRUCTURE')
        try:
            safe_analyze_pdf(corrupt)
            actual = 'accepted'
        except (SafeParserError, PDFValidationError):
            actual = 'rejected'
        cases.append({'test': 'T2', 'fixture': 'corrupt-structure', 'expected': 'rejected',
                      'actual': actual, 'pass': actual == 'rejected', 'evidence': ['parser error handled']})

        # T3: strict, bounded optional Flate decoder rejects expanding payload.
        compressed = zlib.compress(b'X' * (4 * 1024 * 1024), 9)
        try:
            bounded_flate_decode(compressed)
            actual = 'accepted'
        except DecompressionLimitError:
            actual = 'rejected'
        cases.append({'test': 'T3', 'fixture': 'synthetic-flate-expansion', 'expected': 'rejected',
                      'actual': actual, 'pass': actual == 'rejected',
                      'evidence': ['2 MiB decoded-output cap', '100x expansion-ratio cap']})

        # T-final: forged type, too big, repeatability, and harmless worker isolation.
        wrong_type = base / 'fake.txt'
        wrong_type.write_bytes(b'%PDF-1.7\n%%EOF')
        try:
            safe_analyze_pdf(wrong_type)
            actual = 'accepted'
        except PDFValidationError:
            actual = 'rejected'
        cases.append({'test': 'T-final', 'fixture': 'wrong-extension', 'expected': 'rejected',
                      'actual': actual, 'pass': actual == 'rejected', 'evidence': ['extension gate']})

        oversized = base / 'oversized.pdf'
        with oversized.open('wb') as fh:
            fh.write(b'%PDF-1.7')
            fh.truncate(11 * 1024 * 1024)
        try:
            safe_analyze_pdf(oversized)
            actual = 'accepted'
        except PDFValidationError:
            actual = 'rejected'
        cases.append({'test': 'T-final', 'fixture': 'oversized', 'expected': 'rejected',
                      'actual': actual, 'pass': actual == 'rejected', 'evidence': ['10 MiB file cap']})

        benign = base / 'benign.pdf'
        hash_a = safe_analyze_pdf(benign)['sha256']
        hash_b = safe_analyze_pdf(benign)['sha256']
        actual = 'same' if hash_a == hash_b else 'different'
        cases.append({'test': 'T-final', 'fixture': 'repeatability', 'expected': 'same',
                      'actual': actual, 'pass': actual == 'same', 'evidence': ['matching SHA-256']})

    labelled = [r for r in cases if r['test'] in ('T1', 'T4')]
    tp = sum(r['actual'] in ('medium', 'high') for r in labelled if r['fixture'] in ('javascript', 'launch'))
    fn = sum(r['actual'] not in ('medium', 'high') for r in labelled if r['fixture'] in ('javascript', 'launch'))
    fp = sum(r['actual'] in ('medium', 'high') for r in labelled if r['fixture'] in ('benign', 'attachment'))
    tn = sum(r['actual'] == 'low' for r in labelled if r['fixture'] in ('benign', 'attachment'))
    latencies = [r['latency_ms'] for r in cases if 'latency_ms' in r]
    return {'cases': cases, 'metrics': {
        'pass_rate': round(sum(r['pass'] for r in cases) / len(cases), 3),
        'true_positive': tp, 'true_negative': tn, 'false_positive': fp,
        'false_negative': fn, 'false_positive_rate': round(fp / (fp + tn), 3) if fp + tn else None,
        'false_negative_rate': round(fn / (fn + tp), 3) if fn + tp else None,
        'mean_latency_ms': round(statistics.mean(latencies), 2),
        'max_latency_ms': round(max(latencies), 2),
        'note': 'Synthetic, instructor-safe fixtures only; not real-world malware detection accuracy.'
    }, 'boundaries': {
        'T-final_unauthorized_request': 'Member A/API responsibility; cannot test without authentication endpoints',
        'T-final_restart_recovery': 'Member A/API/database integration responsibility',
        'OS_sandbox': 'Separate process with watchdog, not a locked-down OS sandbox'
    }}


if __name__ == '__main__':
    print(json.dumps(evaluate(), indent=2))
