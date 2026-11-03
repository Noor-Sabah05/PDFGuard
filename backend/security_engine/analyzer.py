"""Single deterministic analysis response for backend integration."""
from pathlib import Path
from hashlib import sha256
from backend.security_engine.validation import validate_pdf
from backend.security_engine.metadata import extract_metadata
from backend.security_engine.indicators import detect_indicators
from backend.security_engine.risk_score import calculate_risk


def analyze_pdf(file_path):
    path = Path(file_path)
    validate_pdf(path)
    metadata = extract_metadata(path)
    # bounded 10 MB by validate_pdf; hash in chunks for predictable allocations
    digest = sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(65536), b''):
            digest.update(block)
    if metadata['status'] == 'encrypted':
        return {'status': 'encrypted', 'sha256': digest.hexdigest(), 'metadata': metadata, 'indicators': [], 'risk': None, 'explanation': 'Encrypted PDF: content analysis was not completed.', 'recommended_action': 'Manual review; do not treat as safe.'}
    scan = detect_indicators(path)
    risk = calculate_risk(scan['indicators'])
    if scan['indicators']:
        explanation = 'Configured suspicious structures detected; review listed evidence.'
    else:
        explanation = 'No configured suspicious indicators detected.'
    recommendation = 'Escalate for manual review.' if risk['severity'] == 'high' else ('Review before release.' if risk['severity'] == 'medium' else 'No rule hit; standard security precautions still apply.')
    return {'status': 'completed', 'sha256': digest.hexdigest(), 'metadata': metadata, 'indicators': scan['indicators'], 'objects_inspected': scan['objects_inspected'], 'risk': risk, 'explanation': explanation, 'recommended_action': recommendation}
