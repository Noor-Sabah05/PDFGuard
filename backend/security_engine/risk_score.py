"""Explainable, deterministic heuristic scores. Not malware probabilities."""
RULE_WEIGHTS = {
    '/JavaScript': 25, '/JS': 20, '/Launch': 45, '/OpenAction': 25,
    '/EmbeddedFile': 20, '/AA': 20, '/RichMedia': 20, '/XFA': 10,
}
ENGINE_VERSION = '1.0'
THRESHOLDS = {'medium': 30, 'high': 70}


def calculate_risk(indicators):
    if not isinstance(indicators, list):
        raise ValueError('Indicators must be a list')
    score, reasons, seen = 0, [], set()
    for item in indicators:
        if not isinstance(item, dict):
            raise ValueError('Invalid indicator format')
        name = item.get('indicator')
        if not isinstance(name, str):
            raise ValueError('Invalid indicator name')
        if name in seen:
            continue
        seen.add(name)
        weight = RULE_WEIGHTS.get(name, 0)
        if weight:
            score += weight
            reasons.append({'indicator': name, 'rule_id': 'PDF-' + name.lstrip('/').upper(), 'weight': weight, 'explanation': str(item.get('reason') or name)[:200]})
    score = min(score, 100)
    severity = 'high' if score >= THRESHOLDS['high'] else 'medium' if score >= THRESHOLDS['medium'] else 'low'
    return {'risk_score': score, 'severity': severity, 'reasons': reasons, 'engine_version': ENGINE_VERSION, 'thresholds': dict(THRESHOLDS), 'rule_weights': dict(RULE_WEIGHTS)}
