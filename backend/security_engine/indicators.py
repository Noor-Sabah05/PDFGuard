"""Static object-structure indicators. Streams are *not* decoded or executed.

All reachable objects and xref-listed indirect objects are considered (within
limits). Unsupported/corrupt structures fail closed, rather than claiming low risk.
"""
from pathlib import Path
from pypdf import PdfReader
from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject
from backend.security_engine.validation import validate_pdf

INDICATORS = {
    '/JavaScript': 'JavaScript action detected',
    '/JS': 'JavaScript entry detected',
    '/Launch': 'External launch action detected',
    '/OpenAction': 'Document-open action detected',
    '/EmbeddedFile': 'Embedded file stream detected',
    '/AA': 'Additional automatic actions present',
    '/RichMedia': 'Rich-media content detected',
    '/XFA': 'XFA form content detected',
}
MAX_OBJECTS = 10000
MAX_DEPTH = 30
MAX_FINDINGS = 2000


def _analyze_reader(reader):
    findings, visited, active = [], set(), set()
    inspected = 0
    seen_finding = set()

    def finding(name, location):
        if len(findings) >= MAX_FINDINGS:
            raise ValueError('PDF finding count limit exceeded')
        k = (name, location)
        if k not in seen_finding:
            seen_finding.add(k)
            findings.append({'indicator': name, 'reason': INDICATORS[name], 'location': location[:300]})

    def inspect(obj, location, depth=0):
        nonlocal inspected
        if depth > MAX_DEPTH:
            raise ValueError('PDF object depth limit exceeded')
        if isinstance(obj, IndirectObject):
            key = (obj.idnum, obj.generation)
            if key in visited:
                return
            visited.add(key)
            obj = obj.get_object()
        # guard against direct cyclic references
        if isinstance(obj, (DictionaryObject, ArrayObject)):
            ident = id(obj)
            if ident in active:
                return
            active.add(ident)
        else:
            ident = None
        try:
            inspected += 1
            if inspected > MAX_OBJECTS:
                raise ValueError('PDF object count limit exceeded')
            if isinstance(obj, DictionaryObject):
                for key, value in obj.items():
                    key_name = str(key)
                    loc = f'{location}/{key_name}'
                    if key_name in INDICATORS:
                        finding(key_name, loc)
                    if key_name == '/S' and str(value) in ('/Launch', '/JavaScript'):
                        finding(str(value), loc)
                    if key_name == '/Type' and str(value) == '/EmbeddedFile':
                        finding('/EmbeddedFile', loc)
                    if isinstance(value, (DictionaryObject, ArrayObject, IndirectObject)):
                        inspect(value, loc, depth + 1)
            elif isinstance(obj, ArrayObject):
                for idx, value in enumerate(obj):
                    if isinstance(value, (DictionaryObject, ArrayObject, IndirectObject)):
                        inspect(value, f'{location}[{idx}]', depth + 1)
        finally:
            if ident is not None:
                active.discard(ident)

    inspect(reader.trailer, 'trailer')
    # Objects may be unreachable from document catalog. Inspect all xref-listed
    # indirect objects for static forensic indicators, within the same bounds.
    for generation, object_map in reader.xref.items():
        for obj_id in object_map:
            if obj_id == 0 or (obj_id, generation) in visited:
                continue
            inspect(IndirectObject(obj_id, generation, reader), f'object[{obj_id}:{generation}]')
    return {'status': 'completed', 'indicators': findings, 'objects_inspected': inspected}


def detect_indicators(file_path):
    path = Path(file_path)
    validate_pdf(path)
    try:
        reader = PdfReader(str(path), strict=True)
        if reader.is_encrypted:
            return {'status': 'encrypted', 'indicators': [], 'objects_inspected': 0}
        return _analyze_reader(reader)
    except ValueError:
        raise
    except Exception:
        raise ValueError('PDF indicator analysis failed') from None
