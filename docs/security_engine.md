# PDFGuard — Member B Security Engine (v1.0)

## Scope and handoff
This folder is Member B's independently testable **static triage engine** and safe fixture/evaluation suite. Member A owns authentication, role checks, upload staging, server-side validation enforcement, database and audit persistence; Member C owns dashboard and export. This is not the entire PDFGuard application.

The service entry point for the backend is `safe_analyze_pdf(local_staged_path)`. Do **not** call `analyze_pdf` on untrusted user files directly. Accept **only a server-side staged file path**, not a client-submitted arbitrary path. Assign random opaque upload IDs and keep staged files outside the public web root. Delete them under an approved retention policy. Run the service as a low-privilege OS user with no network access and read-only access to only the input staging directory if a real sandbox is available. The child-process layer is NOT a full sandbox; Windows memory monitoring is best-effort.

## Installed packages and commands
From repository root in Windows PowerShell, with virtual environment active:

```powershell
python -m pip install -r requirements-member-b.txt
python -m pytest -v
python -m tools.evaluate
python -m tools.scan sample.pdf
```

`tools.evaluate` generates five harmless samples in a temporary directory and outputs per-case expected/actual result, evidence, latency and synthetic-corpus confusion counts. It does not download or execute malware. `tools.scan` is for instructor-approved **trusted** PDFs.

## Module purpose
- `validation.py`: basic path/extension/size/PDF header checking; 10 MiB cap. This alone DOES NOT prove valid PDF structure or safe content.
- `metadata.py`: strict PDF parse, page count and bounded/sanitized title and author.
- `indicators.py`: object graph + cross-reference listed object walk. Finds JavaScript action, JS entry, launch action, open action, embedded-file stream, additional actions, rich media and XFA. Findings include structural path evidence. Limits object walk count/depth/findings. Does not intentionally decode stream payloads.
- `risk_score.py`: deterministic rule weights and low/medium/high threshold. Scores are heuristics, not malware probability. Repeated indicator names count only once.
- `analyzer.py`: aggregate hash + metadata + evidence + risk + recommended action. Encrypted PDF => `status=encrypted`, `risk=null`, never call it low-risk.
- `safe_parser.py`: spawned child process, deadline, sampled RSS memory budget and generic safe error on worker failure. **Not a security boundary comparable to a container/VM.**

## Contract
Success example:

```json
{
  "status": "completed",
  "sha256": "<64 hex characters>",
  "metadata": {"status": "completed", "encrypted": false, "pages": 1, "author": "", "title": ""},
  "indicators": [],
  "objects_inspected": 6,
  "risk": {"risk_score": 0, "severity": "low", "reasons": [], "engine_version": "1.0", "thresholds": {"medium": 30, "high": 70}, "rule_weights": {}},
  "explanation": "No configured suspicious indicators detected.",
  "recommended_action": "No rule hit; standard security precautions still apply."
}
```

The example omits full `rule_weights` content for brevity. The actual engine returns all rule weights. Each finding reports `indicator`, `reason` and `location`. Failure is raised as `PDFValidationError`, `ValueError`, or `SafeParserError` and Member A must map these to stable API errors without exposing stack traces. Do not present arbitrary file metadata unescaped in HTML.

## Decisions and caveats
- Risk levels: low = score 0–29, medium = 30–69, high = 70–100.
- Initial weights: `/Launch` 45, `/OpenAction` 25, `/JS` 20, `/JavaScript` 25, `/EmbeddedFile` 20, `/AA` 20, `/RichMedia` 20, `/XFA` 10.
- A benign attachment may create a `/EmbeddedFile` finding but still be low under this policy. An action key alone does **not** prove maliciousness. High score alone also does not prove malware.
- A document can contain unsupported attacks, be parser-specific, or hide content in compressed/object streams. Strict parsing can reject some otherwise viewable PDFs (false positive on structural validation). Any results described as benign are **no hit on configured rules**, not guaranteed safe.
- The engine does not intentionally decompress PDF stream data. The T3 test verifies no explicit `get_data()` call for a safe compressed-stream fixture. However, `pypdf` may internally decompress certain PDF structure types (for example, compressed object streams); the spawned-process RSS/time monitoring reduces resource risk but does NOT guarantee a hard decompression limit. A strong decompression cap requires a parser that offers bounded decoded-stream APIs or a real OS-enforced memory sandbox plus known parser coverage. **Do not claim full T3 decompression enforcement.**
- Process timeout and sampled RSS monitor are best-effort; there is no seccomp/AppContainer/job-object hard limit here. For hostile, real-world PDFs deploy with a real sandbox; real malware should not be collected or run for this project.
- `PdfReader` is used in strict mode; not all PDF features and encodings are covered. Scanning the full cross-reference table can encounter missing or malformed objects and properly fails rather than silently declaring low risk.

## Reproducible evaluation: T1–T5 and T-final
| ID | Case | What is covered / evidence | Current boundary |
|---|---|---|---|
| T1 | benign + instructor-approved synthetic samples | `test_indicators_by_structure`, `tools.evaluate` | Small controlled corpus; not field accuracy |
| T2 | parser failures | `test_corrupt_pdf_rejected`, `test_safe_process_malformed` | Reject with generic error |
| T3 | decompression safety | `test_stream_is_not_decompressed` | Explicit stream non-decoding; **hard decompression cap not demonstrated** |
| T4 | indicator accuracy | `test_indicators_by_structure`, `test_corpus_results` | Heuristic precision/recall on synthetic set only |
| T5 | process handling | `test_safe_process`, `test_safe_process_malformed` | Child process only, no full OS sandbox |
| T-final | oversized, repeated submission, safe failure | `test_oversized_rejected_before_parsing`, `test_repeated_submission_same_fingerprint` | Unauthorized API calls, restart recovery and login require Member A integration |

Recommended remaining integration tests: unauthorized viewer 403, admin-only rule-change 403 for operator, audit append-only, export redaction and success, repeated upload idempotence, CSRF validation, rate limit, restart/recovery. Those belong to shared application, NOT the standalone engine.

## Threats and mitigations (data-flow trust boundary)

```text
[Untrusted browser] -- upload --> [Member A API/auth/role/size checks]
                    TRUST BOUNDARY 1
      [Private staged PDF] --> [Member B spawned scanner]
                    TRUST BOUNDARY 2
      [Normalized JSON evidence] --> [Member A repository/audit]
                    TRUST BOUNDARY 3
      [Member C dashboard/report only to authorized role]
```

| Threat | Mitigation and owner |
|---|---|
| Unauthorized upload or results access | Server-side RBAC, Member A |
| PDF malware executes when viewed | Never render/embed original uploads in browser; static processing only, team |
| Parser infinite loop | Child process timeout, Member B |
| Resource exhaustion via decompression | Avoid decoding payload streams, worker resource observation; **residual pypdf internal risk**, Member B + deployment owner |
| Oversized file/zip bomb-like input | 10 MiB precheck, limited process; residual compression risk, A+B |
| Path traversal/arbitrary file reads | Random private staging filename; user cannot submit filesystem path, Member A |
| Cross-site scripting from PDF metadata | Length cap / remove controls; frontend HTML escaping, B+C |
| Secret leakage through errors/logs | Generic worker failure; logs must redact secrets, A+B |
| Forged audit trail | Append-only transactional audit records, Member A |
| CSRF or session theft | CSRF if cookie auth, secure cookies, expiry, Member A |
| Result tampering or unreproducible decisions | SHA-256, rule version, thresholds, evidence, B+A |
| Maliciously repeated uploads | Rate limits and quotas, Member A |

## Evaluation claims and ethics
The fixture results are generated and measured at runtime, not fixed claims. Cite the test log and JSON evaluation output in the final report. No real exploit code, weaponized PDF or malware is included. Do not upload personal or confidential PDFs into shared repositories. Do not treat automated heuristic triage as a substitute for a professional malware analysis sandbox.

## November 2026 Member B final engineering addendum

- **T3 decompression:** Standard scanner never invokes PDF stream `.get_data()` or executes embedded content. The optional bounded `FlateDecode` utility enforces a strict maximum of 2 MiB decoded output and 100x expansion, rejects incomplete/invalid/trailing streams. Tests include compressed 4 MiB expansion in a tiny fixture, high expansion ratio, truncated and invalid streams. Other PDF filters are intentionally not decoded. This is a deliberately limited supported feature, not universal filter support.
- **T1/T2/T4/T5/T-final:** Run `python -m tools.evaluate` for deterministic benign/adverse synthetic cases with expected/actual and evidence. `python -m pytest -v` tests negative and edge cases. Use SHA-256 + rule IDs to reproduce results.
- **Threats / mitigations (Member B engine):** invalid PDF type => extension/signature gate; oversized upload => file limit; malicious structure => static rule detection; decompression bomb => no stream decoding and bounded optional decoder; parser hang => child-process timeout; memory blowup => watched RSS plus child termination (not a hard quota); deep recursion => object depth/count cap; hidden suspicious objects => xref inspection; encrypted samples => unknown status/manual review; disclosure via parser errors => generic caller-facing exceptions. Full OS sandboxing, authorization, CSRF, audit trail, upload quarantine, secret controls and server-side rate limits belong to the integrated application and must be verified by the team.
- **Scope boundary:** The engine's tests **do not** prove effective Windows sandboxing or enforce hard memory or CPU quotas. Use a restricted user or VM for untrusted PDFs. Never claim a low-risk score proves a document safe.
