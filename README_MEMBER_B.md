# PDFGuard — Member B: security engine and evaluation

This folder is a **drop-in Member B module** for your existing Git clone.
Do not extract over `.git`, `.venv`, `LICENSE` or team-managed files.

## One-step setup (Windows / VS Code)
1. Extract ZIP anywhere (e.g. Downloads).
2. Right-click the extracted folder and **Open in Terminal** (PowerShell).
3. Run: `powershell -ExecutionPolicy Bypass -File .\INSTALL_MEMBER_B.ps1`
4. Installer copies only Member B files, installs dependencies, runs all tests and prints a repeatable evaluation. It **does not commit/push**.
5. Run on branch `sehrish/security-engine` inside your existing Git repo.

## Function interface for Member A
```python
from backend.security_engine.safe_parser import safe_analyze_pdf
result = safe_analyze_pdf(validated_local_pdf_path)
```
Return includes metadata, SHA-256, indicator evidence, explainable score, rules and recommendations. Encrypted PDFs return `status='encrypted'`, risk `None` (not falsely rated low). Invalid inputs throw safe generic exceptions.

## Security boundaries
- Scanner performs **static** object inspection; no JavaScript execution, application launches or PDF viewer opening.
- Basic 10 MiB upload-size guard, PDF header/version check, strict parser, object/depth/finding limits; no PDF stream body decode in normal scanner.
- Separate child process with timeout and best-effort RSS memory monitoring. This is **not an OS sandbox**, and memory observation is not a hard kernel quota.
- Optional decoder `bounded_flate_decode` has 2 MiB decompressed-output cap and 100x expansion ratio cap, with T3 tests. No unbounded decoded-stream extraction in the scanner.
- This module does **not implement server roles, authorization, auditing, CSRF, upload storage or report exports**. Member A/C must integrate those.
- The included evaluation measures a small *synthetic* corpus and does **not** establish real-world malware detection accuracy or universal PDF parsing safety.

## Run separately
```powershell
python -m pytest -v
python -m tools.evaluate
```

## Acceptance evidence
Evaluation includes benign, JavaScript/Launch structural markers, safe attachment, encrypted PDF, malformed parser, a synthetic compression bomb, invalid extension, oversized file, and repeatability. Reports expected/actual, pass/fail, evidence and measured analysis latency. See `docs/security_engine.md` for threat boundaries.
