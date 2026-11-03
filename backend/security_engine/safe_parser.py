"""Process-isolated PDF analysis for Windows/Linux/macOS.

Not a full sandbox. Deploy only against trusted training fixtures unless operating
system sandboxing, filesystem access restrictions and secure staging are added.
No stream decoding is requested by the security engine.
"""
import multiprocessing as mp
import time
from pathlib import Path
import psutil
from backend.security_engine.validation import validate_pdf


class SafeParserError(Exception):
    pass


def _worker(file_path, connection):
    try:
        from backend.security_engine.analyzer import analyze_pdf
        result = analyze_pdf(file_path)
        connection.send(('success', result))
    except Exception:
        try:
            connection.send(('error', 'PDF analysis failed'))
        except (OSError, EOFError, BrokenPipeError):
            pass
    finally:
        connection.close()


def safe_analyze_pdf(file_path, timeout_seconds=10, memory_limit_mb=256):
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not (0 < timeout_seconds <= 60):
        raise ValueError('Timeout must be between 0 and 60 seconds')
    if isinstance(memory_limit_mb, bool) or not isinstance(memory_limit_mb, int) or not (64 <= memory_limit_mb <= 2048):
        raise ValueError('Memory limit must be 64-2048 MB')
    path = Path(file_path)
    validate_pdf(path)
    ctx = mp.get_context('spawn')
    parent, child = ctx.Pipe(duplex=False)
    process = ctx.Process(target=_worker, args=(str(path.resolve()), child))
    process.daemon = True
    try:
        process.start()
        child.close()
        deadline = time.monotonic() + timeout_seconds
        budget = memory_limit_mb * 1024 * 1024
        while time.monotonic() < deadline:
            if parent.poll(0.025):
                try:
                    status, result = parent.recv()
                except (EOFError, OSError):
                    raise SafeParserError('PDF analyzer returned no result') from None
                if status == 'success':
                    return result
                raise SafeParserError('PDF analysis failed')
            if not process.is_alive():
                break
            try:
                worker = psutil.Process(process.pid)
                if worker.memory_info().rss > budget:
                    raise SafeParserError('PDF analysis memory limit exceeded')
            except psutil.NoSuchProcess:
                pass
            except psutil.Error:
                raise SafeParserError('Unable to monitor analysis process') from None
        if parent.poll(0.2):
            try:
                status, result = parent.recv()
            except (EOFError, OSError):
                raise SafeParserError('PDF analyzer returned no result') from None
            if status == 'success':
                return result
            raise SafeParserError('PDF analysis failed')
        if process.is_alive():
            raise SafeParserError('PDF analysis timed out')
        raise SafeParserError('PDF analyzer exited without a result')
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=1)
            if process.is_alive():
                process.kill()
        process.join(timeout=1) if process.pid is not None else None
        parent.close()
        child.close()
