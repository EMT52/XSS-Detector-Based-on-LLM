import os
import json
import copy
import logging
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

logger = logging.getLogger(__name__)

def print_nested_dict(d, indent=0, file=None):
    if file is None:
        raise ValueError("File is None")
    for key in sorted(d.keys()):
        value = d[key]
        output_line = '  ' * indent + str(key) + '\n'
        file.write(output_line)
        if isinstance(value, dict):
            print_nested_dict(value, indent + 1, file)
        else:
            output_line = '  ' * (indent + 1) + str(value) + '\n'
            file.write(output_line)

def _format_put_result(original, found):
    """Format current and legacy records with one conclusion and per-stage errors."""
    standard = original.get("standard_result", original)
    standard_result = {"test_count": standard.get("test_count", 0)}
    standard_error = standard.get("error")
    if str(standard.get("note", "")).startswith("Could not parse context"):
        standard_error = standard_error or "Could not parse context"
    if not standard_result["test_count"] and not found:
        standard_error = standard_error or "No standard payloads tested"
    if standard_error:
        standard_result["error"] = standard_error

    details = original.get("LLM_result", original.get("llm_details"))
    incomplete = bool(standard_error) or original.get("status") == "inconclusive"
    incomplete = incomplete or original.get("note") == "Testing incomplete"
    llm_count = 0
    if details is not None:
        details = copy.deepcopy(details)
        for key in ("status", "note", "method", "llm_tested", "standard_test_count"):
            details.pop(key, None)
        llm_count = details.get("payloads_tested", 0)
        if not llm_count and not found:
            details["error"] = details.get("error") or "No LLM payloads tested"
        if not found:
            details.setdefault("failed_response", None)
        incomplete = incomplete or bool(details.get("error")) or llm_count == 0

    if found:
        note = "Vulnerability found by standard test"
        if details is not None:
            note = "Vulnerability found by LLM"
    else:
        note = "Testing incomplete" if incomplete else "No vulnerability found"
    entry = {"note": note}
    if found:
        entry["payload"] = copy.deepcopy(original.get("payload"))
    entry["test_count"] = standard_result["test_count"] + llm_count
    entry["standard_result"] = standard_result
    if details is not None:
        entry["LLM_result"] = details
    return entry


def record_llm_result(results, test_put_path, llm_result, provider, error=None):
    """Preserve each stage's results; the caller holds the results lock.

    ``safe_files`` is the legacy group for files without a confirmed finding,
    including incomplete tests. It does not establish that those files are safe.
    """
    original = results["safe_files"][test_put_path]
    standard_result = _format_put_result(original, found=False)["standard_result"]
    llm_data = llm_result or {}
    generated = llm_data.get("custom_payloads_generated", 0)
    tested = llm_data.get("custom_payloads_tested", 0)
    llm_error = llm_data.get("error")
    if error is not None:
        llm_error = f"{type(error).__name__}: {error}"
    if llm_result is None and llm_error is None:
        llm_error = "LLM returned no result"

    found = bool(llm_data.get("vulnerability_found"))
    details = {
        "provider": provider,
        "payloads_generated": generated,
        "payloads_tested": tested,
    }
    if llm_error:
        details["error"] = llm_error
    failed_response = llm_data.get("failed_response")
    if not found:
        details["failed_response"] = failed_response
    if llm_error and not found:
        logger.warning(
            "[LLM] Detection failed for %r. Error=%r Response=%r",
            test_put_path, llm_error, failed_response,
        )
    entry = _format_put_result({
        "standard_result": standard_result,
        "payload": llm_data.get("successful_payload"),
        "LLM_result": details,
    }, found=found)
    if found:
        del results["safe_files"][test_put_path]
        results["vulnerable_files"][test_put_path] = entry
    else:
        results["safe_files"][test_put_path] = entry
    return found

def save_output(results, output_file):
    """Atomically save this run, archiving the previous file without merging it."""
    snapshot = copy.deepcopy(results)
    vulnerable = snapshot.setdefault("vulnerable_files", {})
    unconfirmed = snapshot.setdefault("safe_files", {})
    # A confirmed finding takes precedence if a timed-out task left duplicates.
    for path in vulnerable:
        unconfirmed.pop(path, None)
    classified = set(vulnerable) | set(unconfirmed)
    snapshot["cant_parse_files"] = [
        path for path in dict.fromkeys(snapshot.get("cant_parse_files", []))
        if path not in classified
    ]
    for path, entry in vulnerable.items():
        vulnerable[path] = _format_put_result(entry, found=True)
    for path, entry in unconfirmed.items():
        unconfirmed[path] = _format_put_result(entry, found=False)
    payload = json.dumps(snapshot, indent=4, ensure_ascii=False, allow_nan=False)

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=output_path.parent,
            prefix=f".{output_path.name}.", suffix=".tmp", delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            stream.write(payload + "\n")
            stream.flush()
            os.fsync(stream.fileno())

        if output_path.exists():
            history = output_path.parent / "history"
            history.mkdir(exist_ok=True)
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
            archived = history / f"{output_path.stem}-{timestamp}-{uuid4().hex[:8]}.json"
            shutil.copy2(output_path, archived)
            print(f"[+] Previous results archived: {archived}")

        os.replace(temporary_path, output_path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    print(f"[+] Current run saved: {output_path}")
