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

def record_llm_result(results, test_put_path, llm_result, provider, error=None):
    """Preserve each stage's results; the caller holds the results lock.

    ``safe_files`` is the legacy group for files without a confirmed finding,
    including incomplete tests. It does not establish that those files are safe.
    """
    original = results["safe_files"][test_put_path]
    standard_result = copy.deepcopy(original.get("standard_result", original))
    standard_count = standard_result.get("test_count", 0)
    llm_data = llm_result or {}
    generated = llm_data.get("custom_payloads_generated", 0)
    tested = llm_data.get("custom_payloads_tested", 0)
    llm_error = str(error) if error is not None else llm_data.get("error")
    if llm_result is None and llm_error is None:
        llm_error = "LLM returned no result"

    found = bool(llm_data.get("vulnerability_found"))
    if found:
        status = "vulnerable"
        note = "Vulnerability found by LLM"
    elif llm_error:
        status = "error"
        note = "LLM testing failed; result is inconclusive"
    elif tested == 0:
        status = "not_tested"
        note = "LLM did not test any payload; result is inconclusive"
    else:
        status = "no_vulnerability_found"
        note = "LLM testing completed; no vulnerability found"

    details = {
        "provider": provider,
        "status": status,
        "payloads_generated": generated,
        "payloads_tested": tested,
        "standard_test_count": standard_count,
    }
    if llm_error:
        details["error"] = llm_error
    failed_response = llm_data.get("failed_response")
    if status == "error" and failed_response is not None:
        details["failed_response"] = failed_response
        logger.warning(
            "[LLM] Detection failed for %r. Error=%r Response=%r",
            test_put_path, llm_error, failed_response,
        )
    entry = {
        "test_count": standard_count + tested,
        "standard_result": standard_result,
        "note": note,
        "llm_tested": tested > 0,
        "llm_details": details,
    }
    if found:
        entry.update(status="vulnerable", method="llm_enhanced",
                     payload=llm_data.get("successful_payload"))
        del results["safe_files"][test_put_path]
        results["vulnerable_files"][test_put_path] = entry
    else:
        inconclusive = llm_error or tested == 0 or standard_result.get("error")
        entry["status"] = "inconclusive" if inconclusive else "not_detected"
        if llm_error or standard_result.get("error"):
            entry["error"] = llm_error or standard_result["error"]
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
