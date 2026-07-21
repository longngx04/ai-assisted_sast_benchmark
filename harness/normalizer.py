"""Normalization rules for converting raw model output into canonical Findings.

Micro-task 1.2 contract
-----------------------
* File paths are relative to ``WEBGOAT_ROOT``.
* Line numbers are positive integers or ``None``.
* Confidence is clamped to ``[0, 1]``.
* Missing optional *string* fields  → ``None``.
* Missing required *string* fields  → ``""`` (empty string).
* Missing ``data_flow``             → ``[]``.
* Missing numeric fields            → ``None``.
* Finding ID is generated deterministically from
  (experiment_id, file, start_line, cwe, normalized vulnerability_type).
* Raw evidence is never discarded; it is passed through as-is.
"""

from __future__ import annotations

import hashlib
import os
import re
from typing import Any

from harness.schemas import Finding, Severity, ValidationStatus


# ---------------------------------------------------------------------------
# Severity aliases → canonical value
# ---------------------------------------------------------------------------

_SEVERITY_ALIASES: dict[str, Severity] = {
    # canonical
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFORMATIONAL,
    # common alternatives
    "crit": Severity.CRITICAL,
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "warn": Severity.MEDIUM,
    "note": Severity.LOW,
    "info": Severity.INFORMATIONAL,
    "none": Severity.INFORMATIONAL,
}


# ---------------------------------------------------------------------------
# CWE normalization
# ---------------------------------------------------------------------------

_CWE_RE = re.compile(r"(?:CWE-?)?(\d+)", re.IGNORECASE)


def normalize_cwe(raw: Any) -> str | None:
    """Return ``'CWE-<number>'`` or ``None``.

    Accepts inputs like ``'CWE-89'``, ``'cwe89'``, ``'89'``, ``89``.
    """
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    m = _CWE_RE.search(text)
    if m is None:
        return None
    return f"CWE-{m.group(1)}"


# ---------------------------------------------------------------------------
# Path normalization
# ---------------------------------------------------------------------------

def normalize_path(raw_path: str, webgoat_root: str) -> str:
    """Return *raw_path* relative to *webgoat_root*.

    * Strips leading ``./`` and duplicate separators.
    * Resolves ``..`` segments.
    * Uses forward-slash as separator (for cross-platform JSONL portability).
    * If the path is already relative and does not escape *webgoat_root*,
      it is returned as-is after cleanup.
    """
    if not raw_path:
        return raw_path

    # Normalise the root once (resolve symlinks + trailing separator).
    root = os.path.normpath(os.path.abspath(webgoat_root))

    # If the raw path is absolute, make it relative.
    norm = os.path.normpath(raw_path)
    if os.path.isabs(norm):
        try:
            norm = os.path.relpath(norm, root)
        except ValueError:
            # On Windows different drive letters can cause ValueError.
            pass
    else:
        # Even a relative path may contain a ``webgoat_root`` prefix when the
        # model spits out e.g. ``webgoat/WebGoat-2025.3/src/…``.
        # Try stripping the root prefix if it appears.
        abs_candidate = os.path.normpath(os.path.join(root, norm))
        if abs_candidate.startswith(root + os.sep) or abs_candidate == root:
            norm = os.path.relpath(abs_candidate, root)

    # Use forward slashes for portability.
    return norm.replace(os.sep, "/")


# ---------------------------------------------------------------------------
# Deterministic finding ID
# ---------------------------------------------------------------------------

def generate_finding_id(
    experiment_id: str,
    file: str,
    start_line: int | None,
    cwe: str | None,
    vulnerability_type: str,
) -> str:
    """Generate a deterministic, collision-resistant finding ID.

    The ID is built from a stable hash of the five key fields so that the
    same vulnerability discovered in the same experiment always receives the
    same identifier — even across re-runs.

    Format: ``WG-<8-hex-chars>``
    """
    parts = [
        experiment_id,
        file,
        str(start_line) if start_line is not None else "null",
        cwe or "null",
        vulnerability_type.strip().lower(),
    ]
    digest = hashlib.sha256("|".join(parts).encode()).hexdigest()[:8]
    return f"WG-{digest}"


# ---------------------------------------------------------------------------
# Confidence clamping
# ---------------------------------------------------------------------------

def normalize_confidence(raw: Any) -> float:
    """Clamp *raw* into ``[0.0, 1.0]``.

    Non-numeric values become ``0.0`` (lowest confidence).
    """
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, value))


# ---------------------------------------------------------------------------
# Severity normalization
# ---------------------------------------------------------------------------

def normalize_severity(raw: Any) -> Severity:
    """Map free-form severity strings to the canonical enum.

    Falls back to ``Severity.MEDIUM`` for unrecognised values.
    """
    if isinstance(raw, Severity):
        return raw
    key = str(raw).strip().lower()
    return _SEVERITY_ALIASES.get(key, Severity.MEDIUM)


# ---------------------------------------------------------------------------
# Validation status normalization
# ---------------------------------------------------------------------------

def normalize_validation_status(raw: Any) -> ValidationStatus:
    """Map free-form status strings to the canonical enum.

    Falls back to ``ValidationStatus.UNVALIDATED`` for unrecognised values.
    """
    if isinstance(raw, ValidationStatus):
        return raw
    key = str(raw).strip().lower()
    try:
        return ValidationStatus(key)
    except ValueError:
        return ValidationStatus.UNVALIDATED


# ---------------------------------------------------------------------------
# Line number normalization
# ---------------------------------------------------------------------------

def normalize_line(raw: Any) -> int | None:
    """Return a positive ``int`` or ``None``.

    Accepts string or float representations.  Zero and negative values
    become ``None``.
    """
    if raw is None:
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    return value if value >= 1 else None


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def normalize_raw_finding(
    raw: dict[str, Any],
    *,
    experiment_id: str,
    webgoat_root: str,
    tool: str = "custom-harness",
    harness_version: str = "v1",
    model: str = "gemini-2.5-flash",
    prompt_version: str = "unknown",
) -> Finding:
    """Convert a raw (potentially messy) dict into a validated ``Finding``.

    This is the single entry point that downstream pipeline stages should use
    after receiving model output.  It applies every normalization rule defined
    in micro-task 1.2 and delegates final validation to ``Finding.__post_init__``.

    Parameters
    ----------
    raw:
        Raw dict parsed from model JSON output.
    experiment_id:
        Current experiment identifier (injected, not from the raw dict).
    webgoat_root:
        Absolute path to the WebGoat source root on disk.
    tool / harness_version / model / prompt_version:
        Pipeline metadata.  Values present in *raw* take precedence.
    """

    # -- nullable string fields: missing → None --------------------------------
    _nullable_strings = (
        "cwe", "function", "source", "sink", "security_control",
        "validator", "duplicate_of",
    )
    # -- required string fields: missing → "" ----------------------------------
    _required_strings = (
        "vulnerability_type", "description", "evidence",
        "attack_scenario", "recommendation", "notes",
    )

    def _str_or(key: str, default: Any) -> Any:
        v = raw.get(key, default)
        if v is None:
            return default
        return str(v) if not isinstance(v, str) else v

    # Nullable strings
    nullable: dict[str, str | None] = {}
    for key in _nullable_strings:
        v = raw.get(key)
        nullable[key] = str(v) if v is not None and not isinstance(v, str) else v

    # Required strings (never None; fallback to empty string)
    required: dict[str, str] = {}
    for key in _required_strings:
        v = raw.get(key)
        if v is None or (isinstance(v, str) and v == ""):
            required[key] = ""
        else:
            required[key] = str(v)

    # -- CWE -------------------------------------------------------------------
    cwe = normalize_cwe(nullable.get("cwe", raw.get("cwe")))

    # -- file path -------------------------------------------------------------
    file_path = normalize_path(_str_or("file", ""), webgoat_root)

    # -- line numbers ----------------------------------------------------------
    start_line = normalize_line(raw.get("start_line"))
    end_line = normalize_line(raw.get("end_line"))
    # Fix inverted range
    if start_line is not None and end_line is not None and end_line < start_line:
        start_line, end_line = end_line, start_line

    # -- severity & confidence -------------------------------------------------
    severity = normalize_severity(raw.get("severity"))
    confidence = normalize_confidence(raw.get("confidence"))

    # -- validation status -----------------------------------------------------
    validation_status = normalize_validation_status(
        raw.get("validation_status", "unvalidated")
    )
    validator_confidence_raw = raw.get("validator_confidence")
    validator_confidence: float | None = None
    if validator_confidence_raw is not None:
        validator_confidence = normalize_confidence(validator_confidence_raw)

    # -- data flow (list of strings; missing → []) -----------------------------
    data_flow_raw = raw.get("data_flow")
    if isinstance(data_flow_raw, list):
        data_flow = [str(s) for s in data_flow_raw]
    elif isinstance(data_flow_raw, str) and data_flow_raw:
        data_flow = [data_flow_raw]
    else:
        data_flow = []

    # -- vulnerability_type normalisation (strip, title-case) ------------------
    vuln_type = required.get("vulnerability_type", "").strip()

    # -- deterministic finding ID ---------------------------------------------
    finding_id = raw.get("finding_id") or generate_finding_id(
        experiment_id=experiment_id,
        file=file_path,
        start_line=start_line,
        cwe=cwe,
        vulnerability_type=vuln_type,
    )

    # -- pipeline metadata (raw values override defaults) ----------------------
    exp_id = raw.get("experiment_id") or experiment_id
    tool_val = raw.get("tool") or tool
    hv = raw.get("harness_version") or harness_version
    model_val = raw.get("model") or model
    pv = raw.get("prompt_version") or prompt_version

    return Finding(
        finding_id=finding_id,
        experiment_id=exp_id,
        tool=tool_val,
        harness_version=hv,
        model=model_val,
        prompt_version=pv,
        vulnerability_type=vuln_type,
        cwe=cwe,
        severity=severity,
        confidence=confidence,
        file=file_path,
        start_line=start_line,
        end_line=end_line,
        function=nullable.get("function"),
        source=nullable.get("source"),
        sink=nullable.get("sink"),
        data_flow=data_flow,
        description=required.get("description", ""),
        evidence=required.get("evidence", ""),
        attack_scenario=required.get("attack_scenario", ""),
        security_control=nullable.get("security_control"),
        recommendation=required.get("recommendation", ""),
        validation_status=validation_status,
        validator=nullable.get("validator"),
        validator_confidence=validator_confidence,
        duplicate_of=nullable.get("duplicate_of"),
        notes=required.get("notes", ""),
    )
