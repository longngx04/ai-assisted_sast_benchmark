"""Stable data contracts shared by every benchmark experiment."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ValidationStatus(str, Enum):
    UNVALIDATED = "unvalidated"
    VALIDATED = "validated"
    REJECTED = "rejected"
    UNCERTAIN = "uncertain"


class FindingSchemaError(ValueError):
    """Raised when a finding violates the stable harness contract."""


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    experiment_id: str
    tool: str
    harness_version: str
    model: str
    prompt_version: str
    vulnerability_type: str
    cwe: str | None
    severity: Severity
    confidence: float
    file: str
    start_line: int | None
    end_line: int | None
    function: str | None
    source: str | None
    sink: str | None
    data_flow: list[str]
    description: str
    evidence: str
    attack_scenario: str
    security_control: str | None
    recommendation: str
    validation_status: ValidationStatus
    validator: str | None
    validator_confidence: float | None
    duplicate_of: str | None
    notes: str

    def __post_init__(self) -> None:
        if not isinstance(self.severity, Severity):
            raise FindingSchemaError("severity must be a Severity enum value")
        if not isinstance(self.validation_status, ValidationStatus):
            raise FindingSchemaError("validation_status must be a ValidationStatus enum value")
        required_strings = (
            "finding_id", "experiment_id", "tool", "harness_version", "model",
            "prompt_version", "vulnerability_type", "file", "description", "evidence",
            "attack_scenario", "recommendation", "notes",
        )
        nullable_strings = (
            "cwe", "function", "source", "sink", "security_control", "validator", "duplicate_of",
        )
        for name in required_strings:
            if not isinstance(getattr(self, name), str):
                raise FindingSchemaError(f"{name} must be a string")
        for name in nullable_strings:
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise FindingSchemaError(f"{name} must be a string or null")
        self._validate_probability("confidence", self.confidence, nullable=False)
        self._validate_probability("validator_confidence", self.validator_confidence, nullable=True)
        for name in ("start_line", "end_line"):
            value = getattr(self, name)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 1):
                raise FindingSchemaError(f"{name} must be a positive integer or null")
        if self.start_line is not None and self.end_line is not None and self.end_line < self.start_line:
            raise FindingSchemaError("end_line must be greater than or equal to start_line")
        if not isinstance(self.data_flow, list) or any(not isinstance(step, str) for step in self.data_flow):
            raise FindingSchemaError("data_flow must be an array of strings")

    @staticmethod
    def _validate_probability(name: str, value: float | None, *, nullable: bool) -> None:
        if value is None and nullable:
            return
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
            suffix = " or null" if nullable else ""
            raise FindingSchemaError(f"{name} must be a number between 0 and 1{suffix}")

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Finding":
        try:
            values = dict(payload)
            values["severity"] = Severity(values["severity"])
            values["validation_status"] = ValidationStatus(values["validation_status"])
            return cls(**values)
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, FindingSchemaError):
                raise
            raise FindingSchemaError(f"invalid finding payload: {exc}") from exc

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["severity"] = self.severity.value
        payload["validation_status"] = self.validation_status.value
        return payload


class ValidationDecision(str, Enum):
    VALIDATED = "validated"
    REJECTED = "rejected"
    UNCERTAIN = "uncertain"


@dataclass(frozen=True, slots=True)
class ValidationContext:
    """Input payload context provided to an independent validator engine."""
    finding: Finding
    code_context: str
    caller_callee_info: list[str]
    security_assumptions: list[str]
    attack_scenario: str

    def __post_init__(self) -> None:
        if not isinstance(self.finding, Finding):
            raise FindingSchemaError("finding must be a Finding instance")
        if not isinstance(self.code_context, str):
            raise FindingSchemaError("code_context must be a string")
        if not isinstance(self.attack_scenario, str):
            raise FindingSchemaError("attack_scenario must be a string")
        if not isinstance(self.caller_callee_info, list) or any(not isinstance(x, str) for x in self.caller_callee_info):
            raise FindingSchemaError("caller_callee_info must be a list of strings")
        if not isinstance(self.security_assumptions, list) or any(not isinstance(x, str) for x in self.security_assumptions):
            raise FindingSchemaError("security_assumptions must be a list of strings")

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding": self.finding.to_dict(),
            "code_context": self.code_context,
            "caller_callee_info": self.caller_callee_info,
            "security_assumptions": self.security_assumptions,
            "attack_scenario": self.attack_scenario,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ValidationContext":
        try:
            values = dict(payload)
            values["finding"] = Finding.from_dict(values["finding"])
            return cls(**values)
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, FindingSchemaError):
                raise
            raise FindingSchemaError(f"invalid validation context payload: {exc}") from exc


@dataclass(frozen=True, slots=True)
class ValidationResult:
    """Output contract returned by an independent validator engine."""
    status: ValidationDecision
    confidence: float
    reason: str
    missing_evidence: list[str]
    recommended_manual_check: str

    def __post_init__(self) -> None:
        if not isinstance(self.status, ValidationDecision):
            raise FindingSchemaError("status must be a ValidationDecision enum value")
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)) or not 0 <= self.confidence <= 1:
            raise FindingSchemaError("confidence must be a number between 0 and 1")
        if not isinstance(self.reason, str):
            raise FindingSchemaError("reason must be a string")
        if not isinstance(self.recommended_manual_check, str):
            raise FindingSchemaError("recommended_manual_check must be a string")
        if not isinstance(self.missing_evidence, list) or any(not isinstance(x, str) for x in self.missing_evidence):
            raise FindingSchemaError("missing_evidence must be a list of strings")

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "confidence": self.confidence,
            "reason": self.reason,
            "missing_evidence": self.missing_evidence,
            "recommended_manual_check": self.recommended_manual_check,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ValidationResult":
        try:
            values = dict(payload)
            values["status"] = ValidationDecision(values["status"])
            return cls(**values)
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, FindingSchemaError):
                raise
            raise FindingSchemaError(f"invalid validation result payload: {exc}") from exc

    def apply_to_finding(self, finding: Finding, validator_name: str) -> Finding:
        """Apply validator decision and metadata back to update a Finding instance."""
        data = finding.to_dict()
        data["validation_status"] = self.status.value
        data["validator"] = validator_name
        data["validator_confidence"] = self.confidence
        if self.reason:
            existing_notes = data.get("notes", "")
            validator_note = f"[Validator ({validator_name})]: {self.reason}"
            data["notes"] = f"{existing_notes}\n{validator_note}".strip() if existing_notes else validator_note
        return Finding.from_dict(data)

