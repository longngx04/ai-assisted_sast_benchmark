"""Deterministic candidate discovery engine for SAST benchmark.

Micro-tasks 3.1, 3.2, 3.3:
  * 3.1: Rule-based detection of security-sensitive source/sink patterns across 15 categories.
  * 3.2: Early rejection and prioritization heuristic (filtering constants, parameterized queries, sanitizers).
  * 3.3: Export to JSONL format (results/<experiment-id>/candidates.jsonl).

Purely deterministic execution (no LLM calls). Uses regex patterns, symbol index data,
and exclusion policies.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from harness.exclusions import ExclusionPolicy
from harness.indexer import JavaIndexer, JavaSymbolIndex


# ---------------------------------------------------------------------------
# Candidate Data Model
# ---------------------------------------------------------------------------

@dataclass
class Candidate:
    """A deterministic vulnerability candidate."""
    candidate_id: str
    category: str
    file: str
    line: int
    symbol: str | None
    matched_rule: str
    snippet: str
    context_refs: list[str] = field(default_factory=list)
    priority: str = "medium"  # high | medium | low
    is_rejected: bool = False
    rejection_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Candidate Finder Rules & Patterns (Micro-task 3.1)
# ---------------------------------------------------------------------------

@dataclass
class FindingRule:
    rule_id: str
    category: str
    pattern: re.Pattern[str]
    description: str
    default_priority: str = "medium"
    file_suffixes: tuple[str, ...] = (".java",)


# 15 Categories of security rules
_RULES: list[FindingRule] = [
    # 1. SQL Injection / Database
    FindingRule(
        rule_id="sqli_string_concat",
        category="database",
        pattern=re.compile(r'(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^\n\r]*?\+[\s\n]*?\w+', re.IGNORECASE),
        description="String concatenation inside SQL query string",
        default_priority="high",
    ),
    FindingRule(
        rule_id="sqli_statement_execute",
        category="database",
        pattern=re.compile(r'\b(Statement|createNativeQuery)\s*\.\s*(executeQuery|executeUpdate|execute)\b'),
        description="Execution of raw SQL statement or native query",
        default_priority="high",
    ),
    # 2. XSS / Output Encoding
    FindingRule(
        rule_id="xss_raw_write",
        category="html_template",
        pattern=re.compile(r'\b(response|writer|out)\s*\.\s*(print|println|write|append)\s*\([^\)]*?\w+'),
        description="Direct write of unencoded variable to response stream",
        default_priority="medium",
    ),
    FindingRule(
        rule_id="xss_thymeleaf_unescaped",
        category="html_template",
        pattern=re.compile(r'th:utext\s*='),
        description="Thymeleaf unescaped text attribute (th:utext)",
        default_priority="high",
    ),
    FindingRule(
        rule_id="xss_dom_sink",
        category="html_template",
        pattern=re.compile(r'\b(innerHTML|outerHTML|document\.write|eval)\s*(=|\()'),
        description="DOM HTML or code execution sink in client-side source",
        default_priority="high",
        file_suffixes=(".js", ".mjs", ".html", ".htm"),
    ),
    FindingRule(
        rule_id="xss_unescaped_template",
        category="html_template",
        pattern=re.compile(r'(?:v-html\s*=|\{\{\{[^}]+\}\}\}|<%=)'),
        description="Unescaped template output in HTML source",
        default_priority="high",
        file_suffixes=(".html", ".htm", ".js", ".mjs"),
    ),
    # 3. Command Execution
    FindingRule(
        rule_id="cmd_runtime_exec",
        category="command_execution",
        pattern=re.compile(r'\b(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\b'),
        description="OS process or shell command execution",
        default_priority="high",
    ),
    # 4. Path Traversal & File Handling
    FindingRule(
        rule_id="file_path_traversal",
        category="file_handling",
        pattern=re.compile(r'\bnew\s+(File|FileInputStream|FileOutputStream|FileReader|FileWriter|Path)\s*\([^\)]*?\+'),
        description="File path constructed with string concatenation",
        default_priority="high",
    ),
    FindingRule(
        rule_id="file_zip_slip",
        category="file_handling",
        pattern=re.compile(r'\b(ZipEntry|TarArchiveEntry)\s*\.\s*getName\b'),
        description="Zip archive entry extraction without path validation",
        default_priority="medium",
    ),
    # 5. XML External Entity (XXE)
    FindingRule(
        rule_id="xml_xxe_parser",
        category="xml_parsing",
        pattern=re.compile(r'\b(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\s*\.\s*newInstance\b'),
        description="XML parser factory instantiation (check for disabled DTDs)",
        default_priority="medium",
    ),
    # 6. Deserialization
    FindingRule(
        rule_id="deserialization_unsafe",
        category="deserialization",
        pattern=re.compile(r'\b(ObjectInputStream\s*\.\s*readObject|XMLDecoder|XStream\s*\.\s*fromXML)\b'),
        description="Unsafe object deserialization sink",
        default_priority="critical",
    ),
    # 7. SSRF / HTTP Client
    FindingRule(
        rule_id="ssrf_http_connection",
        category="http_client",
        pattern=re.compile(r'\b(URL\s*\.\s*openStream|HttpURLConnection|RestTemplate|WebClient)\b'),
        description="Outbound HTTP client connection",
        default_priority="medium",
    ),
    # 8. Open Redirect
    FindingRule(
        rule_id="redirect_open",
        category="redirect",
        pattern=re.compile(r'\b(sendRedirect|RedirectView|redirect:)\b'),
        description="HTTP response redirect",
        default_priority="medium",
    ),
    # 9. Authentication
    FindingRule(
        rule_id="auth_custom_check",
        category="authentication",
        pattern=re.compile(r'\b(UserDetailsService|PasswordEncoder|AuthenticationManager)\b'),
        description="Authentication service or manager reference",
        default_priority="low",
    ),
    # 10. Authorization & Access Control
    FindingRule(
        rule_id="access_control_annotation",
        category="authorization",
        pattern=re.compile(r'@(PreAuthorize|Secured|RolesAllowed)\b'),
        description="Method-level authorization check annotation",
        default_priority="low",
    ),
    # 11. Session & CSRF
    FindingRule(
        rule_id="session_cookie_handling",
        category="session",
        pattern=re.compile(r'\b(HttpSession|Cookie|csrf)\b'),
        description="Session, cookie, or CSRF management reference",
        default_priority="low",
    ),
    # 12. Weak Cryptography
    FindingRule(
        rule_id="crypto_weak_algorithm",
        category="cryptography",
        pattern=re.compile(r'MessageDigest\.getInstance\s*\(\s*"MD5"|"SHA-1"\s*\)|Cipher\.getInstance\s*\(\s*"DES"|"RC4"\s*\)', re.IGNORECASE),
        description="Use of weak cryptographic hash or cipher algorithm (MD5, SHA-1, DES)",
        default_priority="high",
    ),
    # 13. Hardcoded Secret
    FindingRule(
        rule_id="crypto_hardcoded_secret",
        category="cryptography",
        pattern=re.compile(r'(password|secret|apiKey|privateKey)\s*=\s*"[^"]{4,}"', re.IGNORECASE),
        description="Hardcoded password or secret key string literal",
        default_priority="high",
    ),
    # 14. Sensitive Data Logging
    FindingRule(
        rule_id="logging_sensitive",
        category="logging_sensitive",
        pattern=re.compile(r'\blog\s*\.\s*(info|debug|error|warn)\s*\([^\)]*?(password|token|secret|credit)', re.IGNORECASE),
        description="Logging sensitive credential or user token",
        default_priority="medium",
    ),
    # 15. Unsafe Reflection
    FindingRule(
        rule_id="reflection_unsafe",
        category="reflection",
        pattern=re.compile(r'\b(Class\.forName|Method\.invoke|Field\.set|Constructor\.newInstance)\b'),
        description="Reflection or dynamic class loading",
        default_priority="medium",
    ),
    FindingRule(
        rule_id="xml_external_entity",
        category="xml_parsing",
        pattern=re.compile(r'<!DOCTYPE[^>]*(?:SYSTEM|PUBLIC)|external-general-entities', re.IGNORECASE),
        description="XML source enables or declares external entity processing",
        default_priority="high",
        file_suffixes=(".xml", ".xhtml", ".html"),
    ),
    FindingRule(
        rule_id="config_hardcoded_secret",
        category="cryptography",
        pattern=re.compile(r'(?i)(?:password|secret|api[_-]?key|private[_-]?key)\s*[:=]\s*[^${}\s][^\s#]+'),
        description="Potential hardcoded secret in configuration source",
        default_priority="high",
        file_suffixes=(".properties", ".yml", ".yaml", ".xml"),
    ),
]


# ---------------------------------------------------------------------------
# Early Rejection & Prefilter Rules (Micro-task 3.2)
# ---------------------------------------------------------------------------

_PARAMETERIZED_QUERY_RE = re.compile(r'\?|\:[\w]+|\bPreparedStatement\b|\bJdbcTemplate\b')
_SANITIZER_RE = re.compile(r'\b(htmlEscape|clean|encode|sanitize|safePath|normalize|validate|ESAPI)\b', re.IGNORECASE)
_CONSTANT_ONLY_RE = re.compile(r'^\s*["\'][^"\']*["\']\s*$')


class CandidateFinder:
    """Discovers security candidates deterministically over Java source files.

    Parameters
    ----------
    webgoat_root : str | Path
        Path to WebGoat source root.
    index : JavaSymbolIndex | None
        Optional symbol index from Task 2.2.
    exclusion_policy : ExclusionPolicy | None
        Exclusion policy for build/generated paths.
    """

    def __init__(
        self,
        webgoat_root: str | Path,
        index: JavaSymbolIndex | None = None,
        exclusion_policy: ExclusionPolicy | None = None,
    ) -> None:
        self.root = Path(webgoat_root).resolve()
        self.index = index
        self.policy = exclusion_policy
        self._candidates: list[Candidate] = []

    def scan(self) -> list[Candidate]:
        """Run candidate discovery across supported non-excluded source files."""
        self._candidates = []
        source_files = self._collect_source_files()
        
        cand_counter = 1
        for fpath in source_files:
            rel_file = str(fpath.relative_to(self.root)).replace(os.sep, "/")
            lines = self._read_file(fpath)

            for lineno, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("//") or stripped.startswith("*"):
                    continue

                for rule in _RULES:
                    if not fpath.name.lower().endswith(rule.file_suffixes):
                        continue
                    m = rule.pattern.search(line)
                    if not m:
                        continue

                    cand_id = f"CAND-WG-{cand_counter:04d}"
                    cand_counter += 1

                    symbol = self._resolve_symbol(rel_file, lineno)

                    candidate = Candidate(
                        candidate_id=cand_id,
                        category=rule.category,
                        file=rel_file,
                        line=lineno,
                        symbol=symbol,
                        matched_rule=rule.rule_id,
                        snippet=stripped,
                        context_refs=[f"{rel_file}:{lineno}"],
                        priority=rule.default_priority,
                    )

                    # Apply Early Rejection / Prefilter Heuristics (Task 3.2)
                    self._apply_early_rejection(candidate, line, lines, lineno)

                    self._candidates.append(candidate)

        return self._candidates

    def _collect_source_files(self) -> list[Path]:
        files: list[Path] = []
        supported_suffixes = {suffix for rule in _RULES for suffix in rule.file_suffixes}
        for dirpath, _dirnames, filenames in os.walk(self.root):
            for fname in filenames:
                if not fname.lower().endswith(tuple(supported_suffixes)):
                    continue
                abs_p = Path(dirpath) / fname
                rel_p = str(abs_p.relative_to(self.root)).replace(os.sep, "/")
                if self.policy and self.policy.should_exclude(rel_p):
                    continue
                files.append(abs_p)
        return sorted(files)

    def _read_file(self, path: Path) -> list[str]:
        try:
            return path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []

    def _resolve_symbol(self, file: str, line: int) -> str | None:
        if self.index is None:
            return None
        m = JavaIndexer.get_method_at_line(self.index, file, line)
        if m:
            return m.name
        c = JavaIndexer.get_class_at_line(self.index, file, line)
        if c:
            return c.name
        return None

    def _apply_early_rejection(
        self,
        cand: Candidate,
        line: str,
        lines: list[str],
        lineno: int,
    ) -> None:
        """Task 3.2: Early rejection and priority adjustment heuristics."""
        # 1. Parameterized Query check for SQLi
        if cand.category == "database" and cand.matched_rule == "sqli_string_concat":
            if _PARAMETERIZED_QUERY_RE.search(line):
                cand.priority = "low"
                cand.is_rejected = True
                cand.rejection_reason = "Query appears parameterized or uses PreparedStatement/JdbcTemplate"
                return

        # 2. Explicit Sanitizer check
        if _SANITIZER_RE.search(line):
            cand.priority = "low"
            cand.is_rejected = True
            cand.rejection_reason = "Sanitizer or encoding function detected on line"
            return

        # 3. Check for Constant-only arguments
        args_match = re.search(r'\(([^)]+)\)', line)
        if args_match and _CONSTANT_ONLY_RE.match(args_match.group(1)):
            cand.priority = "low"
            cand.is_rejected = True
            cand.rejection_reason = "Argument appears to be a constant string literal"
            return

        # 4. Surroundings check: method authorization annotation
        if self.index:
            m = JavaIndexer.get_method_at_line(self.index, cand.file, lineno)
            if m:
                ann_names = [a.name for a in m.annotations]
                if "PreAuthorize" in ann_names or "Secured" in ann_names:
                    if cand.category in ("authorization", "authentication"):
                        cand.priority = "low"
                        cand.is_rejected = True
                        cand.rejection_reason = "Authorization annotation explicitly present on method"


# ---------------------------------------------------------------------------
# CLI & Conveniences (Micro-task 3.3)
# ---------------------------------------------------------------------------

def run_candidate_discovery(
    webgoat_root: str | Path,
    output_dir: str | Path,
    experiment_id: str = "exp-d-optimized",
    index_file: str | Path | None = None,
    exclusion_config: str | Path | None = None,
) -> Path:
    """Run candidate discovery and export candidates.jsonl."""
    policy = None
    if exclusion_config and os.path.exists(exclusion_config):
        policy = ExclusionPolicy.from_file(Path(exclusion_config))

    index = None
    if index_file and os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            index = JavaIndexer.load_index(json.load(f))

    finder = CandidateFinder(webgoat_root, index=index, exclusion_policy=policy)
    candidates = finder.scan()

    out_dir = Path(output_dir) / experiment_id
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "candidates.jsonl"

    lines = [json.dumps(c.to_dict(), ensure_ascii=False) for c in candidates]
    out_file.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    return out_file


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Deterministic Candidate Discovery (Phase 3)")
    parser.add_argument("--source", "-s", default="webgoat/WebGoat-2025.3", help="WebGoat root")
    parser.add_argument("--output", "-o", default="results", help="Output root directory")
    parser.add_argument("--experiment-id", "-e", default="exp-d-optimized", help="Experiment ID")
    parser.add_argument("--index", "-i", default="results/symbol_index.json", help="Path to symbol index")
    parser.add_argument("--exclusions", default="configs/exclusions.json", help="Exclusion policy JSON")

    args = parser.parse_args()
    out_path = run_candidate_discovery(
        webgoat_root=args.source,
        output_dir=args.output,
        experiment_id=args.experiment_id,
        index_file=args.index,
        exclusion_config=args.exclusions,
    )
    print(f"Candidates written to {out_path}")
