"""Context retrieval for vulnerability candidate analysis.

Micro-task 2.3 — builds a focused context package for each candidate
vulnerability, including:

* function containing the sink
* function containing the source (if identifiable)
* enclosing class code
* nearest caller / callee chain
* endpoint or route information
* relevant configuration snippets
* architecture summary
* related test / fixture code (if found)

The context is bounded by a configurable token/character budget so that
downstream LLM prompts stay within model limits.

Design decisions
----------------
* Uses the JavaSymbolIndex (Task 2.2) for symbol lookup, caller/callee
  traversal, and endpoint resolution.
* Uses ReconnaissanceResult (Task 2.1) for architecture summary and
  security-pattern context.
* Reads source files from disk on-demand; never loads the entire
  repository into memory.
* Budget is expressed in *characters* by default (1 token ≈ 4 chars).
  A ``token_multiplier`` config adjusts the ratio for providers with
  different tokenizers.
* Each context section carries ``file`` and ``start_line`` / ``end_line``
  so that the model can reference exact locations.

Limitations
-----------
* Cross-file data-flow context relies on the best-effort caller/callee
  edges from ``indexer.py`` — may miss indirect calls.
* Configuration file detection is heuristic (looks for common Spring
  config patterns in ``*.properties``, ``*.yml``, ``*.yaml``, ``*.xml``).
* Test association is by class name similarity; no semantic matching.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from harness.indexer import (
    CallerCalleeEdge,
    ClassInfo,
    JavaIndexer,
    JavaSymbolIndex,
    MethodInfo,
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_BUDGET_CHARS = 32_000       # ~8 000 tokens at 4 chars/token
DEFAULT_TOKEN_MULTIPLIER = 4.0      # chars per token estimate
MAX_CALLER_CALLEE_DEPTH = 2         # how many levels of call chain to include
MAX_CODE_LINES_PER_SECTION = 200    # cap on any single code section
MAX_CONFIG_SNIPPETS = 5             # max config file excerpts
MAX_TEST_SNIPPETS = 3               # max related test excerpts


@dataclass
class ContextConfig:
    """Configuration for context retrieval."""
    budget_chars: int = DEFAULT_BUDGET_CHARS
    token_multiplier: float = DEFAULT_TOKEN_MULTIPLIER
    max_caller_callee_depth: int = MAX_CALLER_CALLEE_DEPTH
    max_code_lines_per_section: int = MAX_CODE_LINES_PER_SECTION
    max_config_snippets: int = MAX_CONFIG_SNIPPETS
    max_test_snippets: int = MAX_TEST_SNIPPETS
    include_architecture_summary: bool = True
    include_config: bool = True
    include_tests: bool = True

    @property
    def budget_tokens(self) -> int:
        """Estimated token budget."""
        return int(self.budget_chars / self.token_multiplier)


# ---------------------------------------------------------------------------
# Context section model
# ---------------------------------------------------------------------------

@dataclass
class ContextSection:
    """A single section of context with source provenance."""
    label: str              # e.g. "sink_function", "caller_method"
    file: str               # relative path
    start_line: int | None
    end_line: int | None
    content: str            # the actual code/text
    char_count: int = 0

    def __post_init__(self) -> None:
        self.char_count = len(self.content)


@dataclass
class CandidateContext:
    """Complete context package for a single candidate."""
    candidate_id: str
    file: str
    line: int | None
    sections: list[ContextSection] = field(default_factory=list)
    total_chars: int = 0
    total_estimated_tokens: int = 0
    budget_chars: int = DEFAULT_BUDGET_CHARS
    budget_exceeded: bool = False
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "file": self.file,
            "line": self.line,
            "sections": [asdict(s) for s in self.sections],
            "total_chars": self.total_chars,
            "total_estimated_tokens": self.total_estimated_tokens,
            "budget_chars": self.budget_chars,
            "budget_exceeded": self.budget_exceeded,
            "warnings": self.warnings,
        }

    def to_prompt_text(self) -> str:
        """Render all context sections into a single prompt-ready string."""
        parts: list[str] = []
        for section in self.sections:
            header = f"=== {section.label} ==="
            if section.file:
                loc = section.file
                if section.start_line:
                    loc += f":{section.start_line}"
                    if section.end_line and section.end_line != section.start_line:
                        loc += f"-{section.end_line}"
                header += f"  [{loc}]"
            parts.append(header)
            parts.append(section.content)
            parts.append("")
        return "\n".join(parts)


# ---------------------------------------------------------------------------
# ContextBuilder
# ---------------------------------------------------------------------------

class ContextBuilder:
    """Builds context packages for vulnerability candidates.

    Parameters
    ----------
    webgoat_root : str | Path
        Absolute path to WebGoat source root.
    index : JavaSymbolIndex
        Pre-built symbol index from ``indexer.py``.
    recon : dict | None
        Parsed ``reconnaissance.json`` dict. If None, architecture
        summary and security-pattern context are omitted.
    config : ContextConfig | None
        Optional configuration overrides.
    """

    def __init__(
        self,
        webgoat_root: str | Path,
        index: JavaSymbolIndex,
        recon: dict[str, Any] | None = None,
        config: ContextConfig | None = None,
    ) -> None:
        self.root = Path(webgoat_root).resolve()
        self.index = index
        self.recon = recon or {}
        self.config = config or ContextConfig()
        # Cache for file contents
        self._file_cache: dict[str, list[str]] = {}

    # -- Public API ----------------------------------------------------------

    def build_context(
        self,
        candidate_id: str,
        file: str,
        line: int | None = None,
        symbol: str | None = None,
        category: str | None = None,
    ) -> CandidateContext:
        """Build a context package for a vulnerability candidate.

        Parameters
        ----------
        candidate_id : str
            Unique ID for the candidate.
        file : str
            Relative path of the file containing the candidate.
        line : int | None
            Line number of the candidate (1-indexed).
        symbol : str | None
            Method or class name related to the candidate.
        category : str | None
            Vulnerability category (e.g. ``"database"``, ``"file_handling"``).

        Returns
        -------
        CandidateContext
            The assembled context package.
        """
        ctx = CandidateContext(
            candidate_id=candidate_id,
            file=file,
            line=line,
            budget_chars=self.config.budget_chars,
        )

        # 1. Sink function
        self._add_sink_function(ctx, file, line, symbol)

        # 2. Enclosing class
        self._add_enclosing_class(ctx, file, line)

        # 3. Caller chain
        self._add_caller_chain(ctx, file, line, symbol)

        # 4. Callee chain
        self._add_callee_chain(ctx, file, line, symbol)

        # 5. Source function (if different from sink)
        self._add_source_function(ctx, file, line, symbol)

        # 6. Endpoint / route info
        self._add_endpoint_info(ctx, file, line, symbol)

        # 7. Architecture summary
        if self.config.include_architecture_summary:
            self._add_architecture_summary(ctx, category)

        # 8. Configuration
        if self.config.include_config:
            self._add_config_context(ctx, file, category)

        # 9. Tests / fixtures
        if self.config.include_tests:
            self._add_test_context(ctx, file, line, symbol)

        # Finalize totals
        ctx.total_chars = sum(s.char_count for s in ctx.sections)
        ctx.total_estimated_tokens = int(
            ctx.total_chars / self.config.token_multiplier
        )

        return ctx

    # -- Section builders ----------------------------------------------------

    def _add_section(
        self,
        ctx: CandidateContext,
        label: str,
        file: str,
        start_line: int | None,
        end_line: int | None,
        content: str,
    ) -> bool:
        """Add a section if budget allows. Returns True if added."""
        current_chars = sum(s.char_count for s in ctx.sections)
        content_chars = len(content)
        if current_chars + content_chars > self.config.budget_chars:
            # Try to truncate to fit
            remaining = self.config.budget_chars - current_chars
            if remaining < 200:  # too small to be useful
                ctx.budget_exceeded = True
                ctx.warnings.append(
                    f"Budget exceeded: skipped '{label}' "
                    f"({content_chars} chars, {remaining} remaining)"
                )
                return False
            content = content[:remaining - 50] + "\n... [truncated to fit budget]"
            ctx.warnings.append(
                f"Truncated '{label}' from {content_chars} to "
                f"{len(content)} chars to fit budget"
            )

        section = ContextSection(
            label=label,
            file=file,
            start_line=start_line,
            end_line=end_line,
            content=content,
        )
        ctx.sections.append(section)
        return True

    def _add_sink_function(
        self,
        ctx: CandidateContext,
        file: str,
        line: int | None,
        symbol: str | None,
    ) -> None:
        """Add the function containing the sink/candidate."""
        method = self._find_method(file, line, symbol)
        if method is None:
            ctx.warnings.append(
                f"Could not resolve sink function at {file}:{line}"
            )
            # Fall back to surrounding lines
            if line is not None:
                code = self._read_lines_range(
                    file,
                    max(1, line - 10),
                    line + 20,
                )
                if code:
                    self._add_section(
                        ctx, "sink_region", file,
                        max(1, line - 10), line + 20, code,
                    )
            return

        code = self._read_method(file, method)
        if code:
            self._add_section(
                ctx, "sink_function", file,
                method.start_line, method.end_line, code,
            )

    def _add_enclosing_class(
        self,
        ctx: CandidateContext,
        file: str,
        line: int | None,
    ) -> None:
        """Add the enclosing class signature + field declarations."""
        cls = self._find_class(file, line)
        if cls is None:
            return

        # Read the class header (annotations, declaration, fields)
        # We do NOT include all method bodies — just the structure
        code = self._read_class_skeleton(file, cls)
        if code:
            self._add_section(
                ctx, "enclosing_class", file,
                cls.start_line, cls.end_line, code,
            )

    def _add_caller_chain(
        self,
        ctx: CandidateContext,
        file: str,
        line: int | None,
        symbol: str | None,
    ) -> None:
        """Add callers of the candidate method (up to depth limit)."""
        method = self._find_method(file, line, symbol)
        if method is None:
            return

        visited: set[str] = set()
        self._collect_callers(
            ctx, method.name, 0, visited,
        )

    def _collect_callers(
        self,
        ctx: CandidateContext,
        method_name: str,
        depth: int,
        visited: set[str],
    ) -> None:
        """Recursively collect caller methods."""
        if depth >= self.config.max_caller_callee_depth:
            return

        edges = JavaIndexer.lookup_callers(self.index, method_name)
        for edge in edges:
            key = f"{edge.caller_class}.{edge.caller_method}"
            if key in visited:
                continue
            visited.add(key)

            # Find the caller method info
            methods = JavaIndexer.lookup_method(
                self.index, edge.caller_method, edge.caller_class,
            )
            for m in methods:
                code = self._read_method(edge.file, m)
                if code:
                    label = f"caller_L{depth}_{edge.caller_class}.{edge.caller_method}"
                    self._add_section(
                        ctx, label, edge.file,
                        m.start_line, m.end_line, code,
                    )
                break  # only first match

            # Recurse
            self._collect_callers(ctx, edge.caller_method, depth + 1, visited)

    def _add_callee_chain(
        self,
        ctx: CandidateContext,
        file: str,
        line: int | None,
        symbol: str | None,
    ) -> None:
        """Add methods called by the candidate method."""
        method = self._find_method(file, line, symbol)
        if method is None:
            return

        cls = self._find_class(file, line)
        if cls is None:
            return

        visited: set[str] = set()
        self._collect_callees(
            ctx, cls.name, method.name, 0, visited,
        )

    def _collect_callees(
        self,
        ctx: CandidateContext,
        class_name: str,
        method_name: str,
        depth: int,
        visited: set[str],
    ) -> None:
        """Recursively collect callee methods."""
        if depth >= self.config.max_caller_callee_depth:
            return

        edges = JavaIndexer.lookup_callees(self.index, class_name, method_name)
        for edge in edges:
            key = f"{edge.caller_class}.{edge.callee_method}"
            if key in visited:
                continue
            visited.add(key)

            # Find the callee method info — search across all classes
            methods = JavaIndexer.lookup_method(self.index, edge.callee_method)
            for m in methods:
                code = self._read_method(m.file, m)
                if code:
                    label = f"callee_L{depth}_{m.class_name}.{m.name}"
                    self._add_section(
                        ctx, label, m.file,
                        m.start_line, m.end_line, code,
                    )
                break  # only first match

    def _add_source_function(
        self,
        ctx: CandidateContext,
        file: str,
        line: int | None,
        symbol: str | None,
    ) -> None:
        """Try to identify and add a source function (entry point).

        Heuristic: look for endpoint methods in the same class that
        receive HTTP input, which may feed data to the sink.
        """
        cls = self._find_class(file, line)
        if cls is None:
            return

        sink_method = self._find_method(file, line, symbol)
        sink_name = sink_method.name if sink_method else None

        for m in cls.methods:
            if m.endpoint is not None and m.name != sink_name:
                # Check if this endpoint method calls the sink
                if sink_name and sink_name in m.calls:
                    code = self._read_method(file, m)
                    if code:
                        self._add_section(
                            ctx, f"source_endpoint_{m.name}", file,
                            m.start_line, m.end_line, code,
                        )

    def _add_endpoint_info(
        self,
        ctx: CandidateContext,
        file: str,
        line: int | None,
        symbol: str | None,
    ) -> None:
        """Add endpoint / route metadata for the candidate."""
        method = self._find_method(file, line, symbol)
        if method and method.endpoint:
            info = (
                f"HTTP {method.endpoint.http_method} "
                f"{method.endpoint.path} "
                f"({method.endpoint.annotation})"
            )
            self._add_section(
                ctx, "endpoint_info", file,
                method.start_line, method.start_line, info,
            )
            return

        # Check if enclosing class has any endpoints
        cls = self._find_class(file, line)
        if cls is None:
            return

        endpoints: list[str] = []
        for m in cls.methods:
            if m.endpoint:
                endpoints.append(
                    f"  {m.endpoint.http_method} {m.endpoint.path} → {m.name}()"
                )
        if endpoints:
            info = f"Class endpoints for {cls.name}:\n" + "\n".join(endpoints)
            self._add_section(
                ctx, "class_endpoints", file,
                cls.start_line, cls.start_line, info,
            )

    def _add_architecture_summary(
        self,
        ctx: CandidateContext,
        category: str | None,
    ) -> None:
        """Add a compact architecture summary from reconnaissance data."""
        if not self.recon:
            return

        parts: list[str] = []

        # Lesson modules (compact list)
        lessons = self.recon.get("lesson_modules", [])
        if lessons:
            names = [lm.get("name", "") for lm in lessons[:15]]
            parts.append(f"WebGoat lessons ({len(lessons)}): {', '.join(names)}")

        # Summary counts
        summary = self.recon.get("summary", {})
        if summary:
            parts.append(
                f"Components: {summary.get('total_components', '?')} | "
                f"Endpoints: {summary.get('total_endpoints', '?')} | "
                f"Patterns: {summary.get('total_security_patterns', '?')}"
            )

        # Security patterns in the candidate category
        if category:
            patterns = self.recon.get("security_patterns", {})
            cat_patterns = patterns.get(category, [])
            if cat_patterns:
                # Summarize — just unique files
                files = sorted(set(p.get("file", "") for p in cat_patterns))
                parts.append(
                    f"Files with '{category}' patterns ({len(cat_patterns)} hits): "
                    + ", ".join(files[:10])
                )

        if parts:
            content = "\n".join(parts)
            self._add_section(
                ctx, "architecture_summary", "", None, None, content,
            )

    def _add_config_context(
        self,
        ctx: CandidateContext,
        file: str,
        category: str | None,
    ) -> None:
        """Add relevant configuration snippets."""
        config_patterns = self._find_config_files(file, category)
        added = 0
        for cfg_file, snippet in config_patterns:
            if added >= self.config.max_config_snippets:
                break
            self._add_section(
                ctx, f"config_{cfg_file}", cfg_file, None, None, snippet,
            )
            added += 1

    def _add_test_context(
        self,
        ctx: CandidateContext,
        file: str,
        line: int | None,
        symbol: str | None,
    ) -> None:
        """Add related test files that may contain evidence."""
        cls = self._find_class(file, line)
        if cls is None:
            return

        test_files = self._find_related_tests(cls.name, file)
        added = 0
        for test_file in test_files:
            if added >= self.config.max_test_snippets:
                break
            code = self._read_file_bounded(test_file)
            if code:
                self._add_section(
                    ctx, f"test_{test_file}", test_file, 1, None, code,
                )
                added += 1

    # -- Lookup helpers ------------------------------------------------------

    def _find_method(
        self,
        file: str,
        line: int | None,
        symbol: str | None,
    ) -> MethodInfo | None:
        """Find the method at the given file/line or by symbol name."""
        if line is not None:
            m = JavaIndexer.get_method_at_line(self.index, file, line)
            if m is not None:
                return m

        if symbol:
            methods = JavaIndexer.lookup_method(self.index, symbol)
            # Prefer method in the same file
            for m in methods:
                if m.file == file:
                    return m
            if methods:
                return methods[0]

        return None

    def _find_class(
        self,
        file: str,
        line: int | None,
    ) -> ClassInfo | None:
        """Find the class at the given file/line."""
        if line is not None:
            c = JavaIndexer.get_class_at_line(self.index, file, line)
            if c is not None:
                return c

        # Fall back to first class in the file
        for c in self.index.classes:
            if c.file == file:
                return c
        return None

    # -- File reading helpers ------------------------------------------------

    def _get_lines(self, rel_path: str) -> list[str]:
        """Read and cache file lines by relative path."""
        if rel_path in self._file_cache:
            return self._file_cache[rel_path]

        abs_path = self.root / rel_path
        try:
            lines = abs_path.read_text(
                encoding="utf-8", errors="replace",
            ).splitlines()
        except OSError:
            lines = []

        self._file_cache[rel_path] = lines
        return lines

    def _read_lines_range(
        self,
        file: str,
        start: int,
        end: int,
    ) -> str:
        """Read a range of lines from a file (1-indexed, inclusive)."""
        lines = self._get_lines(file)
        if not lines:
            return ""
        start = max(1, start)
        end = min(len(lines), end)
        selected = lines[start - 1 : end]
        # Cap line count
        if len(selected) > self.config.max_code_lines_per_section:
            selected = selected[: self.config.max_code_lines_per_section]
            selected.append("// ... [truncated]")
        return "\n".join(selected)

    def _read_method(self, file: str, method: MethodInfo) -> str:
        """Read the source of a method."""
        code = self._read_lines_range(
            file, method.start_line, method.end_line,
        )
        if not code and method:
            ann_prefix = " ".join(a.raw for a in method.annotations) + "\n" if method.annotations else ""
            code = f"// [source file unavailable on disk]\n{ann_prefix}{method.visibility} {method.return_type} {method.name}({method.parameters}) {{ /* ... */ }}"
        return code

    def _read_class_skeleton(self, file: str, cls: ClassInfo) -> str:
        """Read class declaration + fields, omitting method bodies.

        Provides the structural context without blowing the budget.
        """
        lines = self._get_lines(file)
        if not lines:
            methods_summary = "\n".join(
                f"    {m.visibility} {m.return_type} {m.name}({m.parameters});"
                for m in cls.methods
            )
            return f"// [source file unavailable on disk]\n{cls.visibility} {cls.kind} {cls.name} {{\n{methods_summary}\n}}"

        start = max(0, cls.start_line - 1)
        end = min(len(lines), cls.end_line)
        class_lines = lines[start:end]

        # Strategy: include lines up to first method, then just signatures
        result: list[str] = []
        in_method_body = False
        brace_depth = 0
        method_starts = {m.start_line for m in cls.methods}

        for i, raw_line in enumerate(class_lines):
            actual_line = start + i + 1  # 1-indexed

            if in_method_body:
                brace_depth += raw_line.count("{") - raw_line.count("}")
                if brace_depth <= 0:
                    in_method_body = False
                    result.append(raw_line)  # closing brace
                continue

            result.append(raw_line)

            if actual_line in method_starts:
                # We included the method signature line; now skip body
                brace_depth = raw_line.count("{") - raw_line.count("}")
                if brace_depth > 0:
                    in_method_body = True

            if len(result) > self.config.max_code_lines_per_section:
                result.append("    // ... [class skeleton truncated]")
                break

        return "\n".join(result)

    def _read_file_bounded(self, rel_path: str) -> str:
        """Read the first N lines of a file."""
        lines = self._get_lines(rel_path)
        if not lines:
            return ""
        cap = min(len(lines), self.config.max_code_lines_per_section)
        selected = lines[:cap]
        if cap < len(lines):
            selected.append("// ... [file truncated]")
        return "\n".join(selected)

    # -- Config / test discovery ---------------------------------------------

    def _find_config_files(
        self,
        file: str,
        category: str | None,
    ) -> list[tuple[str, str]]:
        """Find configuration files relevant to the candidate.

        Searches for Spring config (application.properties/yml),
        security config classes, and pom.xml dependencies.
        """
        results: list[tuple[str, str]] = []

        # Search through indexed classes for security config
        for c in self.index.classes:
            ann_names = [a.name for a in c.annotations]
            if "Configuration" in ann_names or "EnableWebSecurity" in ann_names:
                code = self._read_class_skeleton(c.file, c)
                if code:
                    results.append((c.file, code))
                    if len(results) >= self.config.max_config_snippets:
                        return results

        # Look for application.properties/yml near the candidate file
        candidate_dir = str(Path(file).parent)
        config_names = [
            "application.properties",
            "application.yml",
            "application.yaml",
            "application-webgoat.properties",
        ]

        for root_dir, _dirs, files in os.walk(self.root):
            for fname in files:
                if fname in config_names:
                    rel = str(
                        Path(root_dir, fname).relative_to(self.root)
                    ).replace(os.sep, "/")
                    content = self._read_file_bounded(rel)
                    if content:
                        results.append((rel, content))
                    if len(results) >= self.config.max_config_snippets:
                        return results

        return results

    def _find_related_tests(
        self,
        class_name: str,
        source_file: str,
    ) -> list[str]:
        """Find test files related to a given class.

        Heuristics:
        1. Look for ``<ClassName>Test.java`` or ``Test<ClassName>.java``.
        2. Look for test files in the same lesson/module package.
        """
        candidates: list[str] = []
        target_names = {
            f"{class_name}Test",
            f"Test{class_name}",
            f"{class_name}Tests",
            f"{class_name}IT",
        }

        # Derive the package/lesson from source file path
        source_parts = set(Path(source_file).parts)

        for c in self.index.classes:
            if c.name in target_names:
                candidates.append(c.file)
            elif "test" in c.file.lower() and c.file != source_file:
                # Check if test is in same lesson package
                test_parts = set(Path(c.file).parts)
                common = source_parts & test_parts
                # If they share a lesson-specific directory, include
                if len(common) >= 3:  # at least 3 common path segments
                    candidates.append(c.file)

        return candidates[: self.config.max_test_snippets]

    # -- Batch / CLI ---------------------------------------------------------

    def build_contexts_batch(
        self,
        candidates: list[dict[str, Any]],
    ) -> list[CandidateContext]:
        """Build context for a batch of candidates.

        Each candidate dict should have at minimum:
        ``candidate_id``, ``file``, ``line``.
        Optional: ``symbol``, ``category``.
        """
        return [
            self.build_context(
                candidate_id=c.get("candidate_id", f"cand-{i}"),
                file=c["file"],
                line=c.get("line"),
                symbol=c.get("symbol"),
                category=c.get("category"),
            )
            for i, c in enumerate(candidates)
        ]


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def build_candidate_context(
    webgoat_root: str | Path,
    index: JavaSymbolIndex,
    candidate_id: str,
    file: str,
    line: int | None = None,
    symbol: str | None = None,
    category: str | None = None,
    recon: dict[str, Any] | None = None,
    config: ContextConfig | None = None,
) -> CandidateContext:
    """One-shot convenience: build context for a single candidate."""
    builder = ContextBuilder(webgoat_root, index, recon=recon, config=config)
    return builder.build_context(candidate_id, file, line, symbol, category)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Context retrieval for vulnerability candidates (Micro-task 2.3)",
    )
    parser.add_argument(
        "--source", "-s",
        default="webgoat/WebGoat-2025.3",
        help="Path to WebGoat source root",
    )
    parser.add_argument(
        "--index", "-i",
        default="results/symbol_index.json",
        help="Path to symbol_index.json",
    )
    parser.add_argument(
        "--recon", "-r",
        default="results/reconnaissance.json",
        help="Path to reconnaissance.json",
    )
    parser.add_argument(
        "--file", "-f",
        required=True,
        help="Relative path of candidate file",
    )
    parser.add_argument(
        "--line", "-l",
        type=int,
        default=None,
        help="Line number of candidate",
    )
    parser.add_argument(
        "--symbol",
        default=None,
        help="Method or class symbol name",
    )
    parser.add_argument(
        "--category",
        default=None,
        help="Vulnerability category",
    )
    parser.add_argument(
        "--budget",
        type=int,
        default=DEFAULT_BUDGET_CHARS,
        help="Character budget for context",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output JSON file (default: stdout)",
    )
    args = parser.parse_args()

    # Load index
    from harness.indexer import JavaIndexer as _Indexer
    with open(args.index, "r", encoding="utf-8") as f:
        raw_index = json.load(f)

    # Reconstruct index dataclasses from JSON
    index = _Indexer.load_index(raw_index)

    # Load recon
    recon_data = None
    if os.path.exists(args.recon):
        with open(args.recon, "r", encoding="utf-8") as f:
            recon_data = json.load(f)

    cfg = ContextConfig(budget_chars=args.budget)
    result = build_candidate_context(
        webgoat_root=args.source,
        index=index,
        candidate_id="cli-candidate",
        file=args.file,
        line=args.line,
        symbol=args.symbol,
        category=args.category,
        recon=recon_data,
        config=cfg,
    )

    output = json.dumps(result.to_dict(), indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Context written to {args.output}")
    else:
        print(output)

    print(f"\nSections: {len(result.sections)}")
    print(f"Total chars: {result.total_chars}")
    print(f"Estimated tokens: {result.total_estimated_tokens}")
    print(f"Budget: {result.budget_chars} chars")
    print(f"Exceeded: {result.budget_exceeded}")
    if result.warnings:
        print(f"Warnings: {len(result.warnings)}")
        for w in result.warnings:
            print(f"  - {w}")
