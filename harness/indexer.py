"""Java symbol index for the SAST benchmark harness.

Micro-task 2.2 — builds a lightweight symbol index over Java source files:
  * class / interface / enum / record / annotation declarations
  * method declarations with line ranges
  * package declarations
  * annotations on classes and methods
  * import statements
  * endpoint mappings (Spring ``@*Mapping``)
  * simple caller/callee edges (method calls within a method body)
  * ``implements`` / ``extends`` relationships

The index is deterministic (no LLM calls) and relies on regex-based heuristics.
If a proper AST parser (e.g. Tree-sitter with Java grammar) is available in the
environment it should be preferred — this module documents that limitation.

Limitations
-----------
* Regex-based: may miss some edge-cases (lambdas, anonymous classes, nested
  generics in method signatures).
* Caller/callee is *intra-file best-effort*: method calls are extracted from
  the method body using heuristic patterns and may include false positives
  (e.g. chained builder calls).
* Does not perform full type resolution or cross-file type inference.
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


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ImportInfo:
    """A single import statement."""
    statement: str          # full import, e.g. "java.sql.Connection"
    is_static: bool
    is_wildcard: bool
    file: str               # relative path
    line: int


@dataclass
class AnnotationInfo:
    """An annotation found on a class or method."""
    name: str               # e.g. "RestController", "PostMapping"
    raw: str                # raw annotation text
    line: int


@dataclass
class MethodInfo:
    """A method declaration."""
    name: str
    class_name: str
    file: str               # relative path
    start_line: int
    end_line: int           # best-effort end line (next method / class close)
    visibility: str         # public | protected | private | package
    return_type: str
    parameters: str         # raw parameter string
    annotations: list[AnnotationInfo]
    endpoint: EndpointMapping | None
    calls: list[str]        # list of method names called (best-effort)


@dataclass
class EndpointMapping:
    """A Spring endpoint mapping extracted from method annotations."""
    http_method: str        # GET, POST, PUT, DELETE, PATCH, ANY
    path: str               # URL pattern
    annotation: str         # e.g. "@PostMapping"


@dataclass
class ClassInfo:
    """A class, interface, enum, record, or annotation type declaration."""
    kind: str               # class | interface | enum | record | annotation_type
    name: str
    qualified_name: str     # package + class name
    package: str
    file: str               # relative path
    start_line: int
    end_line: int           # best-effort
    visibility: str         # public | package
    annotations: list[AnnotationInfo]
    extends: str | None
    implements: list[str]
    methods: list[MethodInfo]
    imports: list[ImportInfo]


@dataclass
class CallerCalleeEdge:
    """A directed caller → callee edge."""
    caller_class: str
    caller_method: str
    callee_method: str
    file: str
    caller_line: int        # start line of the caller method


@dataclass
class JavaSymbolIndex:
    """Top-level index output."""
    generated_at: str
    webgoat_root: str
    total_java_files: int
    indexed_files: int
    excluded_files: int

    classes: list[ClassInfo]
    caller_callee_edges: list[CallerCalleeEdge]

    # Summary
    summary: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Package declaration
_PACKAGE_RE = re.compile(r'^\s*package\s+([\w.]+)\s*;')

# Import statement
_IMPORT_RE = re.compile(
    r'^\s*import\s+(static\s+)?([\w.]+(?:\.\*)?)\s*;'
)

# Class/interface/enum/record/@interface declaration
_TYPE_DECL_RE = re.compile(
    r'^\s*(?:(public|protected|private)\s+)?'
    r'(?:(?:abstract|final|sealed|non-sealed|static)\s+)*'
    r'(class|interface|enum|record|@interface)\s+'
    r'(\w+)'
    r'(?:\s*<[^{]*>)?'                  # generic params
    r'(?:\s+extends\s+([\w.<>,\s]+?))?'   # extends clause
    r'(?:\s+implements\s+([\w.<>,\s]+?))?' # implements clause
    r'(?:\s+permits\s+([\w.<>,\s]+?))?'   # permits clause (sealed)
    r'\s*\{',
    re.MULTILINE,
)

# Method declaration — captures visibility, return type, name, and params
_METHOD_RE = re.compile(
    r'^\s*(?:(public|protected|private)\s+)?'
    r'(?:(?:static|final|abstract|synchronized|native|default|strictfp)\s+)*'
    r'([\w<>\[\]?,\s]+?)\s+'  # return type
    r'(\w+)\s*'               # method name
    r'\(([^)]*)\)\s*'         # parameters
    r'(?:throws\s+[\w.,\s]+\s*)?'
    r'[{;]',                  # body start or abstract semicolon
)

# Annotation (preceding a declaration)
_ANNOTATION_RE = re.compile(
    r'@(\w+)(?:\s*\(([^)]*)\))?'
)

# Spring endpoint mapping annotations
_ENDPOINT_ANNOTATIONS = {
    "RequestMapping": None,
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH",
}

# Extract path from mapping annotation value
_PATH_VALUE_RE = re.compile(
    r'(?:value\s*=\s*|path\s*=\s*)?["{]?\s*"([^"]*)"'
)

# Extract method from @RequestMapping(method = RequestMethod.GET)
_METHOD_VALUE_RE = re.compile(
    r'method\s*=\s*(?:RequestMethod\.)?(\w+)'
)

# Method call pattern: identifier followed by ( — used for caller/callee
_METHOD_CALL_RE = re.compile(r'(?<!\w)(\w+)\s*\(')

# Constructor call: new ClassName(
_CONSTRUCTOR_CALL_RE = re.compile(r'\bnew\s+(\w+)\s*\(')


# ---------------------------------------------------------------------------
# Indexer
# ---------------------------------------------------------------------------

class JavaIndexer:
    """Builds a symbol index over Java source files.

    Usage::

        indexer = JavaIndexer(webgoat_root, exclusion_policy=policy)
        index = indexer.build()
        indexer.save(index, output_dir)
    """

    def __init__(
        self,
        webgoat_root: str | Path,
        exclusion_policy: ExclusionPolicy | None = None,
    ):
        self.root = Path(webgoat_root).resolve()
        self.policy = exclusion_policy
        self._java_files: list[Path] = []
        self._excluded_count = 0

    # -- Public API ----------------------------------------------------------

    def build(self) -> JavaSymbolIndex:
        """Scan all Java files and build the symbol index."""
        self._collect_java_files()

        all_classes: list[ClassInfo] = []
        all_edges: list[CallerCalleeEdge] = []

        for fpath in self._java_files:
            classes, edges = self._index_file(fpath)
            all_classes.extend(classes)
            all_edges.extend(edges)

        summary = self._build_summary(all_classes, all_edges)

        return JavaSymbolIndex(
            generated_at=datetime.now(timezone.utc).isoformat(),
            webgoat_root=str(self.root),
            total_java_files=len(self._java_files) + self._excluded_count,
            indexed_files=len(self._java_files),
            excluded_files=self._excluded_count,
            classes=all_classes,
            caller_callee_edges=all_edges,
            summary=summary,
        )

    def save(
        self,
        index: JavaSymbolIndex,
        output_dir: str | Path,
    ) -> Path:
        """Write ``symbol_index.json`` to *output_dir*.

        Returns the path to the generated file.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        index_path = out / "symbol_index.json"
        index_path.write_text(
            json.dumps(_to_serializable(index), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return index_path

    @staticmethod
    def load_index(data: dict[str, Any]) -> JavaSymbolIndex:
        """Construct a JavaSymbolIndex instance from a parsed JSON dict."""
        classes: list[ClassInfo] = []
        for c in data.get("classes", []):
            methods: list[MethodInfo] = []
            for m in c.get("methods", []):
                annotations = [
                    AnnotationInfo(**ann) for ann in m.get("annotations", [])
                ]
                ep_data = m.get("endpoint")
                endpoint = EndpointMapping(**ep_data) if ep_data else None
                methods.append(MethodInfo(
                    name=m["name"],
                    class_name=m["class_name"],
                    file=m["file"],
                    start_line=m["start_line"],
                    end_line=m["end_line"],
                    visibility=m["visibility"],
                    return_type=m["return_type"],
                    parameters=m["parameters"],
                    annotations=annotations,
                    endpoint=endpoint,
                    calls=m.get("calls", []),
                ))
            class_annotations = [
                AnnotationInfo(**ann) for ann in c.get("annotations", [])
            ]
            imports = [
                ImportInfo(**imp) for imp in c.get("imports", [])
            ]
            classes.append(ClassInfo(
                kind=c["kind"],
                name=c["name"],
                qualified_name=c["qualified_name"],
                package=c["package"],
                file=c["file"],
                start_line=c["start_line"],
                end_line=c["end_line"],
                visibility=c["visibility"],
                annotations=class_annotations,
                extends=c.get("extends"),
                implements=c.get("implements", []),
                methods=methods,
                imports=imports,
            ))
        edges = [
            CallerCalleeEdge(**edge)
            for edge in data.get("caller_callee_edges", [])
        ]
        return JavaSymbolIndex(
            generated_at=data.get("generated_at", ""),
            webgoat_root=data.get("webgoat_root", ""),
            total_java_files=data.get("total_java_files", 0),
            indexed_files=data.get("indexed_files", 0),
            excluded_files=data.get("excluded_files", 0),
            classes=classes,
            caller_callee_edges=edges,
            summary=data.get("summary", {}),
        )

    # -- Lookup helpers (for downstream phases) ------------------------------

    @staticmethod
    def lookup_class(index: JavaSymbolIndex, class_name: str) -> list[ClassInfo]:
        """Find ClassInfo entries by simple or qualified name."""
        return [
            c for c in index.classes
            if c.name == class_name or c.qualified_name == class_name
        ]

    @staticmethod
    def lookup_method(
        index: JavaSymbolIndex,
        method_name: str,
        class_name: str | None = None,
    ) -> list[MethodInfo]:
        """Find MethodInfo entries by name, optionally filtered by class."""
        results: list[MethodInfo] = []
        for c in index.classes:
            if class_name and c.name != class_name and c.qualified_name != class_name:
                continue
            for m in c.methods:
                if m.name == method_name:
                    results.append(m)
        return results

    @staticmethod
    def lookup_callers(
        index: JavaSymbolIndex,
        method_name: str,
    ) -> list[CallerCalleeEdge]:
        """Find all callers of a given method name."""
        return [e for e in index.caller_callee_edges if e.callee_method == method_name]

    @staticmethod
    def lookup_callees(
        index: JavaSymbolIndex,
        class_name: str,
        method_name: str,
    ) -> list[CallerCalleeEdge]:
        """Find all methods called from a given class.method."""
        return [
            e for e in index.caller_callee_edges
            if e.caller_class == class_name and e.caller_method == method_name
        ]

    @staticmethod
    def lookup_endpoints(
        index: JavaSymbolIndex,
        path_substring: str | None = None,
        http_method: str | None = None,
    ) -> list[tuple[ClassInfo, MethodInfo]]:
        """Find methods with endpoint mappings, optionally filtered."""
        results: list[tuple[ClassInfo, MethodInfo]] = []
        for c in index.classes:
            for m in c.methods:
                if m.endpoint is None:
                    continue
                if path_substring and path_substring not in m.endpoint.path:
                    continue
                if http_method and m.endpoint.http_method != http_method.upper():
                    continue
                results.append((c, m))
        return results

    @staticmethod
    def get_methods_in_file(
        index: JavaSymbolIndex,
        file_path: str,
    ) -> list[MethodInfo]:
        """Return all methods in the given file."""
        results: list[MethodInfo] = []
        for c in index.classes:
            if c.file == file_path:
                results.extend(c.methods)
        return results

    @staticmethod
    def get_method_at_line(
        index: JavaSymbolIndex,
        file_path: str,
        line: int,
    ) -> MethodInfo | None:
        """Return the method containing the given line, or None."""
        for c in index.classes:
            if c.file != file_path:
                continue
            for m in c.methods:
                if m.start_line <= line <= m.end_line:
                    return m
        return None

    @staticmethod
    def get_class_at_line(
        index: JavaSymbolIndex,
        file_path: str,
        line: int,
    ) -> ClassInfo | None:
        """Return the class containing the given line, or None."""
        for c in index.classes:
            if c.file == file_path and c.start_line <= line <= c.end_line:
                return c
        return None

    # -- Internal helpers ----------------------------------------------------

    def _collect_java_files(self) -> None:
        """Walk the source tree and collect non-excluded .java files."""
        self._java_files = []
        self._excluded_count = 0
        for dirpath, _dirnames, filenames in os.walk(self.root):
            for fname in filenames:
                if not fname.endswith(".java"):
                    continue
                abs_path = Path(dirpath) / fname
                rel_path = abs_path.relative_to(self.root)
                if self.policy and self.policy.should_exclude(str(rel_path)):
                    self._excluded_count += 1
                    continue
                self._java_files.append(abs_path)

    def _rel(self, path: Path) -> str:
        return str(path.relative_to(self.root)).replace(os.sep, "/")

    def _read_lines(self, path: Path) -> list[str]:
        try:
            return path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []

    def _index_file(self, fpath: Path) -> tuple[list[ClassInfo], list[CallerCalleeEdge]]:
        """Index a single Java file, returning classes and edges."""
        lines = self._read_lines(fpath)
        if not lines:
            return [], []

        rel = self._rel(fpath)
        full_text = "\n".join(lines)

        # 1. Package
        package = self._extract_package(lines)

        # 2. Imports
        imports = self._extract_imports(lines, rel)

        # 3. Collect annotations that appear before class/method declarations
        annotations_by_line = self._collect_annotations(lines)

        # 4. Find class/interface/enum declarations
        raw_classes = self._find_type_declarations(lines, full_text, rel, package)

        # 5. For each class, find methods
        all_edges: list[CallerCalleeEdge] = []
        classes: list[ClassInfo] = []

        for rc in raw_classes:
            # Gather annotations for this class
            class_annotations = self._get_annotations_before(
                annotations_by_line, rc["start_line"]
            )

            # Find class-level base path for endpoint resolution
            class_base_path = ""
            for ann in class_annotations:
                if ann.name == "RequestMapping":
                    pm = _PATH_VALUE_RE.search(ann.raw)
                    if pm:
                        class_base_path = pm.group(1)
                    break

            # Find methods within class range
            methods, edges = self._find_methods(
                lines, rel, rc, annotations_by_line, class_base_path,
            )
            all_edges.extend(edges)

            ci = ClassInfo(
                kind=rc["kind"],
                name=rc["name"],
                qualified_name=f"{package}.{rc['name']}" if package else rc["name"],
                package=package,
                file=rel,
                start_line=rc["start_line"],
                end_line=rc["end_line"],
                visibility=rc["visibility"],
                annotations=class_annotations,
                extends=rc.get("extends"),
                implements=rc.get("implements", []),
                methods=methods,
                imports=imports,
            )
            classes.append(ci)

        return classes, all_edges

    def _extract_package(self, lines: list[str]) -> str:
        """Extract the package declaration."""
        for line in lines[:30]:
            m = _PACKAGE_RE.match(line)
            if m:
                return m.group(1)
        return ""

    def _extract_imports(self, lines: list[str], rel: str) -> list[ImportInfo]:
        """Extract all import statements."""
        imports: list[ImportInfo] = []
        for lineno, line in enumerate(lines, 1):
            m = _IMPORT_RE.match(line)
            if m:
                is_static = m.group(1) is not None
                stmt = m.group(2)
                imports.append(ImportInfo(
                    statement=stmt,
                    is_static=is_static,
                    is_wildcard=stmt.endswith(".*"),
                    file=rel,
                    line=lineno,
                ))
            # Stop after we pass imports (first non-import, non-package, non-empty,
            # non-comment line after we've seen at least one import)
            stripped = line.strip()
            if (
                imports
                and stripped
                and not stripped.startswith("import ")
                and not stripped.startswith("package ")
                and not stripped.startswith("//")
                and not stripped.startswith("/*")
                and not stripped.startswith("*")
            ):
                break
        return imports

    def _collect_annotations(self, lines: list[str]) -> dict[int, list[AnnotationInfo]]:
        """Collect annotations by the line they appear on."""
        result: dict[int, list[AnnotationInfo]] = {}
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped.startswith("@"):
                continue
            for m in _ANNOTATION_RE.finditer(stripped):
                ann = AnnotationInfo(
                    name=m.group(1),
                    raw=m.group(0),
                    line=lineno,
                )
                result.setdefault(lineno, []).append(ann)
        return result

    def _get_annotations_before(
        self,
        annotations_by_line: dict[int, list[AnnotationInfo]],
        decl_line: int,
    ) -> list[AnnotationInfo]:
        """Get annotations on lines immediately preceding a declaration.

        Annotations are considered "before" if they are within 10 lines above
        the declaration and there are no blank non-annotation lines between them.
        """
        collected: list[AnnotationInfo] = []
        for offset in range(1, 11):
            check_line = decl_line - offset
            if check_line < 1:
                break
            if check_line in annotations_by_line:
                collected.extend(annotations_by_line[check_line])
            else:
                # Allow comment lines between annotations
                # but stop at a blank or code line
                break
        return list(reversed(collected))

    def _find_type_declarations(
        self,
        lines: list[str],
        full_text: str,
        rel: str,
        package: str,
    ) -> list[dict[str, Any]]:
        """Find class/interface/enum/record/@interface declarations."""
        raw_classes: list[dict[str, Any]] = []

        for m in _TYPE_DECL_RE.finditer(full_text):
            # Compute line number
            start_pos = m.start()
            start_line = full_text[:start_pos].count("\n") + 1

            visibility = m.group(1) or "package"
            kind = m.group(2)
            if kind == "@interface":
                kind = "annotation_type"
            name = m.group(3)

            # extends
            extends_raw = m.group(4)
            extends = extends_raw.strip().split(",")[0].strip() if extends_raw else None

            # implements
            impl_raw = m.group(5)
            implements: list[str] = []
            if impl_raw:
                implements = [i.strip() for i in impl_raw.split(",") if i.strip()]

            # Estimate end_line by finding matching brace
            end_line = self._find_block_end(lines, start_line)

            raw_classes.append({
                "kind": kind,
                "name": name,
                "visibility": visibility,
                "start_line": start_line,
                "end_line": end_line,
                "extends": extends,
                "implements": implements,
            })

        return raw_classes

    def _find_block_end(self, lines: list[str], start_line: int) -> int:
        """Find the closing brace of a block starting at start_line.

        Uses brace counting. Falls back to file end if not found.
        """
        depth = 0
        started = False
        for lineno in range(start_line - 1, len(lines)):
            line = lines[lineno]
            # Strip string literals and comments to avoid false brace counting
            cleaned = self._strip_strings_and_comments(line)
            for ch in cleaned:
                if ch == "{":
                    depth += 1
                    started = True
                elif ch == "}":
                    depth -= 1
                    if started and depth == 0:
                        return lineno + 1  # 1-indexed
        return len(lines)

    @staticmethod
    def _strip_strings_and_comments(line: str) -> str:
        """Remove string literals and single-line comments for brace counting."""
        # Remove string literals
        result = re.sub(r'"(?:[^"\\]|\\.)*"', '', line)
        # Remove char literals
        result = re.sub(r"'(?:[^'\\]|\\.)*'", '', result)
        # Remove single-line comments
        idx = result.find("//")
        if idx != -1:
            result = result[:idx]
        return result

    def _find_methods(
        self,
        lines: list[str],
        rel: str,
        class_info: dict[str, Any],
        annotations_by_line: dict[int, list[AnnotationInfo]],
        class_base_path: str,
    ) -> tuple[list[MethodInfo], list[CallerCalleeEdge]]:
        """Find method declarations within a class range."""
        methods: list[MethodInfo] = []
        edges: list[CallerCalleeEdge] = []
        class_name = class_info["name"]
        class_start = class_info["start_line"]
        class_end = class_info["end_line"]

        # Keywords that look like methods but aren't
        _not_methods = frozenset({
            "if", "else", "for", "while", "switch", "catch", "try",
            "return", "throw", "new", "super", "this", "assert",
            "synchronized", "do",
        })

        # Java keywords / statements that should never be a return type
        _not_return_types = frozenset({
            "return", "throw", "if", "else", "for", "while", "switch",
            "case", "catch", "try", "finally", "break", "continue",
            "do", "assert", "yield", "var",
        })

        # Scan within the class range
        for lineno in range(class_start, min(class_end + 1, len(lines) + 1)):
            line = lines[lineno - 1]
            m = _METHOD_RE.match(line)
            if not m:
                continue

            visibility = m.group(1) or "package"
            return_type = m.group(2).strip()
            method_name = m.group(3)
            parameters = m.group(4).strip()

            # Skip false positives
            if method_name in _not_methods:
                continue
            if return_type in _not_return_types:
                continue
            # Constructor check: method name matches class name and no explicit return type
            # that's valid, keep it
            if return_type == class_name and method_name == class_name:
                # This is actually a constructor; the regex grouped wrong
                # Keep it as a constructor
                return_type = ""

            # Get annotations
            method_annotations = self._get_annotations_before(
                annotations_by_line, lineno
            )

            # Extract endpoint mapping
            endpoint = self._extract_endpoint(method_annotations, class_base_path)

            # Find method end
            if line.rstrip().endswith(";"):
                # Abstract method
                end_line = lineno
            else:
                end_line = self._find_block_end(lines, lineno)

            # Extract method calls (caller/callee)
            calls = self._extract_method_calls(lines, lineno, end_line, _not_methods)

            mi = MethodInfo(
                name=method_name,
                class_name=class_name,
                file=rel,
                start_line=lineno,
                end_line=end_line,
                visibility=visibility,
                return_type=return_type,
                parameters=parameters,
                annotations=method_annotations,
                endpoint=endpoint,
                calls=calls,
            )
            methods.append(mi)

            # Create caller/callee edges
            for callee in calls:
                edges.append(CallerCalleeEdge(
                    caller_class=class_name,
                    caller_method=method_name,
                    callee_method=callee,
                    file=rel,
                    caller_line=lineno,
                ))

        return methods, edges

    def _extract_endpoint(
        self,
        annotations: list[AnnotationInfo],
        class_base_path: str,
    ) -> EndpointMapping | None:
        """Extract Spring endpoint mapping from method annotations."""
        for ann in annotations:
            if ann.name not in _ENDPOINT_ANNOTATIONS:
                continue

            default_method = _ENDPOINT_ANNOTATIONS[ann.name]

            # Extract path
            pm = _PATH_VALUE_RE.search(ann.raw)
            path = pm.group(1) if pm else ""
            full_path = (
                class_base_path.rstrip("/") + "/" + path.lstrip("/")
            ).rstrip("/") or "/"

            # Extract HTTP method
            http_method = default_method
            if http_method is None:
                mm = _METHOD_VALUE_RE.search(ann.raw)
                http_method = mm.group(1).upper() if mm else "ANY"

            return EndpointMapping(
                http_method=http_method,
                path=full_path,
                annotation=f"@{ann.name}",
            )
        return None

    def _extract_method_calls(
        self,
        lines: list[str],
        start_line: int,
        end_line: int,
        skip_keywords: frozenset[str],
    ) -> list[str]:
        """Extract method call names from a method body (best-effort)."""
        calls: set[str] = set()

        # Java keywords and built-in types that are NOT method calls
        _java_keywords = frozenset({
            "if", "else", "for", "while", "switch", "case", "catch", "try",
            "return", "throw", "new", "super", "this", "assert",
            "synchronized", "do", "finally", "break", "continue",
            "instanceof", "void", "int", "long", "float", "double",
            "boolean", "byte", "char", "short", "String", "Object",
            "class", "interface", "enum", "record", "extends", "implements",
            "import", "package", "public", "private", "protected",
            "static", "final", "abstract", "native", "volatile",
            "transient", "strictfp", "default", "null", "true", "false",
        })

        # Start from line after method declaration header
        body_start = start_line  # include the declaration line for constructor calls
        for lineno in range(body_start, min(end_line + 1, len(lines) + 1)):
            line = lines[lineno - 1]
            stripped = line.strip()

            # Skip comments
            if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
                continue

            # Find method calls
            for m in _METHOD_CALL_RE.finditer(stripped):
                name = m.group(1)
                if name not in _java_keywords and name not in skip_keywords:
                    calls.add(name)

        return sorted(calls)

    def _build_summary(
        self,
        classes: list[ClassInfo],
        edges: list[CallerCalleeEdge],
    ) -> dict[str, Any]:
        """Build summary statistics."""
        kind_counts: dict[str, int] = {}
        total_methods = 0
        total_endpoints = 0
        packages: set[str] = set()

        for c in classes:
            kind_counts[c.kind] = kind_counts.get(c.kind, 0) + 1
            total_methods += len(c.methods)
            packages.add(c.package)
            for m in c.methods:
                if m.endpoint is not None:
                    total_endpoints += 1

        return {
            "total_classes": len(classes),
            "type_counts": kind_counts,
            "total_methods": total_methods,
            "total_endpoints": total_endpoints,
            "total_caller_callee_edges": len(edges),
            "unique_packages": len(packages),
            "packages": sorted(packages),
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_serializable(obj: Any) -> Any:
    """Convert dataclasses (including nested) to dicts for JSON."""
    if hasattr(obj, "__dataclass_fields__"):
        d: dict[str, Any] = {}
        for f_name in obj.__dataclass_fields__:
            d[f_name] = _to_serializable(getattr(obj, f_name))
        return d
    if isinstance(obj, dict):
        return {k: _to_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_serializable(item) for item in obj]
    if isinstance(obj, set):
        return sorted(_to_serializable(item) for item in obj)
    return obj


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def run_indexing(
    webgoat_root: str | Path,
    output_dir: str | Path,
    exclusion_config: str | Path | None = None,
) -> JavaSymbolIndex:
    """Convenience function: index + save in one call."""
    policy = None
    if exclusion_config:
        policy = ExclusionPolicy.from_file(Path(exclusion_config))

    indexer = JavaIndexer(webgoat_root, exclusion_policy=policy)
    index = indexer.build()
    indexer.save(index, output_dir)
    return index


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Java symbol index for WebGoat (Micro-task 2.2)",
    )
    parser.add_argument(
        "--source", "-s",
        default="webgoat/WebGoat-2025.3",
        help="Path to WebGoat source root",
    )
    parser.add_argument(
        "--output", "-o",
        default="results",
        help="Output directory for symbol_index.json",
    )
    parser.add_argument(
        "--exclusions",
        default="configs/exclusions.json",
        help="Path to exclusion config JSON",
    )
    args = parser.parse_args()

    index = run_indexing(args.source, args.output, args.exclusions)
    print(f"Indexed {index.indexed_files} files "
          f"(excluded {index.excluded_files})")
    print(f"Found {index.summary.get('total_classes', 0)} classes, "
          f"{index.summary.get('total_methods', 0)} methods, "
          f"{index.summary.get('total_endpoints', 0)} endpoints")
    print(f"Caller/callee edges: {index.summary.get('total_caller_callee_edges', 0)}")
    print(f"Packages: {index.summary.get('unique_packages', 0)}")
