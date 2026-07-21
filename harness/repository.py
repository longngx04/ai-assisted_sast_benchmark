"""Repository reconnaissance scanner for WebGoat.

Micro-task 2.1 — scans the WebGoat source tree and builds:
  * ``reconnaissance.json``  — machine-readable map of modules, components,
    endpoints, and security-relevant patterns.
  * ``architecture_map.md``  — concise human-readable summary for downstream
    prompts and agents.

The scanner is purely deterministic (no LLM calls).  It uses regex-based
heuristics on Java source files and respects the project's ExclusionPolicy.
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
class EndpointInfo:
    """A single REST or controller endpoint."""
    method: str            # HTTP method (GET, POST, PUT, DELETE, PATCH, …)
    path: str              # URL pattern
    java_method: str       # Java method name
    file: str              # relative path
    line: int              # 1-indexed line number
    annotations: list[str] # raw annotation strings


@dataclass
class ComponentInfo:
    """A Spring-managed component detected by annotation."""
    kind: str              # controller | service | repository | configuration | component
    class_name: str
    file: str
    line: int
    annotations: list[str]
    package: str


@dataclass
class SecurityPattern:
    """A security-relevant pattern found in source."""
    category: str          # e.g. "database", "deserialization", "file_handling"
    pattern: str           # regex or keyword that matched
    file: str
    line: int
    snippet: str           # the matching line (trimmed)


@dataclass
class LessonModule:
    """A WebGoat lesson/module package."""
    name: str
    package: str
    path: str
    java_files: list[str]
    file_count: int


@dataclass
class ReconnaissanceResult:
    """Top-level output of the repository scanner."""
    generated_at: str
    webgoat_root: str
    revision: str | None
    branch: str | None
    total_java_files: int
    scanned_java_files: int
    excluded_files: int

    maven_modules: list[dict[str, str]]
    lesson_modules: list[LessonModule]
    components: list[ComponentInfo]
    endpoints: list[EndpointInfo]
    security_patterns: dict[str, list[SecurityPattern]]

    # Summary counts
    summary: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Regex patterns for Java reconnaissance
# ---------------------------------------------------------------------------

# Spring component annotations
_COMPONENT_RE = re.compile(
    r'@(RestController|Controller|Service|Repository|Configuration|Component)\b',
)

# Class declaration
_CLASS_RE = re.compile(
    r'(?:public\s+)?(?:abstract\s+)?class\s+(\w+)',
)

# Package declaration
_PACKAGE_RE = re.compile(r'^package\s+([\w.]+)\s*;')

# Spring endpoint mapping annotations
_MAPPING_ANNOTATIONS = {
    "RequestMapping": None,   # method comes from annotation args
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH",
}

_MAPPING_RE = re.compile(
    r'@(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)'
    r'\s*\(([^)]*)\)',
    re.DOTALL,
)

# Extract path from mapping annotation value
_PATH_VALUE_RE = re.compile(
    r'(?:value\s*=\s*|path\s*=\s*)?["{]?\s*"([^"]*)"',
)

# Extract method from @RequestMapping(method = RequestMethod.GET)
_METHOD_VALUE_RE = re.compile(
    r'method\s*=\s*(?:RequestMethod\.)?(\w+)',
)

# Java method right after annotation
_JAVA_METHOD_RE = re.compile(
    r'(?:public|protected|private)?\s*\w[\w<>\[\], ]*\s+(\w+)\s*\(',
)

# Security-relevant patterns grouped by category
_SECURITY_PATTERNS: dict[str, list[tuple[str, re.Pattern[str]]]] = {
    "database": [
        ("JDBC/Statement", re.compile(r'(?:createStatement|prepareStatement|executeQuery|executeUpdate)\s*\(')),
        ("SQL string concat", re.compile(r'(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*\+\s*\w', re.IGNORECASE)),
        ("JPA native query", re.compile(r'(?:nativeQuery|createNativeQuery|createQuery)\s*\(')),
        ("JdbcTemplate", re.compile(r'JdbcTemplate|NamedParameterJdbcTemplate')),
        ("DriverManager", re.compile(r'DriverManager\.getConnection')),
    ],
    "deserialization": [
        ("ObjectInputStream", re.compile(r'ObjectInputStream|readObject\s*\(')),
        ("XMLDecoder", re.compile(r'XMLDecoder')),
        ("XStream", re.compile(r'XStream')),
        ("Serializable", re.compile(r'implements\s+.*Serializable')),
    ],
    "command_execution": [
        ("Runtime.exec", re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\(')),
        ("ProcessBuilder", re.compile(r'new\s+ProcessBuilder\s*\(')),
    ],
    "file_handling": [
        ("File I/O", re.compile(r'new\s+File\s*\(|Files\.\w+\s*\(|FileInputStream|FileOutputStream')),
        ("MultipartFile", re.compile(r'MultipartFile|@RequestParam.*file')),
        ("Path traversal risk", re.compile(r'\.resolve\s*\(|\.normalize\s*\(|Paths\.get\s*\(')),
        ("ZipEntry", re.compile(r'ZipEntry|ZipInputStream|ZipFile')),
    ],
    "xml_parsing": [
        ("SAXParser", re.compile(r'SAXParser|SAXParserFactory')),
        ("DocumentBuilder", re.compile(r'DocumentBuilder|DocumentBuilderFactory')),
        ("XMLReader", re.compile(r'XMLReader|XMLInputFactory')),
        ("TransformerFactory", re.compile(r'TransformerFactory')),
    ],
    "authentication": [
        ("UserDetailsService", re.compile(r'UserDetailsService|UserDetails')),
        ("PasswordEncoder", re.compile(r'PasswordEncoder|BCryptPasswordEncoder')),
        ("AuthenticationManager", re.compile(r'AuthenticationManager|AuthenticationProvider')),
        ("Login form", re.compile(r'formLogin|loginPage|loginProcessingUrl')),
    ],
    "authorization": [
        ("@PreAuthorize", re.compile(r'@PreAuthorize')),
        ("@Secured", re.compile(r'@Secured')),
        ("hasRole/hasAuthority", re.compile(r'hasRole|hasAuthority|hasAnyRole')),
        ("antMatchers/requestMatchers", re.compile(r'antMatchers|requestMatchers|authorizeRequests|authorizeHttpRequests')),
    ],
    "session": [
        ("HttpSession", re.compile(r'HttpSession|getSession\s*\(')),
        ("Cookie", re.compile(r'new\s+Cookie|addCookie|getCookies')),
        ("CSRF config", re.compile(r'csrf\(\)|CsrfToken|csrfTokenRepository')),
    ],
    "cryptography": [
        ("MessageDigest", re.compile(r'MessageDigest\.getInstance')),
        ("Cipher", re.compile(r'Cipher\.getInstance')),
        ("SecureRandom", re.compile(r'SecureRandom')),
        ("KeyGenerator", re.compile(r'KeyGenerator|KeyPairGenerator')),
        ("Hardcoded key/secret", re.compile(r'(?:password|secret|key)\s*=\s*"[^"]{3,}"', re.IGNORECASE)),
    ],
    "redirect": [
        ("sendRedirect", re.compile(r'sendRedirect\s*\(')),
        ("redirect:", re.compile(r'"redirect:')),
        ("forward:", re.compile(r'"forward:')),
        ("RedirectView", re.compile(r'RedirectView')),
    ],
    "template_rendering": [
        ("Thymeleaf", re.compile(r'th:|TemplateEngine|SpringTemplateEngine')),
        ("ModelAndView", re.compile(r'ModelAndView|addAttribute')),
    ],
    "http_client": [
        ("URLConnection", re.compile(r'URLConnection|HttpURLConnection|openConnection')),
        ("RestTemplate", re.compile(r'RestTemplate|WebClient|HttpClient')),
        ("URL constructor", re.compile(r'new\s+URL\s*\(')),
    ],
    "jwt": [
        ("JWT parsing", re.compile(r'Jwts?\.|JwtParser|JwtDecoder|JwtBuilder')),
        ("JWT token", re.compile(r'Bearer|Authorization.*token', re.IGNORECASE)),
    ],
    "logging_sensitive": [
        ("Log injection risk", re.compile(r'(?:log|logger|LOG)\.\w+\s*\(.*(?:request|param|input|user)', re.IGNORECASE)),
    ],
    "reflection": [
        ("Class.forName", re.compile(r'Class\.forName\s*\(')),
        ("Method.invoke", re.compile(r'\.invoke\s*\(')),
        ("newInstance", re.compile(r'\.newInstance\s*\(')),
    ],
}


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class RepositoryScanner:
    """Scans the WebGoat repository and produces a ReconnaissanceResult."""

    def __init__(
        self,
        webgoat_root: str | Path,
        exclusion_policy: ExclusionPolicy | None = None,
    ):
        self.root = Path(webgoat_root).resolve()
        self.policy = exclusion_policy
        self._java_files: list[Path] = []
        self._excluded_count = 0

    # -- public API ----------------------------------------------------------

    def scan(self) -> ReconnaissanceResult:
        """Run full reconnaissance and return structured results."""
        self._collect_java_files()

        maven_modules = self._find_maven_modules()
        lesson_modules = self._find_lesson_modules()
        components = self._find_components()
        endpoints = self._find_endpoints()
        security_patterns = self._find_security_patterns()

        summary = self._build_summary(
            lesson_modules, components, endpoints, security_patterns,
        )

        revision, branch = self._git_info()

        return ReconnaissanceResult(
            generated_at=datetime.now(timezone.utc).isoformat(),
            webgoat_root=str(self.root),
            revision=revision,
            branch=branch,
            total_java_files=len(self._java_files) + self._excluded_count,
            scanned_java_files=len(self._java_files),
            excluded_files=self._excluded_count,
            maven_modules=maven_modules,
            lesson_modules=lesson_modules,
            components=components,
            endpoints=endpoints,
            security_patterns=security_patterns,
            summary=summary,
        )

    def save(
        self,
        result: ReconnaissanceResult,
        output_dir: str | Path,
    ) -> tuple[Path, Path]:
        """Write ``reconnaissance.json`` and ``architecture_map.md``.

        Returns the paths to both files.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        recon_path = out / "reconnaissance.json"
        arch_path = out / "architecture_map.md"

        recon_path.write_text(
            json.dumps(_to_serializable(result), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        arch_path.write_text(
            self._render_architecture_map(result),
            encoding="utf-8",
        )
        return recon_path, arch_path

    # -- internal helpers ----------------------------------------------------

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

    # -- Maven modules -------------------------------------------------------

    def _find_maven_modules(self) -> list[dict[str, str]]:
        modules: list[dict[str, str]] = []
        for pom in sorted(self.root.rglob("pom.xml")):
            rel = self._rel(pom.parent) if pom.parent != self.root else "."
            if self.policy and self.policy.should_exclude(str(pom.relative_to(self.root))):
                continue
            # Try to extract the project's own artifactId (skip <parent> block)
            text = pom.read_text(encoding="utf-8", errors="replace")
            # Remove <parent>...</parent> so we don't pick up the parent's artifactId
            stripped = re.sub(r"<parent>.*?</parent>", "", text, flags=re.DOTALL)
            m = re.search(r"<artifactId>\s*([^<]+?)\s*</artifactId>", stripped)
            aid = m.group(1) if m else rel
            modules.append({"path": rel, "artifact_id": aid})
        return modules

    # -- Lesson modules ------------------------------------------------------

    def _find_lesson_modules(self) -> list[LessonModule]:
        lessons_root = self.root / "src" / "main" / "java" / "org" / "owasp" / "webgoat" / "lessons"
        if not lessons_root.is_dir():
            return []
        modules: list[LessonModule] = []
        for child in sorted(lessons_root.iterdir()):
            if not child.is_dir():
                continue
            java_files = [
                self._rel(f)
                for f in sorted(child.rglob("*.java"))
                if not (self.policy and self.policy.should_exclude(self._rel(f)))
            ]
            if java_files:
                pkg_base = "org.owasp.webgoat.lessons." + child.name
                modules.append(LessonModule(
                    name=child.name,
                    package=pkg_base,
                    path=self._rel(child),
                    java_files=java_files,
                    file_count=len(java_files),
                ))
        return modules

    # -- Spring components ---------------------------------------------------

    def _find_components(self) -> list[ComponentInfo]:
        components: list[ComponentInfo] = []
        for fpath in self._java_files:
            lines = self._read_lines(fpath)
            rel = self._rel(fpath)
            package = ""
            for line in lines:
                pm = _PACKAGE_RE.match(line.strip())
                if pm:
                    package = pm.group(1)
                    break

            for lineno, line in enumerate(lines, 1):
                cm = _COMPONENT_RE.search(line)
                if cm:
                    kind = cm.group(1).lower()
                    if kind == "restcontroller":
                        kind = "controller"
                    # Find class name nearby
                    class_name = ""
                    for offset in range(0, min(5, len(lines) - lineno + 1)):
                        clm = _CLASS_RE.search(lines[lineno - 1 + offset])
                        if clm:
                            class_name = clm.group(1)
                            break
                    components.append(ComponentInfo(
                        kind=kind,
                        class_name=class_name,
                        file=rel,
                        line=lineno,
                        annotations=[cm.group(0)],
                        package=package,
                    ))
        return components

    # -- Endpoints -----------------------------------------------------------

    def _find_endpoints(self) -> list[EndpointInfo]:
        endpoints: list[EndpointInfo] = []
        for fpath in self._java_files:
            lines = self._read_lines(fpath)
            rel = self._rel(fpath)
            full_text = "\n".join(lines)

            # Find class-level @RequestMapping for base path
            class_base_path = ""
            for line in lines[:50]:  # typically near top
                if "@RequestMapping" in line:
                    pm = _PATH_VALUE_RE.search(line)
                    if pm:
                        class_base_path = pm.group(1)
                    break

            for lineno, line in enumerate(lines, 1):
                for ann_name, default_method in _MAPPING_ANNOTATIONS.items():
                    if f"@{ann_name}" not in line:
                        continue
                    # Capture multiline annotation
                    ann_text = line
                    if "(" in line and ")" not in line:
                        for extra in range(1, 5):
                            if lineno - 1 + extra < len(lines):
                                ann_text += " " + lines[lineno - 1 + extra]
                                if ")" in lines[lineno - 1 + extra]:
                                    break

                    # Extract path
                    path_match = _PATH_VALUE_RE.search(ann_text)
                    path = path_match.group(1) if path_match else ""
                    full_path = (class_base_path.rstrip("/") + "/" + path.lstrip("/")).rstrip("/") or "/"

                    # Extract method
                    method = default_method
                    if method is None:
                        mm = _METHOD_VALUE_RE.search(ann_text)
                        method = mm.group(1).upper() if mm else "ANY"

                    # Find Java method name
                    java_method = ""
                    for offset in range(1, 6):
                        idx = lineno - 1 + offset
                        if idx < len(lines):
                            jm = _JAVA_METHOD_RE.search(lines[idx])
                            if jm:
                                java_method = jm.group(1)
                                break

                    endpoints.append(EndpointInfo(
                        method=method,
                        path=full_path,
                        java_method=java_method,
                        file=rel,
                        line=lineno,
                        annotations=[f"@{ann_name}"],
                    ))
        return endpoints

    # -- Security patterns ---------------------------------------------------

    def _find_security_patterns(self) -> dict[str, list[SecurityPattern]]:
        result: dict[str, list[SecurityPattern]] = {
            cat: [] for cat in _SECURITY_PATTERNS
        }
        for fpath in self._java_files:
            lines = self._read_lines(fpath)
            rel = self._rel(fpath)
            for lineno, line in enumerate(lines, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("//") or stripped.startswith("*"):
                    continue
                for category, patterns in _SECURITY_PATTERNS.items():
                    for pattern_name, regex in patterns:
                        if regex.search(stripped):
                            result[category].append(SecurityPattern(
                                category=category,
                                pattern=pattern_name,
                                file=rel,
                                line=lineno,
                                snippet=stripped[:200],
                            ))
        return result

    # -- Git info ------------------------------------------------------------

    def _git_info(self) -> tuple[str | None, str | None]:
        revision = branch = None

        # Method 1: Read .git directory directly
        git_dir = self.root / ".git"
        if git_dir.is_dir():
            try:
                head_path = git_dir / "HEAD"
                head = head_path.read_text(encoding="utf-8").strip()
                if head.startswith("ref:"):
                    ref = head.split("ref:", 1)[1].strip()
                    branch = ref.rsplit("/", 1)[-1]
                    ref_path = git_dir / ref
                    if ref_path.exists():
                        revision = ref_path.read_text(encoding="utf-8").strip()
                    else:
                        # Try packed-refs
                        packed = git_dir / "packed-refs"
                        if packed.exists():
                            for line in packed.read_text(encoding="utf-8").splitlines():
                                if line.strip().endswith(ref):
                                    revision = line.strip().split()[0]
                                    break
                else:
                    revision = head
            except OSError:
                pass

        # Method 2: Try git CLI (works when WebGoat is inside another repo)
        if revision is None:
            try:
                import subprocess
                rev_result = subprocess.run(
                    ["git", "-C", str(self.root), "rev-parse", "HEAD"],
                    capture_output=True, text=True, timeout=5,
                )
                if rev_result.returncode == 0:
                    revision = rev_result.stdout.strip()
                br_result = subprocess.run(
                    ["git", "-C", str(self.root), "branch", "--show-current"],
                    capture_output=True, text=True, timeout=5,
                )
                if br_result.returncode == 0 and br_result.stdout.strip():
                    branch = br_result.stdout.strip()
            except (OSError, subprocess.TimeoutExpired):
                pass

        return revision, branch

    # -- Summary -------------------------------------------------------------

    def _build_summary(
        self,
        lessons: list[LessonModule],
        components: list[ComponentInfo],
        endpoints: list[EndpointInfo],
        patterns: dict[str, list[SecurityPattern]],
    ) -> dict[str, Any]:
        comp_counts: dict[str, int] = {}
        for c in components:
            comp_counts[c.kind] = comp_counts.get(c.kind, 0) + 1

        pattern_counts = {cat: len(items) for cat, items in patterns.items()}

        return {
            "lesson_count": len(lessons),
            "component_counts": comp_counts,
            "endpoint_count": len(endpoints),
            "endpoint_methods": _count_values([e.method for e in endpoints]),
            "security_pattern_counts": pattern_counts,
            "total_security_patterns": sum(pattern_counts.values()),
        }

    # -- Architecture map (markdown) -----------------------------------------

    def _render_architecture_map(self, result: ReconnaissanceResult) -> str:
        lines: list[str] = []
        lines.append("# WebGoat Architecture Map")
        lines.append("")
        lines.append(f"Generated: {result.generated_at}")
        lines.append(f"Revision: {result.revision or 'unknown'}")
        lines.append(f"Branch: {result.branch or 'unknown'}")
        lines.append(f"Java files scanned: {result.scanned_java_files}"
                      f" (excluded: {result.excluded_files})")
        lines.append("")

        # Maven
        lines.append("## Maven Modules")
        lines.append("")
        for m in result.maven_modules:
            lines.append(f"- **{m['artifact_id']}** (`{m['path']}`)")
        lines.append("")

        # Lessons
        lines.append("## Lesson Modules")
        lines.append("")
        lines.append("| Module | Package | Files |")
        lines.append("|--------|---------|-------|")
        for lm in result.lesson_modules:
            lines.append(f"| {lm.name} | `{lm.package}` | {lm.file_count} |")
        lines.append("")

        # Components
        lines.append("## Spring Components")
        lines.append("")
        comp_by_kind: dict[str, list[ComponentInfo]] = {}
        for c in result.components:
            comp_by_kind.setdefault(c.kind, []).append(c)
        for kind in ("controller", "service", "repository", "configuration", "component"):
            items = comp_by_kind.get(kind, [])
            if not items:
                continue
            lines.append(f"### {kind.title()}s ({len(items)})")
            lines.append("")
            for c in items:
                lines.append(f"- `{c.class_name}` — `{c.file}:{c.line}`")
            lines.append("")

        # Endpoints
        lines.append("## REST Endpoints")
        lines.append("")
        lines.append(f"Total: {len(result.endpoints)}")
        lines.append("")
        lines.append("| Method | Path | Java Method | File | Line |")
        lines.append("|--------|------|-------------|------|------|")
        for ep in result.endpoints:
            lines.append(
                f"| {ep.method} | `{ep.path}` | `{ep.java_method}` "
                f"| `{ep.file}` | {ep.line} |"
            )
        lines.append("")

        # Security patterns
        lines.append("## Security-Relevant Patterns")
        lines.append("")
        for cat, items in result.security_patterns.items():
            if not items:
                continue
            lines.append(f"### {cat.replace('_', ' ').title()} ({len(items)} matches)")
            lines.append("")
            # Group by pattern name
            by_pattern: dict[str, list[SecurityPattern]] = {}
            for sp in items:
                by_pattern.setdefault(sp.pattern, []).append(sp)
            for pname, sps in by_pattern.items():
                files = sorted({sp.file for sp in sps})
                lines.append(f"- **{pname}** — {len(sps)} hit(s) in: "
                              + ", ".join(f"`{f}`" for f in files[:5]))
                if len(files) > 5:
                    lines.append(f"  …and {len(files) - 5} more files")
            lines.append("")

        # Summary
        lines.append("## Summary")
        lines.append("")
        s = result.summary
        lines.append(f"- Lesson modules: {s.get('lesson_count', 0)}")
        lines.append(f"- Spring components: {sum(s.get('component_counts', {}).values())}")
        for k, v in s.get("component_counts", {}).items():
            lines.append(f"  - {k}: {v}")
        lines.append(f"- REST endpoints: {s.get('endpoint_count', 0)}")
        lines.append(f"- Security patterns detected: {s.get('total_security_patterns', 0)}")
        for k, v in s.get("security_pattern_counts", {}).items():
            if v > 0:
                lines.append(f"  - {k}: {v}")
        lines.append("")

        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _count_values(values: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    return counts


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
    return obj


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def run_reconnaissance(
    webgoat_root: str | Path,
    output_dir: str | Path,
    exclusion_config: str | Path | None = None,
) -> ReconnaissanceResult:
    """Convenience function: scan + save in one call."""
    policy = None
    if exclusion_config:
        policy = ExclusionPolicy.from_file(Path(exclusion_config))

    scanner = RepositoryScanner(webgoat_root, exclusion_policy=policy)
    result = scanner.scan()
    scanner.save(result, output_dir)
    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="WebGoat repository reconnaissance")
    parser.add_argument(
        "--source", "-s",
        default="webgoat/WebGoat-2025.3",
        help="Path to WebGoat source root",
    )
    parser.add_argument(
        "--output", "-o",
        default="results",
        help="Output directory for reconnaissance.json and architecture_map.md",
    )
    parser.add_argument(
        "--exclusions",
        default="configs/exclusions.json",
        help="Path to exclusion config JSON",
    )
    args = parser.parse_args()

    result = run_reconnaissance(args.source, args.output, args.exclusions)
    print(f"Scanned {result.scanned_java_files} files "
          f"(excluded {result.excluded_files})")
    print(f"Found {len(result.endpoints)} endpoints, "
          f"{len(result.components)} components, "
          f"{len(result.lesson_modules)} lesson modules")
    print(f"Security patterns: {result.summary.get('total_security_patterns', 0)}")
