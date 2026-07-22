# Task 4.1–4.3 — Prompts & Security Skill Files

| Attribute | Details |
| :--- | :--- |
| **Task ID** | Task 4.1, Task 4.2, Task 4.3 |
| **Title** | Architecture Prompts, Vulnerability Class Prompts & Security Skills |
| **Status** | ✅ Complete |
| **Phase** | Phase 4: Prompts and Security Skills |
| **Date** | 2026-07-22 |

---

## 1. Objective

The objective of Phase 4 is to design and package versioned analysis prompts and security skill knowledge files for downstream model-based vulnerability investigation (Phase 6). 

Standardizing prompts and security skills guarantees consistent analysis criteria across experiments, prevents model hallucination through explicit checklist requirements, and provides reproducible prompt and skill versions/hashes.

---

## 2. Implementation Details

### 2.1 General & Architecture Prompts (Task 4.1)
Created 3 core architectural prompts in `prompts/`:

| Prompt File | Version | Purpose |
| :--- | :--- | :--- |
| **[prompts/baseline.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/prompts/baseline.md)** | `baseline-audit-v1.0` | Generic full-repository security audit prompt for Baseline Experiment A |
| **[prompts/reconnaissance.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/prompts/reconnaissance.md)** | `reconnaissance-v1.0` | Architectural reconnaissance prompt for mapping modules, trust boundaries, and endpoints |
| **[prompts/architecture-map.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/prompts/architecture-map.md)** | `architecture-map-v1.0` | Markdown rendering prompt for summary architecture maps |

### 2.2 Vulnerability Class Prompts (Task 4.2)
Created 9 vulnerability-specific and utility prompts in `prompts/`:

| Prompt File | Target Vulnerability Class | CWE | Version |
| :--- | :--- | :--- | :--- |
| **[prompts/sqli.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/prompts/sqli.md)** | SQL Injection | CWE-89 | `sqli-v1.0` |
| **[prompts/xss.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/prompts/xss.md)** | Cross-Site Scripting (Reflected/Stored/DOM) | CWE-79 | `xss-v1.0` |
| **[prompts/command-injection.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/prompts/command-injection.md)** | Command Injection / OS Execution | CWE-78 | `command-injection-v1.0` |
| **[prompts/path-traversal.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/prompts/path-traversal.md)** | Path Traversal / File Access | CWE-22 | `path-traversal-v1.0` |
| **[prompts/ssrf.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/prompts/ssrf.md)** | Server-Side Request Forgery | CWE-918 | `ssrf-v1.0` |
| **[prompts/access-control.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/prompts/access-control.md)** | Broken Access Control & IDOR | CWE-284 / CWE-639 | `access-control-v1.0` |
| **[prompts/deserialization.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/prompts/deserialization.md)** | Insecure Deserialization | CWE-502 | `deserialization-v1.0` |
| **[prompts/validation.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/prompts/validation.md)** | Independent Validation Workflow | N/A | `validation-v1.0` |
| **[prompts/deduplication.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/prompts/deduplication.md)** | Semantic Deduplication Workflow | N/A | `deduplication-v1.0` |

### 2.3 Security Skill Knowledge Files (Task 4.3)
Created 9 standardized security skill definitions under `skills/`:

| Skill Folder | Target Area | Skill Version |
| :--- | :--- | :--- |
| **[skills/sqli/SKILL.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/skills/sqli/SKILL.md)** | SQL Injection | `sqli-skill-v1.0` |
| **[skills/xss/SKILL.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/skills/xss/SKILL.md)** | Cross-Site Scripting | `xss-skill-v1.0` |
| **[skills/command-injection/SKILL.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/skills/command-injection/SKILL.md)** | Command Injection | `command-injection-skill-v1.0` |
| **[skills/path-traversal/SKILL.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/skills/path-traversal/SKILL.md)** | Path Traversal | `path-traversal-skill-v1.0` |
| **[skills/ssrf/SKILL.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/skills/ssrf/SKILL.md)** | SSRF | `ssrf-skill-v1.0` |
| **[skills/access-control/SKILL.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/skills/access-control/SKILL.md)** | Access Control & IDOR | `access-control-skill-v1.0` |
| **[skills/authentication/SKILL.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/skills/authentication/SKILL.md)** | Authentication & Session | `authentication-skill-v1.0` |
| **[skills/deserialization/SKILL.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/skills/deserialization/SKILL.md)** | Insecure Deserialization | `deserialization-skill-v1.0` |
| **[skills/business-logic/SKILL.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/skills/business-logic/SKILL.md)** | Business Logic Flaws | `business-logic-skill-v1.0` |

Each skill file is structured into 9 uniform sections: Goal, Sources, Sinks, Common Sanitizers, False Positive Patterns, Mandatory Evidence, Validation Checklist, CWE & Severity Guidance, and Output Schema Requirement.

---

## 3. Key Design Decisions

1. **Mandatory 14-Point Prompt Checklist**: Every vulnerability prompt explicitly forces the model to evaluate source, sink, data flow, controls, exploit condition, line ranges, and false positive criteria.
2. **Anti-Hallucination Directives**: Prompts explicitly forbid generating findings based on missing context, general assumptions, or lesson names alone.
3. **Explicit Version & Hash Tracking**: Comments embedded in prompt and skill headers (`<!-- prompt_version: ... -->`, `<!-- skill_version: ... -->`) are preserved and propagated to `Finding.prompt_version`.

---

## 4. Files Created / Modified

- **`prompts/`** (12 markdown files): Prompt definitions for baseline, recon, architecture, vulnerability classes, validation, and deduplication.
- **`skills/`** (9 subdirectories with `SKILL.md`): Structured security knowledge files.
- **[tests/test_prompts_and_skills.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/tests/test_prompts_and_skills.py)** — Integrity test suite.
- **[reports/phase-4/task-4.1-prompts-and-skills.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/reports/phase-4/task-4.1-prompts-and-skills.md)** — Phase 4 completion report (this file).

---

## 5. Test Results

- **Total Test Suite**: 152 tests across all modules
- **Pass Rate**: 100% (152/152 passed)
- **Prompts & Skills Integrity Tests**: 2 test classes (`test_required_prompts_exist_and_have_version`, `test_required_skills_exist_and_have_version`), 100% pass.

---

## 6. How to Verify / Test

To verify prompt and skill file presence and formatting:

```bash
python3 -m unittest tests.test_prompts_and_skills -v
```

---

## 7. Status & Conclusion

- **Status**: ✅ Complete
- **Conclusion**: Phase 4 is complete. All 12 prompt templates and 9 security skill files are established with explicit versioning and anti-hallucination checklists, ready for Phase 5 and Phase 6 harness integrations.
