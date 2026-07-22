# Security Skill: Access Control & IDOR Audit (Version 1.0)

<!-- skill_version: access-control-skill-v1.0 -->

## 1. Goal
Audit Java source code for Broken Access Control (CWE-284, CWE-639).

## 2. Sources
- HTTP parameters containing target object IDs (e.g. `accountNumber`, `userId`)
- Unauthenticated REST endpoint mappings

## 3. Sinks
- Direct database query or record fetch using user-supplied ID without session user ownership verification
- Missing `@PreAuthorize` / `@Secured` annotations on privileged admin methods

## 4. Common Sanitizers
- Session-based user verification (`if (!record.getOwnerId().equals(currentUser.getId())) throw ...`)
- Method security annotations enforcing role checks (`@PreAuthorize("hasRole('ADMIN')")`)

## 5. False Positive Patterns
- Intentionally public endpoints (e.g. user registration, lesson intro)

## 6. Mandatory Evidence Required
- Endpoint mapping line and missing check rationale

## 7. Validation Checklist
- [ ] Is endpoint accessible by lower-privileged or unauthenticated users?
- [ ] Is object ownership validation absent?

## 8. CWE & Severity Guidance
- **CWE**: CWE-284 / CWE-639
- **Severity**: High
- **Confidence**: 0.85+
