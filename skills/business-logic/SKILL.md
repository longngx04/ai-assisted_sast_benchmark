# Security Skill: Business Logic Audit (Version 1.0)

<!-- skill_version: business-logic-skill-v1.0 -->

## 1. Goal
Audit Java source code for Business Logic Flaws (CWE-840) such as parameter tampering, race conditions, and workflow bypasses.

## 2. Sources
- Price fields, step counters, state parameters, transaction amounts

## 3. Sinks
- Financial calculation methods, state transition methods, checkout logic

## 4. Common Sanitizers
- Server-side state validation against database rather than client-supplied parameters
- Transactional locking (`@Transactional`, mutexes)

## 5. False Positive Patterns
- Client parameters strictly re-validated against database state before execution

## 6. Mandatory Evidence Required
- Code snippet demonstrating flawed state machine or client-controlled parameter trust

## 7. Validation Checklist
- [ ] Is critical business decision trusting client-controlled parameter?
- [ ] Is server-side re-validation missing?

## 8. CWE & Severity Guidance
- **CWE**: CWE-840
- **Severity**: High
- **Confidence**: 0.80+
