# Security Skill: Authentication Audit (Version 1.0)

<!-- skill_version: authentication-skill-v1.0 -->

## 1. Goal
Audit Java source code for Authentication Bypass and Session Management Issues (CWE-287, CWE-384).

## 2. Sources
- Cookies, JWT headers, authentication request bodies

## 3. Sinks
- Custom authentication filter logic bypassing Spring Security
- Hardcoded credentials or JWT secret keys
- Insecure password storage (e.g. plain text or plain MD5)

## 4. Common Sanitizers
- `BCryptPasswordEncoder` / `Argon2PasswordEncoder`
- Standard Spring Security `AuthenticationManager`

## 5. False Positive Patterns
- Test mocks using dummy credentials

## 6. Mandatory Evidence Required
- Code snippet showing custom auth flaw or weak password encoder initialization

## 7. Validation Checklist
- [ ] Are passwords stored without strong salt/hashing?
- [ ] Is session identifier predictable or exposed?

## 8. CWE & Severity Guidance
- **CWE**: CWE-287 / CWE-384
- **Severity**: High / Critical
- **Confidence**: 0.85+
