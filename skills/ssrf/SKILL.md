# Security Skill: Server-Side Request Forgery Audit (Version 1.0)

<!-- skill_version: ssrf-skill-v1.0 -->

## 1. Goal
Audit Java source code for SSRF (CWE-918).

## 2. Sources
- User-supplied URL strings, hostnames, or target endpoints

## 3. Sinks
- `new URL(userInput).openStream()`
- `HttpURLConnection.connect()`
- `RestTemplate.getForObject(userInput, ...)`
- `WebClient.get().uri(userInput)`

## 4. Common Sanitizers
- Allowlist checking against approved external domains
- IP address parsing preventing access to loopback (`127.0.0.1`, `localhost`) or internal subnets (`10.0.0.0/8`, `192.168.0.0/16`)

## 5. False Positive Patterns
- Hardcoded base URL with user input restricted to URL-encoded path component

## 6. Mandatory Evidence Required
- Outbound HTTP call snippet and URL construction source

## 7. Validation Checklist
- [ ] Can user specify full scheme/host/IP of request?
- [ ] Is internal IP validation missing?

## 8. CWE & Severity Guidance
- **CWE**: CWE-918
- **Severity**: Medium / High
- **Confidence**: 0.85+
