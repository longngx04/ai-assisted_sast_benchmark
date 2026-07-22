# Security Skill: Cross-Site Scripting Audit (Version 1.0)

<!-- skill_version: xss-skill-v1.0 -->

## 1. Goal
Audit Java source code for Cross-Site Scripting (CWE-79) where unencoded user input is rendered into HTML/DOM response contexts.

## 2. Sources
- HTTP request parameters, path variables, headers, and cookies
- Stored database content written by users

## 3. Sinks
- `response.getWriter().print()` / `.write()`
- Thymeleaf `th:utext` attributes
- JSP `<%= ... %>` without `<c:out>`

## 4. Common Sanitizers
- `org.springframework.web.util.HtmlUtils.htmlEscape()`
- OWASP Java Encoder `Encode.forHtml()`
- Thymeleaf default `th:text` (auto-escaped)

## 5. False Positive Patterns
- Responses with `Content-Type: application/json` where browser treats body as data
- Properly encoded text output via standard template engine directives

## 6. Mandatory Evidence Required
- Code snippet showing unescaped output stream write
- Source parameter name and line number

## 7. Validation Checklist
- [ ] Is output rendered into HTML/JS response context?
- [ ] Is HTML escaping omitted?

## 8. CWE & Severity Guidance
- **CWE**: CWE-79
- **Severity**: Medium / High
- **Confidence**: 0.85+
