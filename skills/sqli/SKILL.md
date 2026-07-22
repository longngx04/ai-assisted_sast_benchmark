# Security Skill: SQL Injection Audit (Version 1.0)

<!-- skill_version: sqli-skill-v1.0 -->
<!-- skill_hash: a1b2c3d4e5f6 -->

## 1. Goal
Audit Java source code for SQL Injection vulnerabilities (CWE-89), where untrusted input alters the structure of SQL commands executed against database management systems.

## 2. Sources
- HTTP request parameters (`@RequestParam`, `@PathVariable`, `HttpServletRequest.getParameter()`)
- HTTP headers (`@RequestHeader`)
- Unsanitized JSON/XML body fields (`@RequestBody`)

## 3. Sinks
- `java.sql.Statement.executeQuery(String sql)`
- `java.sql.Statement.executeUpdate(String sql)`
- `java.sql.Statement.execute(String sql)`
- `javax.persistence.EntityManager.createNativeQuery(String sql)`
- `org.springframework.jdbc.core.JdbcTemplate` raw query methods with concatenated SQL

## 4. Common Sanitizers / Safe Patterns
- `java.sql.PreparedStatement` with `?` parameter placeholders
- Named parameter queries (`:username`) with `Query.setParameter()`
- Numeric type casting (`Integer.parseInt()`, `Long.parseLong()`) prior to query assembly
- Allowlist validation against fixed sets of column names or table names

## 5. False Positive Patterns
- Concatenation of compile-time `final static` SQL constants
- Schema/table name parameters derived from internal constants
- Prepared statements where parameters are passed via `stmt.setString(1, param)`

## 6. Mandatory Evidence Required
- Exact file path and line number of the SQL query string creation or execution
- Code snippet demonstrating string concatenation or raw formatting
- Attacker-controllable parameter name

## 7. Validation Checklist
- [ ] Is input originating from an external untrusted source?
- [ ] Is the input concatenated into a SQL command string without escaping or binding?
- [ ] Is there an absence of `PreparedStatement` binding?
- [ ] Is the database call reachable during normal application workflow?

## 8. CWE & Severity Guidance
- **CWE**: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
- **Severity**: High (or Critical if database administrative privileges or data extraction is possible)
- **Confidence**: 0.90+ for raw concatenation into `Statement.executeQuery`

## 9. Output Schema Requirement
Outputs must be normalized `Finding` objects adhering to `harness/schemas.py`.
