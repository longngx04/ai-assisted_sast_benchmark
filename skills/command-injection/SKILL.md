# Security Skill: Command Injection Audit (Version 1.0)

<!-- skill_version: command-injection-skill-v1.0 -->

## 1. Goal
Audit Java source code for Command Injection (CWE-78) where user input is executed as part of an OS command.

## 2. Sources
- HTTP parameters, uploaded file names, user environment input

## 3. Sinks
- `Runtime.getRuntime().exec(String command)`
- `ProcessBuilder(List<String> command)` when command string includes shell invocations (`sh -c`)

## 4. Common Sanitizers
- Strict alphanumeric allowlists (`^[a-zA-Z0-9_-]+$`)
- Command argument array passing without shell expansion

## 5. False Positive Patterns
- `exec(new String[]{"/usr/bin/tool", arg})` where `arg` is passed directly without shell command interpolation

## 6. Mandatory Evidence Required
- Process creation line number and raw command string construction snippet

## 7. Validation Checklist
- [ ] Is input passed into shell or process execution context?
- [ ] Is command shell concatenation present?

## 8. CWE & Severity Guidance
- **CWE**: CWE-78
- **Severity**: High / Critical
- **Confidence**: 0.90+
