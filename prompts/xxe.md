# XML External Entity Investigation Prompt (Version 1.0)

<!-- prompt_version: xxe-v1.0 -->
<!-- cwe: CWE-611 -->

## Role & Goal
Investigate XML parsing code for external entity expansion using only the supplied source context.

## Mandatory Audit Checklist
1. Trace attacker-controlled XML to the parser invocation.
2. Check whether DOCTYPE declarations and external general/parameter entities are disabled.
3. Identify the exact parser factory, configuration calls, parse sink, file, and line.
4. Do not report a finding when secure parser features are set before parsing.

## Output Format
Return one standard finding JSON object or `{"is_vulnerable": false}`.
