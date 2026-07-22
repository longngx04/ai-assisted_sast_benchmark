# Security Skill: XML External Entity Audit (Version 1.0)

<!-- skill_version: xxe-skill-v1.0 -->

## Goal
Find CWE-611 only when untrusted XML reaches a parser that permits DTD or external entity resolution.

## Required Evidence
- Untrusted XML source and parse call.
- Factory feature configuration effective for that parser instance.
- Exact code proving external entities were not disabled.

## Safe Patterns
- Disallowing DOCTYPE declarations.
- Disabling external general and parameter entities.
- Disabling XInclude and external DTD loading where supported.
