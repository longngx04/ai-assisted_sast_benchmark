# Security Skill: Insecure Deserialization Audit (Version 1.0)

<!-- skill_version: deserialization-skill-v1.0 -->

## 1. Goal
Audit Java source code for Insecure Deserialization (CWE-502).

## 2. Sources
- Untrusted byte streams, Base64 parameters, XML/JSON body payloads

## 3. Sinks
- `ObjectInputStream.readObject()`
- `XMLDecoder.readObject()`
- `XStream.fromXML()`

## 4. Common Sanitizers
- Look-ahead `ValidatingObjectInputStream` enforcing class allowlists
- `XStream.addPermission()` allowlist configuration

## 5. False Positive Patterns
- Deserialization of hardcoded internal byte arrays

## 6. Mandatory Evidence Required
- Object stream initialization and `readObject()` call line number

## 7. Validation Checklist
- [ ] Is input originating from untrusted source?
- [ ] Is class filtering missing prior to `readObject()`?

## 8. CWE & Severity Guidance
- **CWE**: CWE-502
- **Severity**: Critical
- **Confidence**: 0.95+
