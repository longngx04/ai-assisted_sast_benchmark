# Security Skill: Path Traversal Audit (Version 1.0)

<!-- skill_version: path-traversal-skill-v1.0 -->

## 1. Goal
Audit Java source code for Path Traversal / Arbitrary File Access (CWE-22).

## 2. Sources
- User-supplied file names, path parameters, uploaded filename (`MultipartFile.getOriginalFilename()`)

## 3. Sinks
- `new File(base, userInput)`
- `FileInputStream`, `FileOutputStream`, `Paths.get()`
- `ZipEntry.getName()` during archive extraction

## 4. Common Sanitizers
- `File.getCanonicalPath()` verification against base directory path prefix (`canonicalPath.startsWith(baseCanonicalPath)`)
- Path normalization and stripping of `../` sequences

## 5. False Positive Patterns
- File path restricted to hardcoded resource directory using allowlisted key lookup

## 6. Mandatory Evidence Required
- File instantiation code snippet and path parameter source

## 7. Validation Checklist
- [ ] Can user input contain `../` sequences?
- [ ] Is canonical path prefix check absent?

## 8. CWE & Severity Guidance
- **CWE**: CWE-22
- **Severity**: High
- **Confidence**: 0.85+
