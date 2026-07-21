# PLAN.md — Kế hoạch hoàn thiện AI-assisted SAST Benchmark cho WebGoat

## 1. Tóm tắt mục tiêu

Xây dựng một harness có khả năng:

- Quét source WebGoat bằng `gemini-2.5-flash`.erability candidate bằng deterministic analysis trước khi
- Phát hiện vuln gọi model.
- Điều tra theo context có chọn lọc, không gửi toàn bộ repository vào một prompt.
- Validate độc lập, deduplicate và chuẩn hóa finding.
- Xuất `findings.jsonl`, `llm_usage.jsonl`, `metrics.json`.
- Chạy và so sánh tối thiểu bốn experiment.
- Tạo ground truth cục bộ, ước lượng precision và sinh ~~~~`reports/benchmark.md`.
- Có test, logging, cache, retry, resume và hướng dẫn tái lập.

Workspace hiện chỉ có `CONTEXT.md` và các thư mục rỗng. Vì vậy cần một phase bootstrap trước khi triển khai scanner.

## 2. Quy ước thư mục và giả định

Đặt source WebGoat tại:

```text
webgoat/WebGoat-2025.3/
```

Source WebGoat phải được giữ nguyên, không sửa trực tiếp. Nếu source được đặt ở vị trí khác, dùng biến cấu hình `WEBGOAT_ROOT`.

Cấu trúc đích:

```text
harness/
  __init__.py
  runner.py
  config.py
  repository.py
  indexer.py
  candidate_finder.py
  context_builder.py
  model_client.py
  investigator.py
  validator.py
  deduplicator.py
  normalizer.py
  metrics.py
  cache.py
  logging_utils.py
  schemas.py

prompts/
  baseline.md
  reconnaissance.md
  architecture-map.md
  sqli.md
  xss.md
  command-injection.md
  path-traversal.md
  ssrf.md
  access-control.md
  deserialization.md
  validation.md
  deduplication.md

skills/
  sqli/
  xss/
  command-injection/
  path-traversal/
  ssrf/
  access-control/
  authentication/
  deserialization/
  business-logic/

scripts/
  run_scan.sh
  convert_to_jsonl.py
  validate_jsonl.py
  validate_findings.py
  deduplicate_findings.py
  summarize_results.py

configs/
  baseline.yaml
  vulnerability_specific.yaml
  indexed.yaml
  optimized.yaml

ground_truth/
  webgoat_ground_truth.jsonl

results/
  exp-a-baseline/
  exp-b-vuln-prompts/
  exp-c-indexed/
  exp-d-optimized/

reports/
  benchmark.md
  comparison.csv

tests/
README.md
```

Thư mục hiện tại có tên `promts/`; nên tạo `prompts/` đúng chính tả. Có thể giữ `promts/` làm compatibility alias nhưng không dùng làm thư mục chính.

### Quy tắc offline

- Không dùng Internet để tải WebGoat, dependency, tài liệu hoặc ground truth.
- Chỉ sử dụng source và dependency đã có trong máy.
- Nếu Gemini được gọi qua provider API, chỉ cho phép endpoint đã được cấu hình; không dùng web browsing.
- Nếu môi trường hoàn toàn offline, chạy mock/recorded model adapter và ghi rõ trong metrics rằng model response là mock.
- Không log API key, credential hoặc secret.

---



## Phase 0 — Bootstrap và xác nhận môi trường



### Micro-task 0.1 — Đưa WebGoat vào workspace

Thực hiện:

1. Tạo thư mục `webgoat/` ở repository root.
2. Giải nén hoặc copy source WebGoat vào đó.
3. Không sửa source WebGoat.
4. Kiểm tra source có `pom.xml`, module Java và các package chính.
5. Ghi lại revision nếu source là Git checkout.

Kiểm tra:

```bash
find webgoat -maxdepth 2 -type f | sort | sed -n '1,100p'
test -f webgoat/pom.xml
```

Lý do: scanner cần một source root ổn định và phải phân biệt source sản phẩm với code harness.

### Micro-task 0.2 — Kiểm tra runtime

Ghi nhận:

```bash
python3 --version
java -version
mvn -version
git --version
```

Kiểm tra khả năng build WebGoat ở chế độ offline:

```bash
cd webgoat
mvn -o -DskipTests compile
```

Nếu build offline thất bại do thiếu dependency:

- Không tự tải dependency.
- Ghi lỗi vào `README.md` và `reports/benchmark.md`.
- Vẫn chạy static scan trên source hiện có.
- Đánh dấu limitation trong metrics.

Lý do: build giúp xác nhận cấu trúc project nhưng không được phép phá vỡ ràng buộc không Internet.

### Micro-task 0.3 — Ghi metadata repository

Tạo `results/repository_manifest.json` gồm:

- absolute path;
- source revision/commit nếu có;
- branch;
- số file Java;
- số dòng code;
- module;
- package;
- framework;
- test path;
- dependency path;
- generated/build path bị loại trừ.

Dùng Python hoặc shell để đếm, không ước lượng thủ công.

Lý do: mọi experiment phải chạy trên cùng revision và có thể tái lập.

### Micro-task 0.4 — Xác định dependency và generated code

Tạo exclusion mặc định cho:

```text
target/
build/
.gradle/
node_modules/
vendor/
generated/
*.class
```

Không loại trừ test nếu test chứa evidence về vulnerability. Ghi rõ lý do loại trừ từng thư mục.

---



## Phase 1 — Thiết kế schema và contract



### Micro-task 1.1 — Định nghĩa finding schema

Tạo dataclass hoặc JSON schema cho các field:

- `finding_id`;
- `experiment_id`;
- `tool`;
- `harness_version`;
- `model`;
- `prompt_version`;
- `vulnerability_type`;
- `cwe`;
- `severity`;
- `confidence`;
- `file`;
- `start_line`;
- `end_line`;
- `function`;
- `source`;
- `sink`;
- `data_flow`;
- `description`;
- `evidence`;
- `attack_scenario`;
- `security_control`;
- `recommendation`;
- `validation_status`;
- `validator`;
- `validator_confidence`;
- `duplicate_of`;
- `notes`.

Enum bắt buộc:

```text
severity:
critical, high, medium, low, informational

validation_status:
unvalidated, validated, rejected, uncertain
```

Lý do: schema ổn định là điều kiện để so sánh experiment và chuyển đổi format.

### Micro-task 1.2 — Quy định normalization

- File path tương đối với `WEBGOAT_ROOT`.
- Line number là số nguyên dương hoặc `null` nếu model không chỉ ra được.
- Confidence nằm trong `[0, 1]`.
- Field thiếu dùng `null`, `""` hoặc `[]` theo một quy ước duy nhất.
- Finding ID sinh deterministic từ experiment, file, line, CWE và normalized type.
- Evidence raw phải được giữ lại.



### Micro-task 1.3 — Định nghĩa validator contract

Validator trả về:

```json
{
  "status": "validated|rejected|uncertain",
  "confidence": 0.0,
  "reason": "string",
  "missing_evidence": [],
  "recommended_manual_check": "string"
}
```

Validator phải nhận finding cùng code context, caller/callee và attack scenario; không được chỉ đọc description.

---



## Phase 2 — Xây repository reconnaissance và indexing



### Micro-task 2.1 — Repository scanner

Implement `harness/repository.py` để:

- liệt kê module;
- nhận diện Maven module;
- phát hiện controller, service, repository/data-access;
- tìm endpoint REST/WebSocket;
- nhận diện authentication, authorization, session;
- phát hiện file upload, template, database, command execution;
- bỏ qua generated/build/dependency theo config.

Output:

```text
results/<experiment-id>/reconnaissance.json
results/<experiment-id>/architecture_map.md
```

Lý do: architecture map giúp các prompt sau có context chính xác và giảm token.

### Micro-task 2.2 — Java symbol index

Implement `harness/indexer.py` với mức tối thiểu:

- class;
- interface;
- method;
- package;
- annotations;
- file/line range;
- imports;
- method calls nếu xác định được;
- endpoint mapping;
- caller/callee đơn giản.

Ưu tiên parser có sẵn trong môi trường. Nếu không có AST parser, dùng Java-aware regex có giới hạn và ghi rõ limitation.

Không gửi cả repository vào model.

### Micro-task 2.3 — Context retrieval

Implement `context_builder.py` để tạo context theo candidate:

- function chứa sink;
- function chứa source;
- enclosing class;
- caller/callee gần nhất;
- endpoint hoặc route;
- relevant configuration;
- architecture summary;
- test/fixture liên quan nếu có.

Giới hạn context bằng token/character budget cấu hình được.

Test cần kiểm tra context không vượt budget và luôn giữ file/line.

---



## Phase 3 — Deterministic candidate discovery



### Micro-task 3.1 — Xây source/sink rules

Implement rule finder cho tối thiểu:

- SQL/JDBC/JPA native query;
- string concatenation vào query;
- HTML/template output;
- redirect;
- file path/read/write/upload;
- process/runtime/shell command;
- URL/HTTP client;
- XML parser;
- deserialization;
- reflection/class loading;
- authentication/authorization checks;
- session/cookie/CSRF;
- cryptographic primitive;
- hardcoded secret;
- logging sensitive data.

Mỗi candidate phải chứa:

```json
{
  "candidate_id": "...",
  "category": "...",
  "file": "...",
  "line": 0,
  "symbol": "...",
  "matched_rule": "...",
  "context_refs": []
}
```

Lý do: deterministic prefilter giúp giảm model calls và tăng khả năng tái lập.

### Micro-task 3.2 — Early rejection

Loại hoặc hạ ưu tiên candidate nếu:

- input là constant;
- query đã parameterized;
- output đã encode đúng;
- authorization đã enforce;
- sink không reachable;
- code chỉ là generated/build;
- không có source hoặc data-flow evidence.

Không tự động kết luận candidate là vulnerability.

### Micro-task 3.3 — Candidate report

Sinh:

```text
results/<experiment-id>/candidates.jsonl
```

Kiểm tra:

```bash
python scripts/validate_jsonl.py results/<experiment-id>/candidates.jsonl
```

---



## Phase 4 — Prompt và security skills



### Micro-task 4.1 — Prompt reconnaissance/architecture

Prompt phải yêu cầu model:

- xác định module;
- xác định trust boundary;
- xác định endpoint;
- xác định data store;
- xác định security control;
- chỉ dựa trên source evidence.



### Micro-task 4.2 — Prompt theo vulnerability class

Tạo prompt cho SQLi, XSS, command injection, path traversal, SSRF, access control, deserialization và các class có evidence trong WebGoat.

Mỗi prompt phải yêu cầu:

1. attacker-controlled source;
2. sink;
3. data flow;
4. validation/sanitization/encoding;
5. authorization/authentication;
6. exploit condition;
7. file và line;
8. code evidence;
9. CWE;
10. severity;
11. confidence;
12. attack scenario;
13. false-positive rationale;
14. không xuất finding nếu thiếu evidence.



### Micro-task 4.3 — Security skill files

Mỗi skill phải có:

- mục tiêu;
- source;
- sink;
- sanitizer phổ biến;
- false-positive pattern;
- evidence bắt buộc;
- validation checklist;
- CWE;
- severity guidance;
- output requirements.

Gắn version hoặc hash cho từng prompt/skill.

Lý do: prompt versioning giúp benchmark không bị nhiễu do thay đổi prompt giữa các run.

---



## Phase 5 — Model adapter và instrumentation



### Micro-task 5.1 — Provider adapter

Implement `harness/model_client.py` với interface:

```python
analyze(
    prompt: str,
    model: str,
    experiment_id: str,
    phase: str,
    metadata: dict
) -> ModelResponse
```

Hỗ trợ:

- model configurable;
- timeout;
- retry giới hạn;
- exponential backoff;
- malformed response;
- cache;
- dry-run/mock;
- raw response storage.

Model mặc định:

```text
gemini-2.5-flash
```

Không hardcode API key.

### Micro-task 5.2 — Token và latency instrumentation

Mỗi model call ghi vào:

```text
results/<experiment-id>/llm_usage.jsonl
```

Field tối thiểu:

- request ID;
- model;
- phase;
- agent;
- input tokens;
- output tokens;
- cached tokens;
- reasoning tokens;
- total tokens;
- latency;
- retry count;
- measurement type.

`token_measurement` phải là một trong:

```text
provider
tokenizer_estimate
character_estimate
mock
```

Nếu provider không trả usage, dùng estimator và ghi rõ, không trình bày như token thật.

### Micro-task 5.3 — Cache

Cache key gồm:

- source/file hash;
- prompt version;
- model;
- analysis type;
- relevant context hash.

Không dùng cache nếu source, prompt hoặc model thay đổi.

---



## Phase 6 — Investigation và validation workflow



### Micro-task 6.1 — Investigation agent

Implement workflow:

```text
candidate
→ context retrieval
→ vulnerability-specific prompt
→ model response
→ schema normalization
→ unvalidated finding
```

Model phải trả JSON object hoặc JSON array hợp lệ. Nếu malformed:

- lưu raw response;
- thử repair tối đa một lần;
- nếu vẫn lỗi, ghi error và không tạo finding giả.



### Micro-task 6.2 — Independent validator

Validator phải:

- đọc source/callee/caller;
- kiểm tra source-to-sink;
- kiểm tra reachability;
- kiểm tra sanitizer/authorization;
- kiểm tra attack scenario;
- trả validated/rejected/uncertain;
- ghi reason và missing evidence.

Nếu không có model judge mạnh hơn, dùng Gemini với prompt validator độc lập và gọi kết quả là `estimated precision`.

### Micro-task 6.3 — Validation output

Sinh:

```text
validated_findings.jsonl
rejected_findings.jsonl
uncertain_findings.jsonl
```

Không tính rejected/uncertain là true positive.

---



## Phase 7 — Deduplication và normalization



### Micro-task 7.1 — Dedup key

Deduplicate theo kết hợp:

- vulnerability type;
- CWE;
- file;
- function;
- line range;
- source;
- sink;
- semantic similarity của evidence/description.

Không deduplicate chỉ theo description.

### Micro-task 7.2 — Chọn finding đại diện

Ưu tiên finding có:

1. validation đầy đủ hơn;
2. evidence cụ thể hơn;
3. confidence cao hơn;
4. line chính xác hơn;
5. data-flow rõ hơn.

Finding bị gộp phải giữ `duplicate_of` hoặc mapping file.

### Micro-task 7.3 — Final findings

Sinh:

```text
results/<experiment-id>/findings.jsonl
```

Đây là output chính bắt buộc của mỗi experiment.

Kiểm tra:

```bash
python scripts/validate_jsonl.py results/<experiment-id>/findings.jsonl
python scripts/validate_findings.py results/<experiment-id>/findings.jsonl
```

---



## Phase 8 — Converter và validators



### Micro-task 8.1 — SARIF/JSON converter

Implement:

```bash
python scripts/convert_to_jsonl.py \
  --input results/raw/results.sarif \
  --format sarif \
  --output results/exp-c-indexed/findings.jsonl
```

Converter phải:

- parse SARIF/JSON;
- map severity;
- map rule/CWE;
- normalize path;
- normalize line;
- tạo finding ID;
- giữ raw evidence;
- loại field không serializable;
- báo lỗi rõ ràng.



### Micro-task 8.2 — JSONL validator

Kiểm tra:

- từng dòng là JSON object;
- required fields;
- enum;
- confidence;
- line number;
- duplicate finding ID;
- path relative;
- không có JSON array bọc ngoài.



### Micro-task 8.3 — Dedup CLI

Implement:

```bash
python scripts/deduplicate_findings.py \
  --input results/exp-b-vuln-prompts/raw_findings.jsonl \
  --output results/exp-b-vuln-prompts/findings.jsonl
```

---



## Phase 9 — Ground truth cục bộ



### Micro-task 9.1 — Trích xuất ground truth

Dựa trên:

- source WebGoat;
- lesson/module metadata;
- test;
- expected solution;
- local fixture;
- commit history nếu có sẵn.

Không dùng tên lesson làm bằng chứng duy nhất.

### Micro-task 9.2 — Ground truth schema

Mỗi record:

```json
{
  "lesson": "...",
  "module": "...",
  "vulnerability_type": "...",
  "cwe": "...",
  "relevant_files": [],
  "expected_vulnerable_behavior": "...",
  "validation_evidence": "...",
  "confidence": 0.0
}
```



### Micro-task 9.3 — Mapping finding-ground truth

Mapping phải dựa trên:

- code path;
- file/line;
- behavior;
- source/sink;
- security invariant.

Nếu chỉ khớp tên vulnerability nhưng không khớp code path, đánh dấu uncertain.

---



## Phase 10 — Experiment matrix

Chạy tối thiểu bốn experiment trên cùng source revision.

### Experiment A — Baseline

- harness đơn giản;
- prompt audit tổng quát;
- Gemini 2.5 Flash;
- không validator độc lập;
- context giới hạn;
- JSONL output.



### Experiment B — Vulnerability-specific

- chia theo vulnerability class;
- prompt chuyên biệt;
- self-validation;
- context có chọn lọc;
- dedup.



### Experiment C — Indexed

- symbol index;
- architecture map;
- source/sink candidate discovery;
- cross-file context;
- independent validation.



### Experiment D — Optimized

- cấu hình tốt nhất từ A-C;
- deterministic prefilter;
- parallel analysis có giới hạn;
- context cache;
- independent validation;
- dedup semantic;
- retry/resume;
- đầy đủ metrics.

Mỗi experiment phải lưu:

```text
config.yaml
run.log
findings.jsonl
validated_findings.jsonl
rejected_findings.jsonl
uncertain_findings.jsonl
llm_usage.jsonl
metrics.json
```

Không đổi prompt trong cùng experiment. Nếu đổi prompt, tăng version và tạo experiment ID mới.

---



## Phase 11 — Metrics và reporting



### Micro-task 11.1 — Phase timing

Đo bằng monotonic clock:

- reconnaissance;
- indexing;
- candidate discovery;
- investigation;
- validation;
- deduplication;
- reporting;
- tổng wall-clock duration.



### Micro-task 11.2 — Metrics calculation

Tính:

- raw findings;
- duplicate count;
- unique findings;
- validated;
- true positives;
- false positives;
- uncertain;
- estimated precision;
- findings/minute;
- validated findings/100K tokens;
- TP/100K tokens;
- duplicate rate;
- rejection rate;
- retry/error rate;
- average latency;
- cache hit rate.

Không đủ dữ liệu thì ghi `null`, kèm lý do.

### Micro-task 11.3 — Benchmark report

Tạo `reports/benchmark.md`, gồm:

1. Executive summary.
2. Scope và assumptions.
3. Environment.
4. WebGoat revision.
5. Harness/prompt/skill.
6. Methodology.
7. Schema.
8. Validation.
9. Ground truth.
10. Experiment matrix.
11. Metrics comparison.
12. Precision.
13. Runtime/token.
14. False positives.
15. Missed findings.
16. Limitations.
17. Best configuration.
18. Next improvements.

Bảng tối thiểu:


| Experiment | Harness | Prompt | Raw | Unique | Validated | TP  | FP  | Uncertain | Precision | Time | Tokens |
| ---------- | ------- | ------ | --- | ------ | --------- | --- | --- | --------- | --------- | ---- | ------ |


Kết luận phải tách riêng:

- nhiều raw findings nhất;
- nhiều unique findings nhất;
- nhiều validated findings nhất;
- nhiều true positives nhất;
- precision cao nhất;
- nhanh nhất;
- tiết kiệm token nhất;
- cân bằng tốt nhất.

---



## Phase 12 — Testing



### Micro-task 12.1 — Unit tests

Viết test cho:

- JSONL serialization;
- severity normalization;
- CWE normalization;
- path normalization;
- finding ID;
- deduplication;
- metric calculation;
- token aggregation;
- malformed model output;
- missing field;
- invalid confidence;
- duplicate ID;
- SARIF conversion.

Chạy:

```bash
python -m pytest -q
```

Nếu chưa có pytest:

```bash
python -m unittest discover -s tests -v
```



### Micro-task 12.2 — Fixture end-to-end

Tạo fixture Java nhỏ với ít nhất:

- SQL injection rõ ràng;
- safe parameterized query;
- reflected XSS hoặc path traversal;
- false positive có sanitizer.

Chạy mock adapter để test:

```bash
python -m harness.runner \
  --config configs/baseline.yaml \
  --source tests/fixtures/webgoat-mini \
  --model mock
```

Kỳ vọng:

- vulnerable fixture được phát hiện;
- safe fixture không bị báo;
- false positive bị rejected/uncertain;
- output parse được.



### Micro-task 12.3 — Integration test

Chạy pipeline trên một module nhỏ trước toàn WebGoat:

```bash
python -m harness.runner \
  --config configs/optimized.yaml \
  --source webgoat/<module> \
  --experiment-id exp-smoke
```

Sau đó validate:

```bash
python scripts/validate_jsonl.py results/exp-smoke/findings.jsonl
python scripts/validate_findings.py results/exp-smoke/findings.jsonl
python scripts/summarize_results.py results/exp-smoke
```



### Micro-task 12.4 — Full scan acceptance test

Chỉ chạy full scan sau khi smoke test đạt:

```bash
bash scripts/run_scan.sh --experiment exp-d-optimized
```

Acceptance:

- process exit code 0;
- có `findings.jsonl`;
- mọi dòng parse được;
- có `metrics.json`;
- có `llm_usage.jsonl`;
- không lộ secret;
- source WebGoat không bị sửa;
- report sinh thành công.

---



## Phase 13 — Reproducibility và README

README phải hướng dẫn:

- yêu cầu môi trường;
- đặt source WebGoat ở đâu;
- cấu hình `WEBGOAT_ROOT`;
- cấu hình Gemini;
- chạy mock/offline;
- chạy từng experiment;
- resume;
- timeout/concurrency/retry;
- validate JSONL;
- đọc metrics;
- sinh report;
- limitation;
- không ghi API key vào source.

Mỗi run phải lưu:

- command;
- config;
- model;
- prompt/skill version;
- source revision;
- timestamp;
- concurrency;
- timeout;
- retry policy;
- runtime version;
- warning/error;
- seed nếu có.

---



## Phase 14 — Final review và bàn giao



### Checklist bắt buộc

- [ ] WebGoat source được xác định và giữ nguyên.
- [ ] Có harness chạy được.
- [ ] Có Gemini adapter dùng `gemini-2.5-flash`.
- [ ] Có mock adapter để test offline.
- [ ] Có deterministic candidate discovery.
- [ ] Có context retrieval.
- [ ] Có validation workflow.
- [ ] Có deduplication.
- [ ] Có `findings.jsonl`.
- [ ] Có runtime metrics.
- [ ] Có token metrics và measurement type.
- [ ] Có ít nhất hai experiment, mục tiêu là bốn.
- [ ] Có ground truth cục bộ hoặc limitation rõ ràng.
- [ ] Có `reports/benchmark.md`.
- [ ] Có README tái lập.
- [ ] Unit/integration tests pass.
- [ ] Không có secret trong log/output.
- [ ] JSONL không có duplicate ID.
- [ ] Source WebGoat không bị chỉnh sửa.



### Lệnh kiểm tra cuối

```bash
python -m pytest -q
python scripts/validate_jsonl.py results/exp-d-optimized/findings.jsonl
python scripts/validate_findings.py results/exp-d-optimized/findings.jsonl
python scripts/summarize_results.py results/exp-d-optimized
git diff -- webgoat
```

Nếu WebGoat không phải Git checkout, dùng checksum hoặc snapshot manifest để xác nhận source không đổi.

## 3. Các điểm cần lưu ý quan trọng

- Không xem mọi source/sink match là vulnerability.
- Không dùng tên lesson làm bằng chứng duy nhất.
- Finding phải có source, sink, flow/control, file, line, evidence và attack scenario.
- `uncertain` không được tính vào mẫu số precision chính.
- Precision từ LLM judge phải gọi là `estimated precision`.
- Token estimate phải được đánh dấu rõ.
- Không gửi toàn repository vào một prompt.
- Không dùng Internet để bổ sung ground truth hoặc dependency.
- Không đánh đổi precision để lấy raw finding count.
- Không tự động xem dependency CVE là finding nếu thiếu version/effect evidence.
- Nếu Gemini endpoint không khả dụng, pipeline phải fail rõ ràng hoặc chuyển sang mock; không tạo số liệu giả.
- Mọi số liệu benchmark phải được đo thực tế hoặc ghi rõ là estimate.



## 4. Tiêu chí hoàn thành cuối cùng

Task được xem là hoàn thành khi:

1. Có ít nhất một full scan WebGoat chạy được.
2. Có `results/<experiment-id>/findings.jsonl` parse hợp lệ.
3. Có runtime, token và call metrics.
4. Có validation và deduplication.
5. Có tối thiểu hai experiment có thể so sánh.
6. Có report benchmark.
7. Có test và README tái lập.
8. Có limitation và evidence trail rõ ràng.
9. Kết luận chỉ dựa trên số liệu thực tế, không bịa precision, recall, token hoặc true positive.

