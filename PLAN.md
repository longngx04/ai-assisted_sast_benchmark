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

**Chức năng:** Chuẩn bị một bản source WebGoat đầy đủ tại vị trí cố định để harness có đầu vào thống nhất cho việc lập chỉ mục, quét và kiểm thử.

**Mục đích:** Scanner chỉ cho kết quả đáng tin cậy khi biết chính xác source root và không trộn code của ứng dụng với code của harness. Giữ nguyên source cũng giúp chứng minh các experiment đều phân tích cùng một đối tượng.

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

### Micro-task 0.2 — Kiểm tra runtime

**Chức năng:** Xác nhận các công cụ cần thiết như Python, Java, Maven và Git đang có sẵn, đồng thời kiểm tra WebGoat có thể compile với dependency cục bộ hay không.

**Mục đích:** Việc này phát hiện sớm giới hạn của môi trường để không nhầm lỗi thiếu runtime/dependency với lỗi của scanner. Build offline còn giúp kiểm chứng cấu trúc project mà vẫn tuân thủ yêu cầu không tải thêm dữ liệu từ Internet.

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

### Micro-task 0.3 — Ghi metadata repository

**Chức năng:** Tạo manifest mô tả chính xác phiên bản source, cấu trúc module, quy mô code và các đường dẫn được dùng hoặc bị loại khỏi quá trình quét.

**Mục đích:** Manifest là dấu vết để tái lập benchmark và đối chiếu công bằng giữa các experiment. Nếu kết quả khác nhau, metadata giúp xác định nguyên nhân có phải do source hoặc phạm vi quét đã thay đổi hay không.

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

### Micro-task 0.4 — Xác định dependency và generated code

**Chức năng:** Thiết lập quy tắc loại trừ các thư mục build, dependency và code sinh tự động không thuộc source cần đánh giá.

**Mục đích:** Các file này thường lặp lại, nhiễu hoặc không do đội dự án trực tiếp quản lý; đưa chúng vào sẽ làm tăng thời gian, token và false positive. Việc không loại test một cách máy móc vẫn giữ được evidence hữu ích về hành vi dễ tổn thương.

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

**Chức năng:** Xác định cấu trúc dữ liệu chuẩn cho mọi finding, bao gồm vị trí code, loại lỗ hổng, evidence, mức độ nghiêm trọng và trạng thái validation.

**Mục đích:** Một schema ổn định cho phép các phase và experiment trao đổi dữ liệu nhất quán, validate tự động và so sánh cùng tiêu chí. Nếu mỗi scanner trả field khác nhau, metrics và báo cáo sẽ không đáng tin cậy.

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

### Micro-task 1.2 — Quy định normalization

**Chức năng:** Chuẩn hóa path, line, confidence, giá trị thiếu, ID và evidence trước khi finding đi vào validation, deduplication hoặc reporting.

**Mục đích:** Cùng một finding có thể được model biểu diễn theo nhiều cách; normalization biến chúng về một dạng có thể so sánh bằng máy. Điều này tránh sai metrics do khác biệt hình thức như path tuyệt đối/tương đối hoặc tên loại lỗ hổng không đồng nhất.

- File path tương đối với `WEBGOAT_ROOT`.
- Line number là số nguyên dương hoặc `null` nếu model không chỉ ra được.
- Confidence nằm trong `[0, 1]`.
- Field thiếu dùng `null`, `""` hoặc `[]` theo một quy ước duy nhất.
- Finding ID sinh deterministic từ experiment, file, line, CWE và normalized type.
- Evidence raw phải được giữ lại.



### Micro-task 1.3 — Định nghĩa validator contract

**Chức năng:** Quy định rõ input và output của bộ validator, gồm kết luận, độ tin cậy, lý do, evidence còn thiếu và gợi ý kiểm tra thủ công.

**Mục đích:** Contract buộc validator đánh giá finding dựa trên code context và data flow thay vì chỉ tin phần mô tả của model. Nó cũng giúp mọi kết quả validation có thể được audit và xử lý thống nhất ở các bước sau.

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

**Chức năng:** Khảo sát repository để nhận diện module, framework, endpoint, tầng kiến trúc, cơ chế bảo mật và các khu vực code nhạy cảm.

**Mục đích:** Bản đồ kiến trúc giúp hệ thống hiểu code nào liên quan đến một candidate và lấy đúng context thay vì gửi toàn bộ repository. Nhờ đó model phân tích chính xác hơn với ít token hơn.

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

### Micro-task 2.2 — Java symbol index

**Chức năng:** Lập chỉ mục symbol Java và các quan hệ cơ bản như class, method, annotation, import, endpoint và caller/callee.

**Mục đích:** Index cho phép truy ngược từ một dòng đáng ngờ đến method, class và luồng gọi liên quan mà không phải đọc lại toàn bộ source. Đây là nền tảng để phát hiện data flow xuyên file và cung cấp context đúng cho model.

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

**Chức năng:** Thu thập một gói context có chọn lọc cho từng candidate, gồm source, sink, caller/callee, endpoint, cấu hình và test liên quan.

**Mục đích:** Model cần đủ code để kiểm tra khả năng khai thác nhưng cửa sổ context có giới hạn. Task này giữ evidence quan trọng cùng file/line và loại bỏ phần không liên quan để tiết kiệm token.

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

**Chức năng:** Xây các rule tĩnh để nhận diện điểm nhận dữ liệu không tin cậy, thao tác nhạy cảm và candidate bảo mật trong source Java.

**Mục đích:** Rule deterministic tạo danh sách đầu vào có thể lặp lại và thu hẹp phạm vi phải gọi model. Model vì thế tập trung điều tra candidate có evidence ban đầu thay vì dò tìm mù trên cả repository.

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

### Micro-task 3.2 — Early rejection

**Chức năng:** Loại bỏ hoặc hạ độ ưu tiên các candidate đã có dấu hiệu an toàn, không reachable, không có data flow hoặc nằm ngoài phạm vi source.

**Mục đích:** Một source/sink match chỉ là tín hiệu, chưa phải lỗ hổng. Sàng lọc sớm giảm false positive và chi phí model nhưng vẫn giữ các trường hợp chưa đủ evidence để điều tra tiếp.

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

**Chức năng:** Xuất toàn bộ candidate sau bước prefilter thành JSONL hợp lệ cho từng experiment.

**Mục đích:** File trung gian này tạo ranh giới rõ giữa phát hiện deterministic và phân tích bằng model, giúp debug, resume và so sánh số candidate giữa các cấu hình mà không cần chạy lại toàn pipeline.

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

**Chức năng:** Thiết kế prompt để model tóm tắt kiến trúc, trust boundary, endpoint, data store và security control dựa trên source evidence.

**Mục đích:** Một mô hình đúng về kiến trúc giúp các bước sau hiểu dữ liệu đi từ đâu, qua ranh giới tin cậy nào và được bảo vệ ở đâu. Yêu cầu evidence ngăn model suy đoán thành phần không tồn tại trong code.

Prompt phải yêu cầu model:

- xác định module;
- xác định trust boundary;
- xác định endpoint;
- xác định data store;
- xác định security control;
- chỉ dựa trên source evidence.



### Micro-task 4.2 — Prompt theo vulnerability class

**Chức năng:** Tạo prompt chuyên biệt cho từng nhóm lỗ hổng, với checklist bắt buộc về source, sink, data flow, control, điều kiện khai thác và evidence.

**Mục đích:** Mỗi loại lỗ hổng có tiêu chí xác nhận và false-positive pattern khác nhau. Prompt chuyên biệt giúp model áp dụng đúng tiêu chí, trả kết quả đầy đủ và không tạo finding khi chưa đủ bằng chứng.

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

**Chức năng:** Đóng gói tri thức kiểm tra cho từng loại lỗ hổng thành các skill có version, gồm source/sink, sanitizer, false positive, checklist và quy tắc output.

**Mục đích:** Skill giúp tái sử dụng cùng một tiêu chuẩn phân tích giữa các run và truy vết phiên bản tri thức đã ảnh hưởng đến kết quả. Version/hash cũng ngăn benchmark bị so sánh sai khi prompt hoặc rule đã thay đổi.

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

---



## Phase 5 — Model adapter và instrumentation



### Micro-task 5.1 — Provider adapter

**Chức năng:** Tạo lớp giao tiếp thống nhất với Gemini hoặc mock provider, quản lý timeout, retry, cache, lỗi response và lưu raw output.

**Mục đích:** Tách provider khỏi logic scanner giúp dễ thay cấu hình, test offline và xử lý lỗi nhất quán. Adapter cũng bảo đảm credential không bị hardcode và một lỗi API không làm phát sinh finding giả.

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

**Chức năng:** Ghi lại token, độ trễ, retry và cách đo usage cho từng model call.

**Mục đích:** Benchmark không chỉ đo số finding mà còn phải đo chi phí và tốc độ. Phân biệt usage do provider cung cấp với số ước lượng giúp báo cáo trung thực và so sánh hiệu quả giữa các experiment.

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

**Chức năng:** Lưu và tái sử dụng model response khi source, prompt, model, loại phân tích và context hoàn toàn giống nhau.

**Mục đích:** Cache giảm thời gian, token và chi phí khi resume hoặc chạy lại mà không làm sai kết quả. Cache key chặt chẽ bảo đảm response cũ không bị dùng sau khi bất kỳ đầu vào nào thay đổi.

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

**Chức năng:** Điều phối chuỗi xử lý từ candidate, lấy context, chọn prompt chuyên biệt, gọi model và chuẩn hóa response thành finding chưa validation.

**Mục đích:** Workflow rõ ràng bảo đảm mọi candidate đi qua cùng các bước và mọi finding đều có nguồn gốc truy vết được. Cơ chế lưu/repair response lỗi giúp pipeline bền vững mà không tự bịa dữ liệu khi model trả sai định dạng.

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

**Chức năng:** Đánh giá độc lập từng finding bằng cách kiểm tra lại source-to-sink, reachability, sanitizer, authorization và kịch bản tấn công trong code.

**Mục đích:** Model điều tra có thể kết luận quá sớm hoặc bỏ qua security control. Một lượt validation độc lập làm giảm false positive và cung cấp ước lượng precision có căn cứ, dù vẫn phải ghi rõ khi validator cũng là LLM.

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

**Chức năng:** Phân loại và xuất finding thành ba tập `validated`, `rejected` và `uncertain`.

**Mục đích:** Tách kết quả theo mức độ xác nhận giúp metrics không đánh đồng nghi vấn với true positive. Người review cũng biết finding nào có thể ưu tiên xử lý và finding nào cần kiểm tra thêm.

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

**Chức năng:** Xác định tiêu chí nhận biết nhiều finding có thực chất mô tả cùng một lỗ hổng dựa trên vị trí, source/sink, CWE và nội dung evidence.

**Mục đích:** Một lỗ hổng có thể bị nhiều rule hoặc prompt phát hiện và diễn đạt khác nhau. Dedup theo nhiều tín hiệu tránh đếm trùng nhưng vẫn không gộp nhầm các lỗ hổng chỉ có mô tả giống nhau.

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

**Chức năng:** Chọn record đầy đủ và đáng tin cậy nhất làm đại diện cho mỗi nhóm trùng, đồng thời lưu liên kết từ các record bị gộp.

**Mục đích:** Output cuối cần gọn nhưng không được mất dấu vết phân tích. Quy tắc ưu tiên evidence, validation và vị trí chính xác giúp giữ lại phiên bản hữu ích nhất cho người sửa lỗi.

Ưu tiên finding có:

1. validation đầy đủ hơn;
2. evidence cụ thể hơn;
3. confidence cao hơn;
4. line chính xác hơn;
5. data-flow rõ hơn.

Finding bị gộp phải giữ `duplicate_of` hoặc mapping file.

### Micro-task 7.3 — Final findings

**Chức năng:** Sinh `findings.jsonl` đã chuẩn hóa, validation và deduplicate làm đầu ra chính của mỗi experiment.

**Mục đích:** Một artifact cuối có contract thống nhất là cơ sở để chạy validator, tính metrics và so sánh experiment. Các lệnh kiểm tra bảo đảm lỗi format không âm thầm làm sai báo cáo.

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

**Chức năng:** Chuyển kết quả SARIF hoặc JSON từ công cụ/nguồn khác sang finding JSONL chuẩn của benchmark.

**Mục đích:** Converter cho phép đưa nhiều định dạng đầu vào về cùng schema để so sánh công bằng. Việc giữ raw evidence và báo lỗi rõ ràng giúp quá trình chuyển đổi có thể audit, không che mất dữ liệu gốc.

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

**Chức năng:** Kiểm tra cấu trúc từng dòng, field bắt buộc, enum, kiểu dữ liệu, ID duy nhất và quy tắc path của file JSONL.

**Mục đích:** JSON parse được chưa có nghĩa là dữ liệu đúng contract. Validator chặn record sai trước khi chúng gây lỗi hoặc làm méo deduplication, metrics và báo cáo.

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

**Chức năng:** Cung cấp lệnh độc lập để deduplicate một file raw findings và xuất file findings chuẩn.

**Mục đích:** CLI giúp chạy lại hoặc kiểm thử riêng bước dedup mà không cần gọi toàn pipeline. Điều này hữu ích khi tinh chỉnh tiêu chí gộp, xử lý artifact cũ và tái lập kết quả.

Implement:

```bash
python scripts/deduplicate_findings.py \
  --input results/exp-b-vuln-prompts/raw_findings.jsonl \
  --output results/exp-b-vuln-prompts/findings.jsonl
```

---



## Phase 9 — Ground truth cục bộ



### Micro-task 9.1 — Trích xuất ground truth

**Chức năng:** Xây bộ tham chiếu lỗ hổng cục bộ từ source, metadata, test, solution, fixture và lịch sử commit sẵn có.

**Mục đích:** Ground truth là mốc để phân biệt true positive, false positive và finding bị bỏ sót. Dùng nhiều loại evidence thay vì chỉ tên lesson giúp tránh xác nhận vòng tròn và giữ benchmark đáng tin cậy trong môi trường offline.

Dựa trên:

- source WebGoat;
- lesson/module metadata;
- test;
- expected solution;
- local fixture;
- commit history nếu có sẵn.

Không dùng tên lesson làm bằng chứng duy nhất.

### Micro-task 9.2 — Ground truth schema

**Chức năng:** Chuẩn hóa mỗi mục ground truth với lesson, module, loại lỗ hổng, CWE, file liên quan, hành vi kỳ vọng, evidence và confidence.

**Mục đích:** Schema khiến ground truth có thể được đọc và đối chiếu tự động, đồng thời cho reviewer biết mỗi kết luận dựa trên bằng chứng nào và chắc chắn đến mức nào.

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

**Chức năng:** Đối chiếu finding với ground truth dựa trên code path, vị trí, hành vi, source/sink và security invariant.

**Mục đích:** Chỉ trùng tên loại lỗ hổng chưa đủ chứng minh finding là đúng. Mapping dựa trên hành vi và code evidence giúp tính TP/FP chính xác hơn, còn trường hợp thiếu bằng chứng được giữ là `uncertain` thay vì ép kết luận.

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

**Chức năng:** Chạy cấu hình đơn giản nhất với prompt audit tổng quát để tạo mốc hiệu năng ban đầu.

**Mục đích:** Baseline cho biết chất lượng, thời gian và token khi chưa có các kỹ thuật tối ưu. Các experiment sau phải được so với mốc này để chứng minh cải tiến nào thực sự tạo giá trị.

- harness đơn giản;
- prompt audit tổng quát;
- Gemini 2.5 Flash;
- không validator độc lập;
- context giới hạn;
- JSONL output.



### Experiment B — Vulnerability-specific

**Chức năng:** Đánh giá tác động của prompt chuyên biệt theo từng loại lỗ hổng, context chọn lọc, self-validation và deduplication.

**Mục đích:** So với baseline, experiment này giúp tách riêng lợi ích của kiến thức chuyên biệt và kiểm tra liệu chúng có tăng precision hoặc evidence quality mà không tốn quá nhiều chi phí hay không.

- chia theo vulnerability class;
- prompt chuyên biệt;
- self-validation;
- context có chọn lọc;
- dedup.



### Experiment C — Indexed

**Chức năng:** Đánh giá pipeline có symbol index, architecture map, candidate discovery, context xuyên file và validator độc lập.

**Mục đích:** Experiment này đo giá trị của việc hiểu cấu trúc repository và dùng evidence deterministic trước khi gọi model. Nó cho thấy context có hệ thống có cải thiện khả năng tìm data flow và giảm false positive hay không.

- symbol index;
- architecture map;
- source/sink candidate discovery;
- cross-file context;
- independent validation.



### Experiment D — Optimized

**Chức năng:** Kết hợp cấu hình tốt nhất từ các experiment trước với prefilter, cache, concurrency giới hạn, validation, semantic dedup và khả năng retry/resume.

**Mục đích:** Đây là ứng viên cấu hình thực tế cuối cùng, nhằm đạt cân bằng tốt nhất giữa chất lượng finding, tốc độ, độ ổn định và mức dùng token thay vì chỉ tối đa hóa một chỉ số riêng lẻ.

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

**Chức năng:** Đo thời gian từng phase và tổng thời gian chạy bằng monotonic clock.

**Mục đích:** Phân rã thời gian giúp xác định bottleneck nằm ở indexing, model call, validation hay bước khác. Monotonic clock tránh sai số do đồng hồ hệ thống bị điều chỉnh trong lúc chạy.

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

**Chức năng:** Tính các chỉ số về số lượng, chất lượng, tốc độ, token, lỗi, retry và hiệu quả cache cho mỗi experiment.

**Mục đích:** Một tập metrics chung cho phép so sánh định lượng thay vì dựa vào cảm giác. Quy định dùng `null` khi thiếu dữ liệu ngăn báo cáo tạo ra độ chính xác giả từ thông tin không tồn tại.

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

**Chức năng:** Tổng hợp phạm vi, phương pháp, môi trường, kết quả, hạn chế và so sánh experiment thành báo cáo benchmark dễ đọc.

**Mục đích:** Artifact kỹ thuật rời rạc chưa đủ để ra quyết định. Báo cáo biến dữ liệu thành kết luận có thể kiểm chứng và tách rõ cấu hình tốt nhất theo chất lượng, tốc độ, token cũng như mức cân bằng tổng thể.

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

**Chức năng:** Kiểm thử riêng các hàm cốt lõi về serialization, normalization, ID, dedup, metrics, token, response lỗi và conversion.

**Mục đích:** Unit test bắt lỗi logic nhỏ một cách nhanh và xác định chính xác thành phần hỏng. Các lỗi ở đây có thể âm thầm làm sai toàn bộ benchmark dù pipeline vẫn chạy đến cuối.

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

**Chức năng:** Chạy toàn pipeline bằng mock model trên một project Java nhỏ có cả code dễ tổn thương, code an toàn và false positive có chủ ý.

**Mục đích:** Fixture có đáp án biết trước kiểm tra các phase có phối hợp đúng từ phát hiện đến rejection và output hay không. Mock adapter làm test ổn định, nhanh, offline và không phát sinh chi phí API.

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

**Chức năng:** Chạy pipeline thật trên một module WebGoat nhỏ rồi validate findings và tổng hợp kết quả.

**Mục đích:** Integration test phát hiện lỗi chỉ xuất hiện khi các component làm việc với source thực tế, nhưng có phạm vi nhỏ để debug nhanh và hạn chế token trước khi full scan.

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

**Chức năng:** Chạy cấu hình optimized trên toàn bộ WebGoat và kiểm tra đầy đủ output, exit code, metrics, log, secret và tính nguyên vẹn của source.

**Mục đích:** Đây là cổng xác nhận hệ thống đáp ứng yêu cầu đầu-cuối trong điều kiện sử dụng thực tế. Chỉ chạy sau smoke test giúp tránh tiêu tốn thời gian/API cho một pipeline còn lỗi cơ bản.

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

**Chức năng:** Viết hướng dẫn vận hành và lưu đủ metadata của mỗi run để người khác có thể cài đặt, chạy lại, resume, validate và đọc kết quả.

**Mục đích:** Benchmark chỉ có giá trị khi người khác có thể tái lập cách nó được tạo ra. README và run metadata loại bỏ các giả định ngầm về môi trường, cấu hình model, prompt version và chính sách retry.

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

**Chức năng:** Thực hiện checklist và các lệnh kiểm tra cuối để xác nhận mọi artifact, test, metrics, bảo mật log và tính nguyên vẹn source đều đạt yêu cầu.

**Mục đích:** Bước bàn giao gom các tiêu chí hoàn thành thành một cổng kiểm soát cuối cùng, giúp tránh bỏ sót file bắt buộc hoặc công bố benchmark khi dữ liệu chưa hợp lệ và chưa thể tái lập.



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
