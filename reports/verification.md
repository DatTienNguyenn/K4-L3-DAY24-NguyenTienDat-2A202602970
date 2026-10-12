# Verification — Báo cáo nghiệm thu Lab 24 L3

## 1. Thông số môi trường & Tổng kết kiểm tra trước khi nộp
- **Hệ điều hành (OS):** Linux 6.6.87.2-microsoft-standard-WSL2 (x86_64)
- **Phiên bản Python:** Python 3.11.16
- **Phiên bản Gitleaks:** Gitleaks v8.30.1
- **Kết quả kiểm thử toàn bộ (`python -m pytest tests/ -q --basetemp=.pytest_tmp`):** `33 passed in 0.56s` (33 passed, 0 failed, 0 skipped)
- **Kiểm tra Pre-commit (`pre-commit run --all-files`):** `Passed` (`Detect hardcoded secrets: Passed`)
- **Kiểm tra tính toàn vẹn Ledger (`ledger.verify()`):** `True`
- **Kích thước file bằng chứng rò rỉ sau khi contain (`reports/attack-after.log`):** `0 bytes` (hoàn toàn rỗng)
- **Các lỗi còn lại:** Không có (0 errors)

---

## 2. Nhật ký thực thi chi tiết từng Checkpoint

### Checkpoint 1 — Baseline
- **Nội dung:** Đọc hiểu mã nguồn `_naive_loop()`, phân tích 3 điểm yếu cốt lõi về Identity, Policy Authorization trước khi gọi `http_post`, và bằng chứng PII exfiltration.
- **Minh chứng:** Điền đầy đủ câu trả lời dẫn chứng dòng code cụ thể trong `reports/baseline.md`.
- **Trạng thái:** VERIFIED.

### Checkpoint 2 — Red Team & Injection Corpus
- **Nội dung:** Giữ `ticket-901.md`, viết thêm 3 biến thể lure mới (`ticket-902.md`, `ticket-903.md`, `ticket-904.md` + `ticket-904b.md`) thử nghiệm các kỹ thuật giấu lệnh và giả mạo thẩm quyền khác nhau.
- **Lệnh kiểm tra lure:**
  ```bash
  python -m agent.check_lure corpus/ticket-90*.md
  ```
- **Output:**
  ```text
  ── Kiểm tra corpus/ticket-901.md ── => SẴN SÀNG
  ── Kiểm tra corpus/ticket-902.md ── => SẴN SÀNG
  ── Kiểm tra corpus/ticket-903.md ── => SẴN SÀNG
  ── Kiểm tra corpus/ticket-904.md + corpus/ticket-904b.md ── => SẴN SÀNG
  4/4 lure sẵn sàng.
  ```
- **Bằng chứng exfiltration trước contain (`reports/attack-before.log`):** Chứa 4 dòng log JSON (1192 bytes) thể hiện toàn bộ PII synthetic của `KH-000999` bị gửi ra sink.
- **Trạng thái:** VERIFIED.

### Checkpoint 3a — PII Detection & Redaction Gate
- **Nội dung:** Hoàn thiện `detect()` và `redact()` trong `agent/pii.py` cho 4 loại dữ liệu: CCCD, Phone, Bank Account, Email.
- **Lệnh kiểm tra:**
  ```bash
  pytest tests/test_pii.py -v -s
  ```
- **Output:**
  ```text
  [pii] gold=118 pred=118 tp=118
  [pii] precision=1.000 recall=1.000
  PASSED
  tests/test_pii.py::test_redact_removes_detected_entities PASSED
  ```
- **Đánh giá theo RUBRIC.md:** Recall = 100% (> 95%) → Đạt mức điểm tối đa (10/10).
- **Trạng thái:** VERIFIED.

### Checkpoint 3b — Policy Enforcement Point (PEP)
- **Nội dung:** Hoàn thiện `check()` trong `agent/policy.py`. Áp dụng rule tối thiểu cấm egress khi dữ liệu ở mức `restricted`, kiểm tra mục đích, quyền hạn, thời hạn và phân loại dữ liệu.
- **Lệnh kiểm tra:**
  ```bash
  pytest tests/test_policy.py -v
  ```
- **Output:** `4 passed in 0.02s`
- **Trạng thái:** VERIFIED.

### Checkpoint 3c — On-Behalf-Of (OBO) Delegation
- **Nội dung:** Kiểm tra phân quyền theo người ủy quyền mô phỏng (`data/principals.json`). `support_l1` bị chặn đọc private store; `dpo` được phép đọc hồ sơ khách hợp lệ; kiểm tra quyền giao thoa delegation depth và hết hạn token.
- **Lệnh kiểm tra:**
  ```bash
  pytest tests/test_obo.py -v
  ```
- **Output:** `5 passed in 0.08s`
- **Trạng thái:** VERIFIED.

### Checkpoint 3d — Trifecta Split
- **Nội dung:** Tách biệt Run A (đọc corpus) và Run B (đọc private store). Run A chỉ truyền số ticket nguyên bản từ tên file sang Run B. Run B tra cứu `related_tickets` từ `customers.json`, loại bỏ hoàn toàn free text của kẻ tấn công (`KH-000777`).
- **Lệnh kiểm tra:**
  ```bash
  pytest tests/test_split.py -v --basetemp=.pytest_tmp
  ```
- **Output:** `1 passed in 0.08s`
- **Trạng thái:** VERIFIED.

### Checkpoint 3e — Tamper-evident Audit Ledger
- **Nội dung:** Hoàn thiện `append()` và `verify()` trong `agent/ledger.py` với chuỗi hash SHA-256 (`prev_hash`, `hash`), mọi dòng bắt buộc có `reason` không rỗng và chỉ lưu `args_hash`.
- **Lệnh kiểm tra unit test:**
  ```bash
  pytest tests/test_ledger.py -v
  ```
- **Output:** `3 passed in 0.02s`
- **Lệnh xác minh file ledger thật (`reports/ledger.jsonl`):**
  ```bash
  python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"
  ```
- **Output:** `True`
- **Dòng chứng cứ deny egress trong ledger:**
  - Dòng 23 & Dòng 46: `tool="http_post"`, `decision="deny"`, `reason="Cấm tuyệt đối egress mạng đối với dữ liệu restricted"`, `on_behalf_of="dpo"`.
- **Trạng thái:** VERIFIED.

### Checkpoint 4 — Supply Chain & Secrets
- **Nội dung:** Quét Git history phát hiện secret giả cài sẵn; cấu hình allowlist `.venv/` trong `.gitleaks.toml`; sinh `requirements.lock` kèm sha256 hashes; cấu hình hook `.pre-commit-config.yaml` gitleaks pin v8.30.1; viết báo cáo sự cố `reports/secrets-incident.md`.
- **Lệnh kiểm tra quét lịch sử Git:**
  ```bash
  gitleaks git --config .gitleaks.toml --redact .
  # Output: Mã thoát 1, leaks found: 1 (bắt đúng token giả tại commit 1bdd849)
  ```
- **Lệnh kiểm tra quét working directory:**
  ```bash
  gitleaks dir --config .gitleaks.toml --redact .
  # Output: Mã thoát 0, no leaks found
  ```
- **Lệnh kiểm tra pre-commit:**
  ```bash
  pre-commit run --all-files
  # Output: Detect hardcoded secrets: Passed
  ```
- **Lệnh kiểm tra supply chain test:**
  ```bash
  pytest tests/test_supply_chain.py -v --basetemp=.pytest_tmp
  # Output: 3 passed in 0.01s
  ```
- **Trạng thái:** VERIFIED.

### Checkpoint 5 — Prove & Compliance Mapping
- **Nội dung:** Replay toàn bộ 4 biến thể injection dưới cả 2 principal (`support_l1`, `dpo`), xác minh `reports/attack-after.log` rỗng (0 bytes); hoàn thành `compliance-mapping.md` và `dpia-lite.md`.
- **Lệnh kiểm tra injection:**
  ```bash
  pytest tests/test_injection.py -v --basetemp=.pytest_tmp
  # Output: 8 passed in 0.15s (4 biến thể x 2 principal)
  ```
- **Kiểm tra file sau containment:**
  - `reports/attack-before.log`: 1192 bytes (chứa 4 request exfil baseline).
  - `reports/attack-after.log`: 0 bytes (không có request nào lọt ra sink).
- **Trạng thái:** VERIFIED.

---

## 3. Các lỗi đã gặp và giải pháp xử lý
1. **Lỗi `gitleaks: command not found`:**
   - *Nguyên nhân:* Môi trường hệ thống chưa có sẵn binary `gitleaks` trong biến môi trường `PATH`.
   - *Giải pháp:* Tải trực tiếp bản release chính thức v8.30.1 (`gitleaks_8.30.1_linux_x64.tar.gz`), giải nén vào `~/.local/bin/gitleaks` (thư mục đã nằm trong `PATH`) và cấp quyền thực thi `chmod +x`.
2. **Xung đột cổng `10024` khi chạy pytest:**
   - *Nguyên nhân:* Server sink chạy nền ở terminal ngoài chiếm giữ cổng `10024`, khiến fixture `clean_sink` trong `tests/conftest.py` không thể bind socket trong background thread.
   - *Giải pháp:* Tắt tiến trình server sink độc lập trước khi chạy pytest suite; sau khi pytest hoàn tất mới khởi động lại server sink để chạy thử nghiệm manual.
3. **Phòng tránh False Positive trong `.venv/` khi quét secret:**
   - *Nguyên nhân:* Thư mục môi trường ảo `.venv/` có thể chứa các chuỗi token kiểm thử từ thư viện bên ngoài.
   - *Giải pháp:* Bổ sung cấu hình allowlist đường dẫn `paths = ['''\.venv/''']` vào file `.gitleaks.toml` mà không làm ảnh hưởng đến rule chính `lab24-synthetic-token`.
