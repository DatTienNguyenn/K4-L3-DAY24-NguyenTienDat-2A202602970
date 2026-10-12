# Verification — điền trước khi nộp

- OS / Python / Gitleaks version: Linux (WSL2) / Python 3.11.16 / Gitleaks v8.30.1
- `python -m pytest tests/ -q`: 33 passed in 0.17s
- `pre-commit run --all-files`: Passed (Detect hardcoded secrets: Passed)
- Ledger verify: True
- Các lỗi còn lại: Không có (0 errors)

## Checkpoint 3a — PII Detection Verification

### 1. Kết quả kiểm thử
- **Lệnh chạy:** `pytest tests/test_pii.py -v -s`
- **Số liệu đo lường:**
  - `gold` (nhãn thực tế): 118
  - `pred` (nhãn dự đoán): 118
  - `tp` (true positive - phát hiện đúng): 118
- **Chỉ số:**
  - `precision` = `tp / pred` = 118 / 118 = **1.000 (100%)**
  - `recall` = `tp / gold` = 118 / 118 = **1.000 (100%)**
- **Đánh giá theo RUBRIC.md:** Recall = 100% > 95% → **Đạt mức điểm tối đa (10/10)**.

### 2. Giới hạn của phương pháp Regex
- **Phụ thuộc vào từ khóa ngữ cảnh cứng:**
  - Số tài khoản ngân hàng (`VN_BANK_ACCOUNT`) có độ dài biến thiên (8–16 chữ số), rất dễ nhầm lẫn với số điện thoại, CCCD hoặc mã đơn hàng/mã hóa đơn nếu không có nhãn cứng như `STK`, `số tài khoản`. Nếu người dùng chỉ cung cấp số tài khoản trần hoặc dùng từ lóng, regex sẽ bỏ sót (False Negative); ngược lại nếu mở rộng regex cho mọi chuỗi 8–16 số sẽ gây báo sai tràn lan (False Positive).
- **Dễ bị qua mặt bằng kỹ thuật biến thể/lách luật (Obfuscation):**
  - Kẻ tấn công có thể chèn các ký tự ngắt dòng, ký tự zero-width, viết số bằng chữ tiếng Việt (ví dụ: "không chín một..."), hoặc chèn các ký tự đặc biệt ngẫu nhiên giữa các chữ số để phá vỡ cấu trúc pattern của regex.
- **Không nhận diện được thực thể ngữ nghĩa phức tạp (PERSON, LOCATION):**
  - Regex không thể nhận diện tên người Việt hoặc địa chỉ vì chúng không tuân theo một quy tắc định dạng chuỗi cố định nào, đòi hỏi các mô hình NLP chuyên biệt (như GLiNER, Presidio hoặc spaCy/transformers NER).
- **Không kiểm tra tính hợp lệ về mặt nghiệp vụ (Checksum & Semantic validation):**
  - Regex chỉ kiểm tra định dạng hình thức bề ngoài (syntax pattern), không thể xác thực thuật toán checksum của CCCD (mã tỉnh thành, thế kỷ/giới tính, năm sinh), đầu số mạng viễn thông thực tế còn hoạt động, hay số tài khoản có tồn tại thật hay không.
