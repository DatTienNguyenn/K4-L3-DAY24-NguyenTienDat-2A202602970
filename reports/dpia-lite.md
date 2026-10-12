# Đánh giá tác động quyền riêng tư tóm lược (DPIA-lite)

*Bản mô tả học tập trong khuôn khổ Lab 24 — Data Governance & Security (L3), không cấu thành hồ sơ đánh giá tác động bảo vệ dữ liệu cá nhân chính thức theo quy định pháp luật.*

---

### 1. Loại dữ liệu và phân loại dữ liệu
- **Dữ liệu ticket hỗ trợ kỹ thuật (`corpus/*.md`):**
  - Chứa nội dung câu hỏi, yêu cầu và phản hồi từ người dùng, được phân loại ở mức `internal`.
  - Đây là bề mặt tấn công tiềm ẩn (untrusted content) do có thể bị kẻ tấn công cài cắm chỉ thị Prompt Injection gián tiếp (như các biến thể từ `ticket-901.md` đến `ticket-904b.md`).
- **Hồ sơ khách hàng (`data/customers.json`):**
  - Chứa thông tin nhận dạng cá nhân (PII) tổng hợp gồm: `customer_id`, `name`, `cccd` (12 số), `phone` (10 số), `bank_account` (8–16 số), `email` và `related_tickets`.
  - Phân loại ở mức `restricted` (dữ liệu nhạy cảm cao, yêu cầu bảo vệ nghiêm ngặt).
  - Toàn bộ dữ liệu là dữ liệu tổng hợp giả lập (synthetic data), không phải thông tin của thể nhân có thật.

---

### 2. Mục đích xử lý và Principal (Danh tính người dùng)
- **`support_l1` (Nhân viên hỗ trợ bậc 1):**
  - Quyền công cụ (`allowed_tools`): Chỉ được phép sử dụng `search_docs`.
  - Mục đích hợp lệ (`purposes`): `summarize-tickets`, `support-reply`.
  - Nguyên tắc: Không được phép truy cập kho dữ liệu riêng (`read_customer`), không được đọc CCCD/STK của khách hàng.
- **`dpo` (Cán bộ bảo vệ dữ liệu cá nhân / Quản trị viên tuân thủ):**
  - Quyền công cụ (`allowed_tools`): Được phép sử dụng `search_docs`, `read_customer`.
  - Mục đích hợp lệ (`purposes`): `summarize-tickets`, `support-reply`, `privacy-audit`.
  - Nguyên tắc: Được phép đọc hồ sơ khách hàng liên kết với ticket hợp lệ để đối soát, nhưng vẫn bị cấm tuyệt đối việc truyền PII ra ngoài hệ thống (`http_post`).

---

### 3. Dữ liệu đi qua những Run / Tool / Endpoint nào?
- **Run A (Untrusted Corpus Ingestion):**
  - Nhận yêu cầu từ người dùng (`message`).
  - Gọi công cụ `tools.search_docs` (chân 1 của Trifecta) để tìm kiếm nội dung ticket trong `corpus/`.
  - Toàn bộ nội dung văn bản thô đi vào Run A; PII trong ticket được làm mờ/che giấu bằng `pii.redact()` trước khi gửi văn bản tóm tắt sang LLM.
- **Ranh giới phân tách (Boundary Sanitization - Trifecta Split):**
  - Chỉ trích xuất ID ticket dạng số (`ticket_id: int`) từ **tên file** (ví dụ: `ticket-007.md` → `7`), loại bỏ hoàn toàn free text chứa injection từ kẻ tấn công trước khi chuyển sang Run B.
- **Run B (Private Store Access):**
  - Chỉ nhận danh sách số ticket đã được lọc từ Run A.
  - Tra cứu khách hàng thực sự liên quan thông qua thuộc tính `related_tickets` trong kho dữ liệu tin cậy `data/customers.json`.
  - Gọi công cụ `tools.read_customer` (chân 2 của Trifecta) khi được Policy phê duyệt.
- **Cổng kiểm soát chính sách (PEP - Policy Enforcement Point):**
  - Đặt chốt chặn kiểm tra trước mọi lời gọi tool (`search_docs`, `read_customer`, `http_post`).
  - Đánh giá tính hợp lệ dựa trên: phân loại dữ liệu, danh tính người ra lệnh (`on_behalf_of`), thời hạn token (`expires_at`), mục đích (`purpose`), phạm vi quyền hiệu lực và quy tắc cấm egress dữ liệu restricted.
- **Điểm đích mạng (Localhost Sink):**
  - Server mô phỏng rò rỉ dữ liệu nghe tại `http://127.0.0.1:10024/reconcile` (chân 3 của Trifecta).
  - Bị Policy chặn hoàn toàn khi Agent có ý định gửi dữ liệu nhạy cảm ra ngoài.
- **Audit Ledger (`reports/ledger.jsonl`):**
  - Ghi nhận 100% các quyết định (`allow` và `deny`), thời gian (`ts`), lý do (`reason`), mã băm tham số (`args_hash`), liên kết chuỗi băm SHA-256 (`prev_hash`, `hash`).

---

### 4. Đã chặn / cho phép gì và các giới hạn còn lại
- **Đã chặn (Containment & Safeguards):**
  - Chặn Prompt Injection: Vô hiệu hóa cả 4 kỹ thuật lure (HTML comment, thẻ ẩn/zero-width space, giả danh thẩm quyền, chia tách đa tài liệu).
  - Chặn mở private store trái thẩm quyền: `support_l1` bị Policy từ chối truy cập `read_customer` (`decision="deny"`).
  - Chặn truy cập dữ liệu không liên quan: Khách hàng chỉ được kẻ tấn công nêu tên trong văn bản tự do (như `KH-000777`) không bao giờ bị đọc.
  - Chặn rò rỉ dữ liệu ra mạng: Chặn hoàn toàn lời gọi `tools.http_post` ra sink khi dữ liệu ở mức restricted; file `reports/attack-after.log` hoàn toàn rỗng (0 bytes).
- **Đã cho phép (Utility Preservation):**
  - Duy trì đầy đủ chức năng nghiệp vụ hợp lệ: `dpo` vẫn đọc được các hồ sơ khách hàng gắn với ticket mở trong tuần; kết quả tóm tắt gửi về người dùng đầy đủ và chính xác.
- **Các giới hạn còn lại (Limitations):**
  - **Mô phỏng LLM Mock:** Sử dụng mô hình deterministic để đảm bảo tính tái lập trong chấm điểm, chưa phản ánh đầy đủ tính ngẫu nhiên và ngữ nghĩa phức tạp của LLM thương mại lớn thực tế.
  - **Cơ chế xác thực mô phỏng:** Danh tính người dùng và thời hạn token dựa trên file cấu hình tĩnh (`principals.json`), chưa tích hợp hệ thống IAM/IdP doanh nghiệp thực (OAuth2/OIDC/mTLS).
  - **Bộ lọc PII bằng Regex:** Mới nhận diện 4 loại thực thể có cấu trúc định dạng cố định (CCCD, SĐT, STK, Email); chưa nhận diện được tên người, địa chỉ phi cấu trúc và có thể bị lách qua các kỹ thuật obfuscation phức tạp.
  - **Audit Hash Chain cục bộ:** Hash chain bảo vệ tính toàn vẹn trong phạm vi một file đơn lẻ; chưa thể chống lại hành vi cố ý cắt xén dòng cuối (truncation attack) hoặc xoá toàn bộ file nếu thiếu mốc tin cậy độc lập bên ngoài (như hệ thống WORM hoặc SIEM tập trung).
