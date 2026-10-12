# Baseline — điền trong checkpoint 1

1. Agent có identity mỗi run chưa? Dẫn file/hàm:
   Chưa. Ở baseline, hàm `run_once()` gọi `_naive_loop()` mà không truyền `principal_id`, và trong `_naive_loop` hoàn toàn không khởi tạo `agent_id`, `run_id` hay danh tính người dùng để kiểm quyền. Do đó, các hàm `read_customer()` và `http_post()` được gọi trực tiếp mà không có cơ chế định danh hay phân quyền.

2. Ai cho phép `http_post`? Dẫn file/hàm:
   Không có policy nào kiểm tra mục đích, quyền hay loại dữ liệu trước khi gọi `http_post`; hàm `http_post` chỉ có một allowlist cứng host/port để ngăn gửi ra Internet thật. Thực chất kẻ tấn công là bên quyết định: ticket là dữ liệu nhưng baseline xử lý chỉ thị bên trong như lệnh, trích xuất qua `llm.find_injection()` rồi tự động kích hoạt `read_customer()` và `http_post()` mà chưa có cổng kiểm quyền nào.

3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:
   Body của request POST chứa dữ liệu khách hàng được tạo tại dòng `agent/loop.py:44` (`{"records": collected}`) và gửi đi qua `requests.post()`. Bằng chứng sink nhận body đó được ghi lại trong file `reports/sink.log` (định nghĩa trong hàm `Handler.do_POST`), từ đó làm căn cứ lưu thành `reports/attack-before.log`.
