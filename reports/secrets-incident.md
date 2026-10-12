# Secret giả trong lịch sử Git — điền trong checkpoint 4

- Scanner và phiên bản: Gitleaks v8.30.1
- Commit chứa token giả: Commit 1bdd849 (`1bdd849922156c868a5ee9293d68f5b72e242d2c` - "chore: seed student lab with synthetic secret exercise")
- File, rule và kết quả quét lịch sử:
  - File: `lab-fake-secret.txt`
  - Rule: `lab24-synthetic-token` (cấu hình trong `.gitleaks.toml`)
  - Kết quả quét lịch sử: Lệnh `gitleaks git --config .gitleaks.toml --redact .` trả về mã lỗi 1 (`WRN leaks found: 1`), phát hiện chính xác token giả `LAB24_FAKE_TOKEN` tồn tại trong lịch sử commit `1bdd849`.
- Kết quả quét file hiện tại:
  - Lệnh `gitleaks dir --config .gitleaks.toml --redact .` trả về mã 0 (`INF no leaks found`), do file `lab-fake-secret.txt` đã được xoá khỏi thư mục làm việc ở các commit sau.
- Lần quét đầu và lý do chỉnh allowlist:
  - Ở lần quét ban đầu, nếu scanner quét qua thư mục môi trường ảo `.venv/` có thể bắt các chuỗi mẫu thử trong thư viện bên thứ ba (false positive).
  - Để ngăn ngừa false positive mà không tắt bỏ rule hay bỏ qua cả repo, đã bổ sung allowlist đường dẫn `paths = ['''\.venv/''']` trong `.gitleaks.toml`.
- Nếu đây là credential thật, cần xử lý thế nào:
  1. Thu hồi / Rotate ngay lập tức secret/token tại dịch vụ cấp token (nhà cung cấp dịch vụ, IdP, cloud provider). Xoá file ở commit mới không làm token cũ tự vô hiệu.
  2. Kiểm tra log kiểm toán (audit logs) và nhật ký truy cập để rà soát hành vi sử dụng trái phép/lạm dụng trong khoảng thời gian token bị lộ.
  3. Xử lý các bản sao: Xoá bỏ triệt để khỏi lịch sử Git (sử dụng `git-filter-repo` hoặc BFG Repo-Cleaner) trên remote repository, thông báo cho toàn bộ đội ngũ fork/clone repo cập nhật bản sao sạch.
- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:
  - Xoá file ở commit mới chỉ xoá ở nhánh HEAD hiện tại, commit cũ chứa secret vẫn vĩnh viễn nằm trong git tree history (object database). Bất kỳ ai clone repo đều có thể checkout commit cũ (`git checkout 1bdd849` hoặc `git log -p`) để đọc nguyên văn secret.
  - Pin dependency chỉ bảo vệ chuỗi cung ứng khỏi gói độc hại, hoàn toàn không vô hiệu hóa được credential đã bị lộ trong lịch sử. Token chỉ thực sự an toàn khi được thu hồi/rotate tại phía dịch vụ cấp.
