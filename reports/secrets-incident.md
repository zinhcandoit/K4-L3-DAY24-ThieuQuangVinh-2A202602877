# Secret giả trong lịch sử Git — điền trong checkpoint 4

- Scanner và phiên bản:
  Gitleaks version 8.30.1.

- Commit chứa token giả:
  `1bdd849` (`1bdd849922156c868a5ee9293d68f5b72e242d2c`) — chore: seed student lab with synthetic secret exercise.

- File, rule và kết quả quét lịch sử:
  - File: `lab-fake-secret.txt` (dòng 1).
  - Rule ID: `lab24-synthetic-token` (được định nghĩa trong `.gitleaks.toml`).
  - Kết quả lệnh `gitleaks git --config .gitleaks.toml --redact --verbose .`:
    Tìm thấy 1 leak tại commit `1bdd849`:
    Finding/Secret: `LAB24_FAKE_TOKEN=LAB24-DEMO-****************`
    Fingerprint: `1bdd849922156c868a5ee9293d68f5b72e242d2c:lab-fake-secret.txt:lab24-synthetic-token:1`
    Lệnh trả về exit code 1 theo đúng kỳ vọng khi phát hiện token rò rỉ trong lịch sử.

- Kết quả quét file hiện tại:
  - Lệnh `gitleaks dir --config .gitleaks.toml --verbose .` báo cáo: `no leaks found` (0 leaks, exit code 0).
  - File `lab-fake-secret.txt` đã bị xóa khỏi HEAD tại commit `ece6ca4`.

- Nếu đây là credential thật, cần xử lý thế nào:
  - Ngay lập tức thu hồi (revoke) và xoay vòng (rotate) credential trên hệ thống quản lý danh tính / nhà cung cấp dịch vụ (IdP, API provider, IAM).
  - Rà soát audit log trên hệ thống dịch vụ để kiểm tra xem credential bị lộ đã từng được sử dụng để truy cập hay trích xuất dữ liệu trái phép hay chưa.
  - Cắt bỏ lịch sử Git bằng công cụ chuyên dụng (`git-filter-repo` hoặc BFG Repo-Cleaner) và force push cập nhật remote, đồng thời thông báo cho toàn bộ đội ngũ liên quan.

- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:
  - Xóa file khỏi commit hiện tại (HEAD) không loại bỏ nội dung khỏi cơ sở dữ liệu đối tượng của Git; token vẫn nằm nguyên vẹn trong snapshot của commit `1bdd849` và bất kỳ ai có quyền clone repo đều đọc được.
  - Pin dependency (hash lock trong `requirements.lock`) chỉ giúp bảo vệ tính toàn vẹn của gói thư viện tải về từ PyPI nhằm ngăn ngừa supply chain poisoning, hoàn toàn không có tác dụng vô hiệu hóa một credential đã bị lộ ra ngoài.
  - Vì vậy, một khi secret đã bị lộ, biện pháp an ninh duy nhất và bắt buộc là thu hồi (revoke) và rotate secret tại nguồn phát hành.
