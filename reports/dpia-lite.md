# DPIA-lite — điền trong checkpoint 5

1. Loại dữ liệu và phân loại:
- **Dữ liệu tài liệu hỗ trợ (`corpus/*.md`)**: Phân loại `internal` (hoặc `public`). Chứa yêu cầu dịch vụ của khách hàng và có thể chứa nội dung không tin cậy (untrusted content / prompt injection payload) do người ngoài cài cắm.
- **Dữ liệu hồ sơ khách hàng (`data/customers.json`)**: Phân loại `restricted`. Chứa thông tin định danh cá nhân nhạy cảm (PII) gồm: CCCD (12 chữ số), số điện thoại, số tài khoản ngân hàng (STK), họ tên, email, và danh mục `related_tickets`.
- **Dữ liệu nhật ký kiểm toán (`reports/ledger.jsonl`)**: Phân loại `internal`. Chứa thông tin lịch sử gọi công cụ, hash tham số (`args_hash`), phân loại dữ liệu, danh tính uỷ quyền (`on_behalf_of`), quyết định allow/deny và lý do (`reason`). Tuyệt đối không lưu PII thô trong ledger.

2. Mục đích xử lý và principal:
- Hệ thống áp dụng nguyên tắc đặc quyền tối thiểu (Least Privilege) với các principal mô phỏng:
  + `support_l1`: Hỗ trợ khách hàng cấp 1. Mục đích: `summarize-tickets`, `support-reply`. Chỉ được phép gọi `search_docs`, bị từ chối gọi `read_customer` và `http_post`.
  + `dpo`: Cán bộ bảo vệ dữ liệu (Data Protection Officer). Mục đích: `summarize-tickets`, `support-reply`, `privacy-audit`. Được phép gọi `search_docs` và `read_customer` cho hồ sơ hợp lệ gắn với ticket.
  + Tuyệt đối không principal nào được cấp quyền `http_post` dữ liệu `restricted` ra ngoài mạng.

3. Dữ liệu đi qua những run/tool nào, endpoint nào:
- **Run A (`lab24-agent/run-a`)**: Gọi tool `search_docs` đọc các file Markdown trong `corpus/`. Tách và chỉ trích xuất danh sách `ticket_id` dạng số nguyên từ tên file (ví dụ `ticket-901.md` -> 901) chuyển sang Run B. Toàn bộ free text từ người dùng/kẻ tấn công bị cô lập tại Run A.
- **Run B (`lab24-agent/run-b`)**: Tiếp nhận danh sách `ticket_id`, đối chiếu trường `related_tickets` trong `data/customers.json` để xác định khách hàng hợp lệ (không chấp nhận bất kỳ customer ID nào nêu trong free text). Kiểm tra PEP trước khi gọi `read_customer`.
- **Tool `http_post`**: Nhắm tới endpoint exfiltration `http://127.0.0.1:10024/reconcile`. Khi phát hiện chỉ thị gọi network cho dữ liệu `restricted`, PEP tại `agent/policy.py` lập tức từ chối và ngăn chặn việc kích hoạt request HTTP.

4. Bằng chứng deny/allow và giới hạn của mock:
- **Bằng chứng Allow**: Ghi nhận trong `reports/ledger.jsonl` đối với `search_docs` (cho cả `support_l1` và `dpo`) và `read_customer` (cho `dpo` với mục đích `support-reply`).
- **Bằng chứng Deny**: Ghi nhận trong `reports/ledger.jsonl` dòng `http_post` bị `deny` với reason: `"Chặn egress cho dữ liệu restricted: không được phép gửi dữ liệu bảo mật ra ngoài mạng."` và `on_behalf_of: "dpo"`. Đồng thời `reports/attack-after.log` hoàn toàn rỗng (0 bytes).
- **Giới hạn của mock**:
  + Thao tác hoàn toàn trên dữ liệu tổng hợp (synthetic) trong môi trường localhost `127.0.0.1:10024`.
  + Mock LLM là bộ so khớp quy tắc tất định (deterministic) phục vụ chấm điểm tự động và tái lập kết quả; không mô phỏng toàn diện tính bất định của LLM thương mại lớn.
  + Cờ `--as` và tệp `principals.json` là mô phỏng phân quyền OBO trong phạm vi bài lab, không phải hệ thống xác thực người dùng production (như OAuth2, OIDC, Active Directory).
