# Baseline — điền trong checkpoint 1

1. Agent có identity mỗi run chưa? Dẫn file/hàm:
Chưa có. Trong `agent/loop.py` hàm `_naive_loop(message: str, llm)` (dòng 27–55), hàm không nhận hay tạo bất kỳ định danh nào (`run_id`, `agent_id`, `principal_id`, `on_behalf_of`). Mọi run chạy vô danh, không phân biệt người dùng hay ngữ cảnh uỷ quyền.

2. Ai cho phép `http_post`? Dẫn file/hàm:
Không có cơ chế hoặc chủ thể nào cho phép/phê duyệt. Trong `agent/loop.py` hàm `_naive_loop` (dòng 43–45), agent trực tiếp gọi `tools.http_post(injected.target_url, {"records": collected})` mà không qua bất kỳ lớp Policy Enforcement Point (PEP) hay kiểm tra quyền nào (`agent/policy.py` hoàn toàn bị bỏ qua). Chỉ có ràng buộc cứng duy nhất là allowlist mạng trong `agent/tools.py` hàm `http_post` (dòng 76–83) giới hạn localhost `127.0.0.1:10024`.

3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:
Phía agent hoàn toàn không có bằng chứng hay log kiểm toán nào (chưa có audit ledger ghi nhận tool call, parameters hay decisions). Bằng chứng duy nhất về việc gửi sai PII nằm ở phía receiver (sink server) tại file `reports/sink.log`, do hàm `make_handler` / `do_POST` trong `sink/sink.py` (dòng 42–47) ghi lại toàn bộ nội dung body nhận được từ request POST.
