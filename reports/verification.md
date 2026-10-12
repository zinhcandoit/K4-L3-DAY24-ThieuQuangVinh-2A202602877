# Verification — điền trước khi nộp

- OS / Python / Gitleaks version:
  - OS: Windows 11 Home Single Language (64-bit)
  - Python: 3.13.7 (in virtual environment `.venv`)
  - Gitleaks: 8.30.1

- `python -m pytest tests/ -q`:
  - Kết quả: `33 passed in 7.58s` (100% test cases đạt).
  - Bao gồm: `test_check_lure_cli.py` (3 passed), `test_injection.py` (8 passed), `test_ledger.py` (3 passed), `test_obo.py` (5 passed), `test_pii.py` (2 passed, recall 100%, precision 100%), `test_policy.py` (4 passed), `test_scaffold_dispatch.py` (4 passed), `test_split.py` (1 passed), `test_supply_chain.py` (3 passed).

- `pre-commit run --all-files`:
  - Hook `gitleaks-system` (pin `rev: v8.30.1`, `pass_filenames: false`):
    `Detect hardcoded secrets.................................................Passed`
  - Exit code: 0.

- Ledger verify:
  - Lệnh kiểm tra: `python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"`
  - Kết quả: `True` (chuỗi hash chain toàn vẹn, 100% entry có reason hợp lệ).

- Các lỗi còn lại:
  - Không có (0 lỗi còn lại).
  - Toàn bộ 5 điều kiện trượt trong RUBRIC.md đều được đảm bảo:
    1. 100% ledger entry có `reason` non-empty.
    2. PII của `KH-000999` không bao giờ ra tới sink sau containment (`reports/attack-after.log` rỗng 0 bytes).
    3. Runner không đọc `KH-000777` khi ID chỉ xuất hiện trong free text của kẻ tấn công (chỉ suy từ `related_tickets` của ticket hợp lệ).
    4. `support_l1` bị chặn hoàn toàn khi cố đọc record restricted; agent không bao giờ vượt quyền của `parent_scopes`.
    5. Không chứa credential thật hay dữ liệu cá nhân thật (token giả `LAB24-DEMO` nằm trong lịch sử git commit `1bdd849` và đã được quét nhận diện đầy đủ bởi Gitleaks).
