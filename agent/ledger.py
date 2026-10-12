"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng với chuỗi hàm băm (hash chain).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _calc_hash(entry_dict: dict) -> str:
    """Tính SHA-256 từ nội dung entry (bỏ field 'hash', sắp xếp keys)."""
    data = {k: v for k, v in entry_dict.items() if k != "hash"}
    serialized = json.dumps(data, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def append(entry: dict, path: Path) -> dict:
    """Append 1 tool call entry vào ledger với hash chain.

    Tự tính prev_hash và hash.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = "0" * 64
    if path.exists() and path.stat().st_size > 0:
        lines = [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        if lines:
            try:
                last_entry = json.loads(lines[-1])
                prev_hash = last_entry.get("hash", "0" * 64)
            except Exception:
                prev_hash = "0" * 64

    new_entry = dict(entry)
    new_entry["prev_hash"] = prev_hash
    new_entry["hash"] = _calc_hash(new_entry)

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(new_entry, ensure_ascii=False) + "\n")

    return new_entry


def verify(path: Path) -> bool:
    """Xác minh tính toàn vẹn của chuỗi hash trong ledger.

    Trả về True nếu:
    - Mọi dòng có reason non-empty
    - prev_hash khớp với hash của dòng trước
    - hash của dòng khớp với sha256 tính từ nội dung dòng
    """
    path = Path(path)
    if not path.exists():
        return False

    lines = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not lines:
        return False

    expected_prev_hash = "0" * 64
    for line in lines:
        try:
            entry = json.loads(line)
        except Exception:
            return False

        # 1. Reason không được để trống
        if not entry.get("reason"):
            return False

        # 2. prev_hash phải khớp
        if entry.get("prev_hash") != expected_prev_hash:
            return False

        # 3. hash phải khớp với giá trị tính lại
        saved_hash = entry.get("hash")
        computed_hash = _calc_hash(entry)
        if not saved_hash or saved_hash != computed_hash:
            return False

        expected_prev_hash = saved_hash

    return True
