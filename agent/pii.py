"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Nhận diện và làm mờ các thực thể dữ liệu cá nhân (CCCD, SĐT, STK, Email)
bằng Regex Recognizer cho tiếng Việt.
"""
from __future__ import annotations

import re


EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
BANK_ACCOUNT_RE = re.compile(
    r"(?:STK|số\s+tài\s+khoản|tài\s+khoản)\s*:?\s*(\d{8,16})\b",
    re.IGNORECASE,
)
CCCD_EXPLICIT_RE = re.compile(
    r"(?:CCCD|căn\s+cước(?:\s+công\s+dân)?)\s*(?:của\s+[^:]+)?\s*:?\s*(\d{12})\b",
    re.IGNORECASE,
)
CCCD_STANDALONE_RE = re.compile(r"\b\d{12}\b")
PHONE_RE = re.compile(r"\b0\d{9}\b")


def detect(text: str) -> list[dict]:
    """Nhận diện các thực thể PII trong text:
    - EMAIL
    - VN_BANK_ACCOUNT
    - VN_CCCD
    - VN_PHONE
    """
    entities: list[dict] = []

    # 1. EMAIL
    for m in EMAIL_RE.finditer(text):
        entities.append({"type": "EMAIL", "start": m.start(), "end": m.end()})

    # 2. VN_BANK_ACCOUNT (ưu tiên trước CCCD để tránh số tài khoản 12 chữ số bị nhầm)
    for m in BANK_ACCOUNT_RE.finditer(text):
        start = m.start(1)
        end = m.end(1)
        entities.append({"type": "VN_BANK_ACCOUNT", "start": start, "end": end})

    def _is_overlapping(start: int, end: int) -> bool:
        return any(
            (e["start"] <= start < e["end"]) or (e["start"] < end <= e["end"])
            for e in entities
        )

    # 3. VN_CCCD
    for m in CCCD_EXPLICIT_RE.finditer(text):
        start = m.start(1)
        end = m.end(1)
        if not _is_overlapping(start, end):
            entities.append({"type": "VN_CCCD", "start": start, "end": end})

    for m in CCCD_STANDALONE_RE.finditer(text):
        start = m.start()
        end = m.end()
        if not _is_overlapping(start, end):
            entities.append({"type": "VN_CCCD", "start": start, "end": end})

    # 4. VN_PHONE
    for m in PHONE_RE.finditer(text):
        start = m.start()
        end = m.end()
        if not _is_overlapping(start, end):
            entities.append({"type": "VN_PHONE", "start": start, "end": end})

    # Sắp xếp theo vị trí bắt đầu
    entities.sort(key=lambda x: x["start"])
    return entities


def redact(text: str) -> str:
    """Thay thế mọi PII entity được phát hiện bằng [REDACTED_<TYPE>]."""
    entities = detect(text)
    # Thay thế từ cuối văn bản về đầu để không làm lệch offset
    res = text
    for entity in sorted(entities, key=lambda x: x["start"], reverse=True):
        placeholder = f"[REDACTED_{entity['type']}]"
        res = res[: entity["start"]] + placeholder + res[entity["end"] :]
    return res
