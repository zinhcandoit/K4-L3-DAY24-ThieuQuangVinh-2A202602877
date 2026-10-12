"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict:
    if PRINCIPALS_FILE.exists():
        return json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))
    return {}


def check(context: PolicyContext) -> tuple[bool, str]:
    """Kiểm tra chính sách an toàn thông tin và phân quyền (OBO PEP).

    Trả về (allow, reason).
    reason KHÔNG BAO GIỜ được để trống.
    """
    # 1. Rule tối thiểu: Dữ liệu restricted đi kèm egress phải bị DENY tuyệt đối
    if context.data_classification == "restricted" and context.egress_enabled is True:
        return (
            False,
            "Chặn egress cho dữ liệu restricted: không được phép gửi dữ liệu bảo mật ra ngoài mạng.",
        )

    # 2. Kiểm tra thời hạn hiệu lực (expires_at)
    if context.expires_at:
        try:
            exp_time = datetime.fromisoformat(context.expires_at)
            # Chuẩn hóa về UTC nếu có timezone info
            now = datetime.now(timezone.utc)
            if exp_time.tzinfo is None:
                exp_time = exp_time.replace(tzinfo=timezone.utc)
            if now > exp_time:
                return (
                    False,
                    f"Phiên uỷ quyền đã hết hạn lúc {context.expires_at}.",
                )
        except Exception:
            return (False, f"Định dạng expires_at không hợp lệ: {context.expires_at}.")

    # 3. Kiểm tra principal (mô phỏng OBO)
    principals = _load_principals()
    if not context.principal_id or context.principal_id not in principals:
        return (
            False,
            f"Danh tính principal không hợp lệ hoặc không xác định: '{context.principal_id}'.",
        )

    principal_info = principals[context.principal_id]

    # 4. Kiểm tra mục đích yêu cầu (purpose)
    allowed_purposes = principal_info.get("purposes", [])
    if context.request_purpose and allowed_purposes and context.request_purpose not in allowed_purposes:
        return (
            False,
            f"Mục đích '{context.request_purpose}' không được phép đối với principal '{context.principal_id}'.",
        )

    # 5. Kiểm tra quyền hiệu lực (effective permissions)
    # Quyền hiệu lực = principal.allowed_tools ∩ agent_scopes
    principal_tools = set(principal_info.get("allowed_tools", []))
    if context.agent_scopes:
        effective_tools = principal_tools & set(context.agent_scopes)
    else:
        effective_tools = principal_tools

    # Nếu delegation_depth > 0: giao tiếp với parent_scopes
    if context.delegation_depth > 0:
        parent_tools = set(context.parent_scopes)
        effective_tools = effective_tools & parent_tools

    if context.requested_tool:
        if context.requested_tool not in effective_tools:
            return (
                False,
                f"Principal '{context.principal_id}' không có quyền gọi tool '{context.requested_tool}' "
                f"(quyền hiệu lực: {sorted(effective_tools)}).",
            )

    return (
        True,
        f"Chấp thuận: principal '{context.principal_id}' được phép gọi tool '{context.requested_tool}' "
        f"với mục đích '{context.request_purpose}'.",
    )
