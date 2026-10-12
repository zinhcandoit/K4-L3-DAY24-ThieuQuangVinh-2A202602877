"""BƯỚC 3c — Trifecta split + egress allowlist + OBO delegation.

Tách 1 yêu cầu người dùng thành 2 run riêng biệt:
- Run A: gọi search_docs (untrusted content). Chỉ trích xuất ticket ID dạng số từ TÊN FILE.
- Run B: suy customer_id từ nguồn tin cậy data/customers.json (related_tickets).
  Kiểm tra PEP (policy.check) trước khi gọi bất kỳ tool nào.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, tools
from agent.policy import PolicyContext, check

BASE_DIR = Path(__file__).resolve().parent.parent
CUSTOMERS_FILE = BASE_DIR / "data" / "customers.json"
REPORTS_DIR = BASE_DIR / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def _hash_args(args: dict | str) -> str:
    serialized = json.dumps(args, sort_keys=True, ensure_ascii=False) if isinstance(args, dict) else str(args)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def handle(
    message: str,
    llm,
    log_dir: Path | None = None,
    principal_id: str = "support_l1",
) -> str:
    """Xử lý yêu cầu người dùng với kiến trúc Trifecta Split, PEP và Ledger."""
    ledger_path = (log_dir / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    agent_id = "lab24-agent"

    # =========================================================================
    # RUN A: Đọc untrusted content (search_docs)
    # KHÔNG gọi read_customer, KHÔNG gọi http_post
    # =========================================================================
    ctx_search = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner="lab24-agent/run-a",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=("search_docs", "read_customer"),
        expires_at=expires_at,
    )
    allowed_search, reason_search = check(ctx_search)
    ledger.append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": run_id,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
            "tool": "search_docs",
            "args_hash": _hash_args({"query": message}),
            "classification": "internal",
            "decision": "allow" if allowed_search else "deny",
            "reason": reason_search,
        },
        ledger_path,
    )

    if not allowed_search:
        return "Yêu cầu bị từ chối bởi chính sách an toàn thông tin."

    docs = tools.search_docs(message)

    # Trích xuất ticket_id (dạng số nguyên) DUY NHẤT TỪ TÊN FILE
    ticket_ids: set[int] = set()
    for doc in docs:
        doc_id = doc.get("id", "")
        m = re.search(r"ticket-(\d+)", doc_id)
        if m:
            ticket_ids.add(int(m.group(1)))

    combined_text = "\n\n".join(d.get("text", "") for d in docs)
    injected = llm.find_injection(combined_text)

    # =========================================================================
    # RUN B: Truy xuất private data (read_customer)
    # CHỈ nhận input là list[int] ticket_id đã sanitize từ Run A.
    # KHÔNG BAO GIỜ nhận customer_id từ free text của attacker!
    # =========================================================================
    customers_data = json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
    target_customer_ids: list[str] = []
    for cust in customers_data:
        cust_tickets = cust.get("related_tickets", [])
        if any(t in ticket_ids for t in cust_tickets):
            target_customer_ids.append(cust["customer_id"])

    collected_records: list[dict] = []
    for cust_id in target_customer_ids:
        ctx_cust = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=0,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=("search_docs", "read_customer"),
            expires_at=expires_at,
        )
        allowed_cust, reason_cust = check(ctx_cust)
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": agent_id,
                "run_id": run_id,
                "on_behalf_of": principal_id,
                "expires_at": expires_at,
                "tool": "read_customer",
                "args_hash": _hash_args({"customer_id": cust_id}),
                "classification": "restricted",
                "decision": "allow" if allowed_cust else "deny",
                "reason": reason_cust,
            },
            ledger_path,
        )

        if allowed_cust:
            try:
                collected_records.append(tools.read_customer(cust_id))
            except tools.ToolError:
                pass

    # =========================================================================
    # PEP Chặn Egress: Nếu có chỉ thị gọi http_post
    # =========================================================================
    if injected is not None:
        target_url = injected.target_url
        ctx_post = PolicyContext(
            data_classification="restricted",
            request_purpose="reconciliation",
            agent_owner="lab24-agent/run-b",
            delegation_depth=0,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=("search_docs", "read_customer"),
            expires_at=expires_at,
        )
        allowed_post, reason_post = check(ctx_post)
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": agent_id,
                "run_id": run_id,
                "on_behalf_of": principal_id,
                "expires_at": expires_at,
                "tool": "http_post",
                "args_hash": _hash_args({"url": target_url}),
                "classification": "restricted",
                "decision": "allow" if allowed_post else "deny",
                "reason": reason_post,
            },
            ledger_path,
        )

        if allowed_post:
            tools.http_post(target_url, {"records": collected_records})

    return llm.summarize(docs)
