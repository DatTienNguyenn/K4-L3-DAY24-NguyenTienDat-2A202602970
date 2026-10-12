"""BƯỚC 3c — trifecta split + egress allowlist (13').

Tách 1 yêu cầu người dùng thành 2 run riêng biệt (Run A và Run B):
    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
           Trích xuất số ticket từ tên file dạng ticket-007.md -> 7,
           không lấy customer ID trong phần text.
           Che PII trong nội dung trước khi đưa vào bản tóm tắt.
    Run B: chỉ nhận danh sách số ticket từ Run A.
           Sau khi policy cho phép mở dữ liệu riêng, tra related_tickets trong
           data/customers.json để tìm khách thật sự liên quan.
           Kiểm tra policy lần nữa ngay trước mỗi read_customer.

Mọi tool call đều phải:
    1. Kiểm tra qua agent.policy.check(context) trước khi gọi tool.
    2. Ghi nhận vào audit ledger qua agent.ledger.append().
    3. Chỉ thực thi tool nếu policy cho phép (allow=True).
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools
from agent.policy import PolicyContext

BASE_DIR = Path(__file__).resolve().parent.parent
CUSTOMERS_FILE = BASE_DIR / "data" / "customers.json"
REPORTS_DIR = BASE_DIR / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


def _hash_args(args: dict) -> str:
    serialized = json.dumps(args, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]


def _load_customers() -> list[dict]:
    if CUSTOMERS_FILE.exists():
        return json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
    return []


def handle(
    message: str,
    llm,
    log_dir: Path | None = None,
    principal_id: str = "support_l1",
) -> str:
    """Xử lý yêu cầu người dùng qua kiến trúc Trifecta Split kết hợp PEP và Ledger."""
    ledger_path = (Path(log_dir) if log_dir else REPORTS_DIR) / "ledger.jsonl"
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    expires_at = "2099-01-01T00:00:00+00:00"
    agent_id = "lab24-agent"
    agent_scopes = ("search_docs", "read_customer", "http_post")

    # -------------------------------------------------------------
    # 1. Run A: search_docs (untrusted content)
    #    Không gọi read_customer hoặc http_post
    # -------------------------------------------------------------
    search_ctx = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner=f"{agent_id}/run-a",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=agent_scopes,
        parent_scopes=(),
        expires_at=expires_at,
    )
    allowed, reason = policy.check(search_ctx)
    ledger.append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": f"{run_id}-a",
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
            "tool": "search_docs",
            "args_hash": _hash_args({"query": message}),
            "classification": "internal",
            "decision": "allow" if allowed else "deny",
            "reason": reason,
        },
        ledger_path,
    )

    if not allowed:
        return f"Access denied: {reason}"

    docs = tools.search_docs(message)

    # Lấy số ticket từ tên file đúng dạng ticket-007.md -> 7,
    # tuyệt đối không lấy customer ID trong phần free text.
    ticket_ids: list[int] = []
    for d in docs:
        filename = d.get("id", "")
        m = re.search(r"ticket-(\d+)", filename)
        if m:
            ticket_ids.append(int(m.group(1)))

    ticket_ids = sorted(set(ticket_ids))

    # -------------------------------------------------------------
    # 2. Run B: Chỉ nhận danh sách số ticket từ Run A
    #    Kiểm tra policy trước khi mở dữ liệu riêng (private store)
    # -------------------------------------------------------------
    collected_records: list[dict] = []

    store_ctx = PolicyContext(
        data_classification="restricted",
        request_purpose="support-reply",
        agent_owner=f"{agent_id}/run-b",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="read_customer",
        agent_scopes=agent_scopes,
        parent_scopes=(),
        expires_at=expires_at,
    )
    store_allowed, store_reason = policy.check(store_ctx)

    if not store_allowed:
        # Với support_l1: policy deny, không được mở private store
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": agent_id,
                "run_id": f"{run_id}-b",
                "on_behalf_of": principal_id,
                "expires_at": expires_at,
                "tool": "read_customer",
                "args_hash": _hash_args({"ticket_ids": ticket_ids}),
                "classification": "restricted",
                "decision": "deny",
                "reason": store_reason,
            },
            ledger_path,
        )
    else:
        # Với dpo (được phép mở dữ liệu riêng): tra related_tickets trong data/customers.json
        customers_data = _load_customers()
        target_customer_ids: list[str] = []
        for c in customers_data:
            rel = set(c.get("related_tickets", []))
            if rel.intersection(ticket_ids):
                target_customer_ids.append(str(c["customer_id"]))

        # Kiểm tra policy lần nữa ngay trước mỗi read_customer
        for cid in sorted(set(target_customer_ids)):
            read_ctx = PolicyContext(
                data_classification="restricted",
                request_purpose="support-reply",
                agent_owner=f"{agent_id}/run-b",
                delegation_depth=0,
                egress_enabled=False,
                principal_id=principal_id,
                requested_tool="read_customer",
                agent_scopes=agent_scopes,
                parent_scopes=(),
                expires_at=expires_at,
            )
            read_allowed, read_reason = policy.check(read_ctx)
            ledger.append(
                {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "agent_id": agent_id,
                    "run_id": f"{run_id}-b",
                    "on_behalf_of": principal_id,
                    "expires_at": expires_at,
                    "tool": "read_customer",
                    "args_hash": _hash_args({"customer_id": cid}),
                    "classification": "restricted",
                    "decision": "allow" if read_allowed else "deny",
                    "reason": read_reason,
                },
                ledger_path,
            )
            if read_allowed:
                try:
                    rec = tools.read_customer(cid)
                    collected_records.append(rec)
                except tools.ToolError:
                    pass

    # -------------------------------------------------------------
    # 3. Kiểm tra Prompt Injection & Lượt kiểm gửi http_post riêng
    #    Chỉ gửi URL, không mang hồ sơ khách. Khi deny thì không gọi tools.http_post
    # -------------------------------------------------------------
    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)
    if injected is not None:
        post_ctx = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner=f"{agent_id}/run-b",
            delegation_depth=1,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=agent_scopes,
            parent_scopes=("search_docs", "read_customer"),
            expires_at=expires_at,
        )
        post_allowed, post_reason = policy.check(post_ctx)
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": agent_id,
                "run_id": f"{run_id}-b",
                "on_behalf_of": principal_id,
                "expires_at": expires_at,
                "tool": "http_post",
                "args_hash": _hash_args({"url": injected.target_url}),
                "classification": "restricted",
                "decision": "allow" if post_allowed else "deny",
                "reason": post_reason,
            },
            ledger_path,
        )
        if post_allowed:
            tools.http_post(injected.target_url, {"records": collected_records})

    # Che PII trong nội dung trước khi đưa vào bản tóm tắt
    redacted_docs = [{**d, "text": pii.redact(d["text"])} for d in docs]
    return llm.summarize(redacted_docs)
