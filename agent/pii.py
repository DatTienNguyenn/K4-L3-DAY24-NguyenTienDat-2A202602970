"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re

# Regex cho từng loại PII
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# STK thường đi kèm nhãn STK / số tài khoản / tài khoản (8-16 chữ số)
_BANK_RE = re.compile(
    r"(?i:\b(?:stk|số tài khoản|so tai khoan|tài khoản số|tài khoản)\s*[:.-]?\s*)(\d{8,16})\b"
)

# CCCD: 12 chữ số liên tiếp
_CCCD_RE = re.compile(r"\b\d{12}\b")

# Số điện thoại: bắt đầu bằng 0 hoặc +84, 10-11 chữ số, có thể có khoảng trắng/gạch ngang/chấm
_PHONE_RE = re.compile(r"(?<!\d)(?:0|\+84)(?:[.\s-]?\d){9,10}(?!\d)")


def detect(text: str) -> list[dict]:
    """Phát hiện các thực thể PII trong văn bản: VN_CCCD, VN_PHONE, VN_BANK_ACCOUNT, EMAIL.

    Trả về danh sách dict: {"type": str, "start": int, "end": int}
    """
    candidates: list[dict] = []

    # 1. Email (độ chính xác cao, nhận diện trước)
    for m in _EMAIL_RE.finditer(text):
        candidates.append({"type": "EMAIL", "start": m.start(), "end": m.end()})

    # 2. VN_BANK_ACCOUNT (có ngữ cảnh STK / số tài khoản)
    for m in _BANK_RE.finditer(text):
        candidates.append({"type": "VN_BANK_ACCOUNT", "start": m.start(1), "end": m.end(1)})

    # 3. VN_CCCD (12 chữ số)
    for m in _CCCD_RE.finditer(text):
        candidates.append({"type": "VN_CCCD", "start": m.start(), "end": m.end()})

    # 4. VN_PHONE (bắt đầu bằng 0/+84, 10-11 số)
    for m in _PHONE_RE.finditer(text):
        candidates.append({"type": "VN_PHONE", "start": m.start(), "end": m.end()})

    # Xử lý vùng trùng lắp (overlap resolution theo độ ưu tiên):
    # EMAIL > VN_BANK_ACCOUNT > VN_CCCD > VN_PHONE
    accepted: list[dict] = []
    for cand in candidates:
        s, e = cand["start"], cand["end"]
        # Kiểm tra trùng với các vùng đã chấp nhận
        overlap = any(max(s, acc["start"]) < min(e, acc["end"]) for acc in accepted)
        if not overlap:
            accepted.append(cand)

    # Sắp xếp theo vị trí xuất hiện trong chuỗi
    accepted.sort(key=lambda x: (x["start"], x["end"]))
    return accepted


def redact(text: str) -> str:
    """Thay thế các vùng PII được phát hiện bằng [REDACTED_<TYPE>].

    Thay từ cuối chuỗi về đầu để vị trí offset các vùng phía trước không bị lệch.
    """
    entities = detect(text)
    # Sắp xếp từ cuối chuỗi về đầu (start giảm dần)
    for ent in sorted(entities, key=lambda x: x["start"], reverse=True):
        replacement = f"[REDACTED_{ent['type']}]"
        text = text[: ent["start"]] + replacement + text[ent["end"] :]
    return text
