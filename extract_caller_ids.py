#!/usr/bin/env python3
"""Extract scammer-attributed phone numbers from the NCSU/FTC PoNE corpus.

Two complementary sources:
  1. PDF cease-and-desist letters — the originating caller-IDs of the
     illegal robocalls the FTC documented.
  2. metadata.csv transcripts — callback numbers the scammers themselves
     spoke on the recordings ("press 1 or call us back at...").

Output: caller_ids.csv with the normalized E.164 number, where it came from,
the surrounding context, and a heuristic flag for likely FTC / admin numbers
(those tend to appear across many letters, real scam numbers tend to appear
in one).

Run from the repo root:  python extract_caller_ids.py
"""

from __future__ import annotations

import csv
import re
import sys
from collections import defaultdict
from pathlib import Path

import pdfplumber

# US/NANP phone-number regex.  Tolerates these formats:
#   (315) 232-8257     315-232-8257     315.232.8257     3152328257
#   +1 315 232 8257    1-315-232-8257   +13152328257
# Negative look-around prevents grabbing parts of longer digit runs.
PHONE_RE = re.compile(
    r"(?<!\d)"
    r"(?:\+?1[\s\-\.‐-―]?)?"        # optional country code
    r"\(?(\d{3})\)?[\s\-\.‐-―]?"    # area code
    r"(\d{3})[\s\-\.‐-―]?"          # exchange
    r"(\d{4})"                                # subscriber
    r"(?!\d)"
)

# Hard-exclude list: published contacts for the FTC, FCC, IRS, SSA, etc.
# These will show up all over the PoNE letters as part of letterhead /
# enforcement-contact boilerplate and are obviously not scam numbers.
HARD_EXCLUDE = {
    "8773824357",  # 1-877-FTC-HELP
    "8883821222",  # DoNotCall.gov report line
    "8003821222",  # DNC alt
    "2023262222",  # FTC HQ
    "2023262040",  # FTC press
    "8662902236",  # FTC TTY
    "8888255322",  # 1-888-CALL-FCC
    "8002255322",  # FCC alt
    "8008294933",  # real IRS business
    "8008291040",  # real IRS individual
    "8006221234",  # SSA
    "8007727115",  # SSA fraud
    "8003663998",  # OIG hotline
    "2024183300",  # FCC HQ
    "8002255322",  # FCC consumer
}
# FTC HQ extensions are 202-326-XXXX; FCC HQ extensions are 202-418-XXXX.
EXCLUDE_PREFIXES = ("202326", "202418", "202382")


def is_valid_nanp(num: str) -> bool:
    """Filter obviously invalid 10-digit strings (years, ZIP+phone joins, etc.)."""
    if len(num) != 10:
        return False
    area = num[:3]
    exch = num[3:6]
    # NANP: area / exchange must be 200-999, can't be N11
    if not (200 <= int(area) <= 999):
        return False
    if not (200 <= int(exch) <= 999):
        return False
    if area[1:3] == "11" or exch[1:3] == "11":
        return False
    return True


def looks_excluded(num: str) -> bool:
    if num in HARD_EXCLUDE:
        return True
    return any(num.startswith(p) for p in EXCLUDE_PREFIXES)


def extract_category(ctx: str, num: str) -> str:
    """Pull the campaign tag from PoNE call-record tables.

    Each row looks like:  ... DATE DATE 17244428039 Utility-SupplyCharges /attachments/...
    The category sits between the phone digits and the word 'attachments'
    (sometimes truncated by pdfplumber to 'tachments' / 'chments' / 'achments').
    Returns the category string, or '' if this context is not a table row.
    """
    digits_idx = ctx.find(num)
    if digits_idx < 0:
        # number may be hyphenated in context; bail rather than be clever
        return ""
    after = ctx[digits_idx + len(num):]
    for marker in ("attachments", "tachments", "achments", "chments"):
        i = after.find(marker)
        if i > 0:
            cat = after[:i].strip(" / ")
            if 3 <= len(cat) <= 60 and not cat.lower().startswith("http"):
                return cat
            return ""
    return ""


def extract_from_text(
    text: str,
    source_kind: str,
    source_id: str,
    by_number: dict[str, list[tuple[str, str, str, str]]],
) -> None:
    for m in PHONE_RE.finditer(text):
        area, exch, sub = m.groups()
        num = area + exch + sub
        if not is_valid_nanp(num):
            continue
        if looks_excluded(num):
            continue
        start = max(0, m.start() - 80)
        end = min(len(text), m.end() + 80)
        ctx = re.sub(r"\s+", " ", text[start:end]).strip()
        cat = extract_category(ctx, num) if source_kind == "pdf" else ""
        by_number[num].append((source_kind, source_id, ctx, cat))


def main() -> int:
    base = Path(__file__).resolve().parent
    pdf_dir = base / "pdf_files"
    meta_csv = base / "metadata.csv"
    out_csv = base / "caller_ids.csv"

    if not pdf_dir.exists():
        sys.exit(f"pdf_files/ not found at {pdf_dir}")

    by_number: dict[str, list[tuple[str, str, str]]] = defaultdict(list)

    # -- 1) PDFs ------------------------------------------------------
    pdfs = sorted(pdf_dir.glob("*.pdf"))
    print(f"[pdfs] processing {len(pdfs)} cease-and-desist letters", flush=True)
    for i, pdf in enumerate(pdfs, 1):
        try:
            with pdfplumber.open(pdf) as doc:
                text = "\n".join((p.extract_text() or "") for p in doc.pages)
        except Exception as exc:
            print(f"  ! {pdf.name}: {exc}")
            continue
        before = len(by_number)
        extract_from_text(text, "pdf", pdf.name, by_number)
        added = len(by_number) - before
        print(f"  [{i:2}/{len(pdfs)}] {pdf.name[:60]:<60} +{added:>3} new")

    # -- 2) metadata.csv transcripts ----------------------------------
    if meta_csv.exists():
        rows = list(csv.DictReader(meta_csv.open(encoding="utf-8")))
        print(f"[csv] mining {len(rows)} call transcripts for callback numbers")
        before = len(by_number)
        for row in rows:
            extract_from_text(
                row.get("transcript", "") or "",
                "transcript",
                row.get("file_name", "?"),
                by_number,
            )
        print(f"  +{len(by_number) - before} new from transcripts")

    # -- 3) rank + write ---------------------------------------------
    out_rows = []
    for num, hits in by_number.items():
        pdf_pdfs = {h[1] for h in hits if h[0] == "pdf"}
        tr_hits = [h for h in hits if h[0] == "transcript"]
        pdf_count = len(pdf_pdfs)
        tr_count = len(tr_hits)
        likely_admin = "yes" if pdf_count >= 4 else "no"
        # most common non-empty campaign category, if any
        cats = [h[3] for h in hits if h[3]]
        category = max(set(cats), key=cats.count) if cats else ""
        first_kind, first_src, first_ctx, _ = hits[0]
        pretty = f"+1 ({num[:3]}) {num[3:6]}-{num[6:]}"
        out_rows.append({
            "phone_e164": f"+1{num}",
            "phone_pretty": pretty,
            "scam_category": category,
            "total_hits": len(hits),
            "pdf_count": pdf_count,
            "transcript_count": tr_count,
            "likely_admin": likely_admin,
            "first_source": f"{first_kind}:{first_src}",
            "first_context": first_ctx[:280],
        })

    # Real (non-admin) scam-source numbers first, then by total hit count.
    out_rows.sort(key=lambda r: (r["likely_admin"] == "yes", -r["total_hits"]))

    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(out_rows[0].keys()))
        w.writeheader()
        w.writerows(out_rows)

    real = [r for r in out_rows if r["likely_admin"] == "no"]
    admin = [r for r in out_rows if r["likely_admin"] == "yes"]
    print()
    print("=" * 78)
    print(f"  unique numbers extracted   {len(out_rows):>5}")
    print(f"  flagged likely-admin       {len(admin):>5}  (appear in >= 4 PDFs)")
    print(f"  remaining scam candidates  {len(real):>5}")
    print(f"  output                     {out_csv.relative_to(base)}")
    print()
    print("Top 15 scam candidates by occurrence count:")
    for r in real[:15]:
        print(
            f"  {r['phone_pretty']:<22} "
            f"hits={r['total_hits']:>3} pdfs={r['pdf_count']} csv={r['transcript_count']}"
            f"  | {r['first_context'][:90]}"
        )
    print()
    print("Filtered as enforcement / admin boilerplate:")
    for r in admin[:8]:
        print(
            f"  {r['phone_pretty']:<22} "
            f"hits={r['total_hits']:>3} pdfs={r['pdf_count']}"
            f"  | {r['first_context'][:90]}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
