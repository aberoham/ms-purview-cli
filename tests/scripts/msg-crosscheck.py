# /// script
# requires-python = ">=3.11"
# dependencies = ["extract-msg==0.55.0"]
# ///
"""Cross-check `purview export read` against extract-msg (development only).

    uv run tests/scripts/msg-crosscheck.py <items.zip> <export-read.jsonl>

Reads every .msg in the items zip with extract-msg, from memory, and compares
subject, sender address, To and CC addresses (local parts, as sets), sent time
and body text with the records `purview export read` wrote for the same zip.
A field empty in both readers is counted apart, not as agreeing. Prints counts
only, never a value, so it can run on a private export: items compared,
agreements and differences per field, and items either reader could not read.
Exits 1 when a field differs on any item both readers read, or a record is
missing.

The shipped binary never needs this script or Python (AGENTS.md).
"""

import difflib
import html
import io
import json
import re
import sys
import zipfile
from collections import Counter
from datetime import UTC
from email.utils import getaddresses

import extract_msg


def words(text):
    return re.sub(r"\s+", " ", re.sub(r"[^\w@.]+", " ", text or "")).strip().lower()


def html_text(raw):
    """extract-msg's HTML body as rough text, for the word comparison."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    raw = re.sub(r"(?is)<(head|style|script)\b.*?</\1\s*>|<!--.*?-->", " ", raw or "")
    return html.unescape(re.sub(r"<[^>]+>", " ", raw))


def address(mailbox):
    return (mailbox or {}).get("address") or ""


def locals_in(listed):
    """The local parts of the addresses in an extract-msg header string,
    whose recipients are separated by `;`."""
    return {
        addr.split("@")[0].lower()
        for _, addr in getaddresses((listed or "").split(";"))
        if "@" in addr
    }


def main(argv):
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    zip_path, jsonl_path = argv
    ours = {}
    with open(jsonl_path, encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            ours[record["entry"]] = record
    counts = Counter()
    with zipfile.ZipFile(zip_path) as archive:
        for name in archive.namelist():
            if not name.lower().endswith(".msg"):
                continue
            counts["items"] += 1
            record = ours.get(name)
            if record is None:
                counts["missing from export read"] += 1
                continue
            if record.get("error"):
                counts["export read error: " + record["error"]] += 1
            try:
                message = extract_msg.openMsg(io.BytesIO(archive.read(name)))
            except Exception:  # noqa: BLE001 - any failure is a count
                counts["extract-msg could not read"] += 1
                continue
            try:
                sent = message.date.astimezone(UTC) if message.date else None
                theirs = {
                    # extract-msg keeps a trailing NUL that the format pads with.
                    "subject": (message.subject or "").rstrip("\0"),
                    "from": (message.sender or ""),
                    "to": message.to or "",
                    "cc": message.cc or "",
                    # The same instant, which extract-msg gives in local time.
                    "sent": sent.strftime("%Y-%m-%dT%H:%M:%SZ") if sent else "",
                    "body": message.body or html_text(message.htmlBody),
                }
            except Exception:  # noqa: BLE001
                counts["extract-msg could not read a field"] += 1
                continue
            checks = {}
            for field in ("subject", "sent"):
                if (record.get(field) or "") or theirs[field]:
                    checks[field] = (record.get(field) or "") == theirs[field]
                else:
                    counts[f"{field}: empty in both"] += 1
            ours_from = address(record.get("from")).lower()
            their_from = locals_in(theirs["from"])
            if ours_from.startswith("/") and not their_from:
                # No SMTP sender: the Exchange address against a display name.
                counts["from: no SMTP address in either"] += 1
            elif ours_from or their_from:
                checks["from"] = {ours_from.split("@")[0]} == their_from
            else:
                counts["from: empty in both"] += 1
            # A recipient can be shown under another of its addresses, so the
            # local parts are compared, as sets.
            for field in ("to", "cc"):
                ours_set = {address(m).split("@")[0].lower() for m in record.get(field) or []}
                theirs_set = locals_in(theirs[field])
                if not theirs_set and theirs[field].strip():
                    # extract-msg shows display names only.
                    counts[f"{field}: no SMTP addresses from extract-msg"] += 1
                elif ours_set or theirs_set:
                    checks[field] = ours_set == theirs_set
            if theirs["body"].strip():
                ratio = difflib.SequenceMatcher(
                    None, words(record.get("body")), words(theirs["body"]), autojunk=False
                ).ratio()
                checks["body"] = bool(record.get("body")) and ratio >= 0.8
            else:
                counts["body: extract-msg has none"] += 1
            for field, same in checks.items():
                counts[f"{field}: {'agree' if same else 'differ'}"] += 1
    for key in sorted(counts):
        print(f"{key}: {counts[key]}")
    failed = any(key.endswith(": differ") for key in counts) or counts["missing from export read"]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
