# /// script
# requires-python = ">=3.11"
# dependencies = ["extract-msg==0.55.0"]
# ///
"""Cross-check `purview export read` against extract-msg (development only).

    uv run tests/scripts/msg-crosscheck.py <items.zip> <export-read.jsonl>

Reads every .msg in the items zip with extract-msg, from memory, and compares
subject, sender address, recipient addresses, sent time and body text with the
records `purview export read` wrote for the same zip. Prints counts only, never
a value, so it can run on a private export: items compared, agreements and
differences per field, and items either reader could not read. Exits 1 when a
field differs on any item both readers read.

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
                    # The same instant, which extract-msg gives in local time.
                    "sent": sent.strftime("%Y-%m-%dT%H:%M:%SZ") if sent else "",
                    "body": message.body or html_text(message.htmlBody),
                }
            except Exception:  # noqa: BLE001
                counts["extract-msg could not read a field"] += 1
                continue
            checks = {
                "subject": (record.get("subject") or "") == theirs["subject"],
                "sent": (record.get("sent") or "") == theirs["sent"],
            }
            ours_from = address(record.get("from")).lower()
            if ours_from.startswith("/") and "@" not in theirs["from"]:
                # No SMTP sender: the Exchange address against a display name.
                counts["from: no SMTP address in either"] += 1
            else:
                checks["from"] = ours_from in theirs["from"].lower()
            # A recipient can be shown under another of its addresses, so the
            # local part is compared.
            checks["to"] = all(
                address(m).split("@")[0].lower() in theirs["to"].lower()
                for m in record.get("to") or []
            )
            if record.get("body") and theirs["body"]:
                ratio = difflib.SequenceMatcher(
                    None, words(record["body"]), words(theirs["body"]), autojunk=False
                ).ratio()
                checks["body"] = ratio >= 0.8
            elif not theirs["body"]:
                counts["body: extract-msg has none"] += 1
            for field, same in checks.items():
                counts[f"{field}: {'agree' if same else 'differ'}"] += 1
    for key in sorted(counts):
        print(f"{key}: {counts[key]}")
    return 1 if any(key.endswith(": differ") for key in counts) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
