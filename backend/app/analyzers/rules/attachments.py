"""Attachment checks using only name, type and size. File contents never leave Gmail."""
import re
from collections import defaultdict

from app.analyzers.rules.common import RuleOutput, make_finding, summarize
from app.analyzers.rules.data import (
    ARCHIVE_EXTENSIONS, DANGEROUS_EXTENSIONS, DECOY_EXTENSIONS, EXECUTABLE_CONTENT_TYPES,
    HTML_CONTENT_TYPES, HTML_EXTENSIONS, LARGE_ATTACHMENT_BYTES, MACRO_EXTENSIONS,
)
from app.context import EmailContext
from app.models import AttachmentIn
from app.sanitize import BIDI_CONTROL_CHARS

_PASSWORD = re.compile(r"\b(password|passcode|pwd)\b")
TITLES = {
    "disguised_filename": "Disguised file name (right-to-left trick)",
    "double_extension": "Double file extension",
    "executable_attachment": "Executable or script attachment",
    "html_attachment": "HTML attachment (often a fake login page)",
    "macro_attachment": "Office file with macros",
    "archive_attachment": "Archive attachment",
    "archive_with_password": "Password-protected archive (hides content from scanners)",
}


def visible_name(name: str) -> str:
    """The file name without invisible text-direction characters (what the user actually sees)."""
    return "".join(char for char in name if char not in BIDI_CONTROL_CHARS)


def extensions(name: str) -> list[str]:
    """'Invoice.PDF .exe.' -> ['pdf', 'exe']: lowercased, spaces and trailing dots removed."""
    cleaned = visible_name(name).strip().rstrip(". ")
    return [part.strip().lower() for part in cleaned.split(".")][1:]


def check(ctx: EmailContext) -> RuleOutput:
    """Rule: flags risky attachments (double extensions, executables, HTML, macros, archives)."""
    hits: dict[str, list[str]] = defaultdict(list)
    large = 0
    for attachment in ctx.attachments:
        _inspect(attachment, hits)
        if attachment.size > LARGE_ATTACHMENT_BYTES:
            large += 1

    text = f"{ctx.headers.subject}\n{ctx.body.text}".lower()
    if "archive_attachment" in hits and _PASSWORD.search(text):
        hits["archive_with_password"] = hits.pop("archive_attachment")

    out = RuleOutput()
    for finding_id, names in hits.items():
        out.findings.append(make_finding(
            finding_id, "attachments", TITLES[finding_id], summarize([f'"{n}"' for n in names])))
    if large:
        out.notices.append(f"{large} attachment(s) larger than 10 MB could not be fingerprinted.")
    return out


def _inspect(attachment: AttachmentIn, hits: dict[str, list[str]]) -> None:
    """Records which attachment signals one file triggers."""
    shown = visible_name(attachment.name).strip() or "(no name)"
    if any(char in BIDI_CONTROL_CHARS for char in attachment.name):
        hits["disguised_filename"].append(shown)

    exts = extensions(attachment.name)
    last = exts[-1] if exts else ""
    content_type = attachment.content_type.lower().split(";")[0].strip()

    if len(exts) >= 2 and last in DANGEROUS_EXTENSIONS and exts[-2] in DECOY_EXTENSIONS:
        hits["double_extension"].append(shown)
    if last in DANGEROUS_EXTENSIONS or (not last and content_type in EXECUTABLE_CONTENT_TYPES):
        hits["executable_attachment"].append(shown)
    if last in HTML_EXTENSIONS or (not last and content_type in HTML_CONTENT_TYPES):
        hits["html_attachment"].append(shown)
    if last in MACRO_EXTENSIONS:
        hits["macro_attachment"].append(shown)
    if last in ARCHIVE_EXTENSIONS:
        hits["archive_attachment"].append(shown)
