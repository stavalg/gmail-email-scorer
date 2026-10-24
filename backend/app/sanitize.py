"""Cleans text before it is sent back to the add-on.

Removes invisible control characters, including text-direction characters, which attackers use
to make 'exe.pdf' look like 'pdf.exe'. HTML escaping happens in the add-on, right before display.
"""
import re

BIDI_CONTROL_CHARS = frozenset("‎‏‪‫‬‭‮⁦⁧⁨⁩")
MAX_DISPLAY_CHARS = 200

_UNSAFE = re.compile("[\x00-\x08\x0b-\x1f\x7f" + "".join(sorted(BIDI_CONTROL_CHARS)) + "]")


def clean_text(value: str, limit: int = MAX_DISPLAY_CHARS) -> str:
    """Removes control and text-direction characters and caps the length before display."""
    value = _UNSAFE.sub("", value)
    return value if len(value) <= limit else value[: limit - 1] + "…"
