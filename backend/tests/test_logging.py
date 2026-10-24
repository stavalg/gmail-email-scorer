import logging

import app.main  # noqa: F401 - importing the app applies its logging setup


def test_http_client_logs_never_include_request_urls():
    # httpx logs every request URL at INFO. Those URLs contain domains taken from the
    # analyzed email (VirusTotal lookups), and logs must never contain email-derived data.
    for name in ("httpx", "httpcore"):
        assert logging.getLogger(name).getEffectiveLevel() >= logging.WARNING
