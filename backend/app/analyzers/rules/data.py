"""Everything tunable about the rules lives here: points, brands and indicator lists."""
from dataclasses import dataclass

# Points per signal. Each signal counts once per email. Never negative: nothing lowers the score.
WEIGHTS: dict[str, int] = {
    # authentication
    "dmarc_fail": 30,
    "spf_fail": 15,
    "dkim_fail": 15,
    # sender
    "brand_display_name": 25,
    "lookalike_domain": 30,
    "display_name_address": 30,
    "reply_to_mismatch": 15,
    "malformed_sender": 10,
    # links
    "link_text_mismatch": 25,
    "brand_in_subdomain": 30,
    "punycode_link": 25,
    "script_link": 25,
    "ip_link": 20,
    "shortener_link": 10,
    "abused_tld": 10,
    # content
    "urgency_language": 10,
    "credential_request": 15,
    # attachments
    "disguised_filename": 60,
    "double_extension": 60,
    "executable_attachment": 40,
    "html_attachment": 30,
    "archive_with_password": 30,
    "macro_attachment": 20,
    "archive_attachment": 15,
}


def validate_weights(weights: dict[str, int]) -> None:
    """Points must be whole, non-negative numbers."""
    for name, points in weights.items():
        if isinstance(points, bool) or not isinstance(points, int) or points < 0:
            raise ValueError(f"Invalid weight for {name!r}: {points!r}")


validate_weights(WEIGHTS)  # a bad edit stops the app from starting instead of scoring wrongly


@dataclass(frozen=True)
class Brand:
    """A brand we protect: how it appears in sender names, in domains, and its real domains."""
    name: str                   # shown to the user
    keywords: tuple[str, ...]   # phrases matched as whole words in sender NAMES; specific enough
                                # that people and newsletters don't match ("chase bank", not "chase")
    labels: tuple[str, ...]     # domain labels for lookalike / hidden-brand checks on DOMAINS
    domains: tuple[str, ...]    # legitimate registrable domains; the first is the main one


BRANDS: tuple[Brand, ...] = (
    Brand("PayPal", ("paypal",), ("paypal",), ("paypal.com", "paypal.me")),
    Brand("Microsoft", ("microsoft", "office 365", "onedrive", "outlook team", "outlook.com"),
          ("microsoft", "outlook", "office365", "onedrive"),
          ("microsoft.com", "live.com", "outlook.com", "office.com", "office365.com",
           "microsoftonline.com", "onedrive.com", "sharepoint.com")),
    Brand("Google", ("google",), ("google",), ("google.com", "youtube.com")),
    Brand("Apple", ("apple support", "apple id", "apple store", "icloud"), ("apple", "icloud"),
          ("apple.com", "icloud.com")),
    Brand("Amazon", ("amazon",), ("amazon",), ("amazon.com", "amazon.co.uk", "amazon.de", "amazonses.com")),
    Brand("Netflix", ("netflix",), ("netflix",), ("netflix.com",)),
    Brand("Meta", ("facebook", "instagram", "whatsapp"), ("facebook", "instagram", "whatsapp"),
          ("facebook.com", "facebookmail.com", "instagram.com", "whatsapp.com", "meta.com")),
    Brand("LinkedIn", ("linkedin",), ("linkedin",), ("linkedin.com",)),
    Brand("DHL", ("dhl",), ("dhl",), ("dhl.com", "dhl.de")),
    Brand("FedEx", ("fedex",), ("fedex",), ("fedex.com",)),
    Brand("UPS", ("ups delivery", "ups shipping", "ups my choice", "united parcel service"), ("ups",),
          ("ups.com",)),
    Brand("DocuSign", ("docusign",), ("docusign",), ("docusign.com", "docusign.net")),
    Brand("Dropbox", ("dropbox",), ("dropbox",), ("dropbox.com", "dropboxmail.com")),
    Brand("Adobe", ("adobe",), ("adobe",), ("adobe.com",)),
    Brand("Chase", ("chase bank", "jpmorgan chase", "chase online"), ("chase",), ("chase.com",)),
    Brand("Wells Fargo", ("wells fargo",), ("wellsfargo",), ("wellsfargo.com",)),
    Brand("Bank of America", ("bank of america",), ("bankofamerica",), ("bankofamerica.com", "bofa.com")),
    Brand("Coinbase", ("coinbase",), ("coinbase",), ("coinbase.com",)),
    Brand("Binance", ("binance",), ("binance",), ("binance.com",)),
)

SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
})

# Top-level domains frequently abused for phishing (weak signal on its own).
ABUSED_TLDS = frozenset({
    "zip", "mov", "top", "xyz", "click", "link", "country", "gq", "tk", "ml", "cf", "ga",
    "work", "support", "rest", "fit", "kim", "loan",
})

URGENCY_PHRASES = (
    "urgent", "immediately", "action required", "within 24 hours", "within 48 hours",
    "account will be suspended", "account has been suspended", "account will be closed",
    "final notice", "last warning", "act now", "expires today", "unusual activity",
    "suspicious activity",
)

CREDENTIAL_PHRASES = (
    "verify your account", "verify your password", "confirm your password",
    "update your password", "enter your password", "login credentials",
    "confirm your identity", "verify your identity", "update your payment",
    "update billing", "billing information", "credit card number",
    "social security number", "bank account details",
)

DANGEROUS_EXTENSIONS = frozenset({
    "exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "ps1", "hta", "lnk", "msi",
    "iso", "img", "one", "com", "pif", "cpl", "jar", "wsf",
})
DECOY_EXTENSIONS = frozenset({
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv",
    "jpg", "jpeg", "png", "gif",
})
HTML_EXTENSIONS = frozenset({"html", "htm", "shtml", "xhtml"})
MACRO_EXTENSIONS = frozenset({"docm", "xlsm", "pptm", "dotm", "xltm"})
ARCHIVE_EXTENSIONS = frozenset({"zip", "rar", "7z", "gz", "tar", "cab"})
EXECUTABLE_CONTENT_TYPES = frozenset({
    "application/x-msdownload", "application/x-dosexec", "application/x-msdos-program",
    "application/x-msi", "application/hta",
})
HTML_CONTENT_TYPES = frozenset({"text/html"})
LARGE_ATTACHMENT_BYTES = 10 * 1024 * 1024

# Very common domains not worth a VirusTotal lookup (saves the free quota).
COMMON_SAFE_DOMAINS = frozenset({
    "google.com", "gmail.com", "youtube.com", "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "linkedin.com", "github.com", "paypal.com",
})
