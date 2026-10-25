import re
import urllib.parse
from typing import Tuple

ALLOWED_URL_SCHEMES = {"http", "https"}

DANGEROUS_SCHEMES = {"javascript", "vbscript", "data"}

def validate_url(url_str: str) -> Tuple[bool, str, str]:
    """
    Validate a user-supplied URL for safe web linking.
    Returns: (is_safe, sanitized_or_original_url, failure_reason)
    """
    if not url_str:
        return True, "", ""

    trimmed = url_str.strip()
    # Check for control characters or embedded nulls
    if any(ord(c) < 32 or ord(c) == 127 for c in trimmed):
        return False, "", "URL contains invalid control characters."

    # Parse scheme
    parsed = urllib.parse.urlparse(trimmed)
    scheme = parsed.scheme.lower()

    if not scheme:
        # Relative or scheme-less URL (e.g., www.example.com or /profile)
        # Check if leading part attempts pseudo-protocol bypass like 'javascript&colon;'
        lower_unquote = urllib.parse.unquote(trimmed).lower().replace(" ", "").replace("\t", "")
        for dangerous in DANGEROUS_SCHEMES:
            if lower_unquote.startswith(dangerous + ":"):
                return False, "", f"Executable URI scheme '{dangerous}:' rejected."
        return True, trimmed, ""

    if scheme in DANGEROUS_SCHEMES:
        return False, "", f"Executable URI scheme '{scheme}:' rejected."

    if scheme not in ALLOWED_URL_SCHEMES:
        return False, "", f"URL scheme '{scheme}:' is not an allowed web scheme (allowed: http, https)."

    return True, trimmed, ""

def escape_html_attribute(value: str) -> str:
    """Safely escapes quotes and HTML characters for inclusion in attributes."""
    if not value:
        return ""
    return (
        value.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
             .replace("'", "&#x27;")
    )
