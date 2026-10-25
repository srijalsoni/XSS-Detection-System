from typing import Dict

DEFAULT_SECURITY_HEADERS: Dict[str, str] = {
    # Restrict execution of scripts and framing to same-origin
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    ),
    # Prevent MIME-sniffing
    "X-Content-Type-Options": "nosniff",
    # Block page rendering in <frame>, <iframe>, <embed> to prevent clickjacking
    "X-Frame-Options": "DENY",
    # Control referrer information sent in HTTP requests
    "Referrer-Policy": "strict-origin-when-cross-origin",
    # Legacy browser XSS protection mode
    "X-XSS-Protection": "1; mode=block",
}


def apply_security_headers(response):
    """Attach standard defense-in-depth HTTP security headers to response."""
    for header, value in DEFAULT_SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    return response
