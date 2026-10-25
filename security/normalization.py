import html
import re
import urllib.parse

MAX_ANALYSIS_LENGTH = 4096


class Normalizer:
    """
    Safely prepares untrusted input for detection analysis.
    Does NOT mutate original user input stored by the web application.
    """

    @staticmethod
    def normalize(text: str) -> str:
        if not text:
            return ""

        # Bound processing length to prevent regex abuse or resource exhaustion
        bounded = text[:MAX_ANALYSIS_LENGTH]

        # 1. Trim surrounding whitespace
        normalized = bounded.strip()

        # 2. Repeated URL decoding (up to 2 passes to catch %253C -> %3C -> <)
        for _ in range(2):
            decoded = urllib.parse.unquote(normalized)
            if decoded == normalized:
                break
            normalized = decoded

        # 3. HTML entity decoding (e.g. &lt; -> <, &#60; -> <, &#x3c; -> <)
        normalized = html.unescape(normalized)

        # 4. Remove internal NULL bytes safely without raw null literals in source
        normalized = normalized.replace(chr(0), "")

        return normalized
