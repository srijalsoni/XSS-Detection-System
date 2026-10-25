import re
from dataclasses import dataclass
from typing import List, Pattern


@dataclass
class XSSRule:
    rule_id: str
    name: str
    category: str                    # SCRIPT_TAG, EVENT_HANDLER, PSEUDO_PROTOCOL, DANGEROUS_TAG, ATTRIBUTE_INJECTION, JS_SINK
    severity: str                    # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    pattern: Pattern
    example_indicator: str


# Pre-compiled, linear regex patterns avoiding nested quantifiers or catastrophic backtracking
BUILTIN_RULES: List[XSSRule] = [
    XSSRule(
        rule_id="XSS-001",
        name="Explicit Script Tag",
        category="SCRIPT_TAG",
        severity="HIGH",
        description="Identifies HTML <script> opening or closing elements.",
        pattern=re.compile(r"<\s*/?\s*script[\s/>]", re.IGNORECASE),
        example_indicator="<script>"
    ),
    XSSRule(
        rule_id="XSS-002",
        name="Inline Event Handler Attribute",
        category="EVENT_HANDLER",
        severity="HIGH",
        description="Identifies inline DOM event handler attributes (e.g. onload=, onerror=, onclick=).",
        pattern=re.compile(r"\b(on[a-z]{3,15})\s*=", re.IGNORECASE),
        example_indicator="onerror="
    ),
    XSSRule(
        rule_id="XSS-003",
        name="JavaScript or Executable URI Scheme",
        category="PSEUDO_PROTOCOL",
        severity="HIGH",
        description="Identifies javascript:, vbscript:, or data:text/html URI execution schemes.",
        pattern=re.compile(r"(javascript|vbscript)\s*:|data\s*:\s*text/html", re.IGNORECASE),
        example_indicator="javascript:"
    ),
    XSSRule(
        rule_id="XSS-004",
        name="Dangerous Executable HTML/SVG Elements",
        category="DANGEROUS_TAG",
        severity="MEDIUM",
        description="Identifies HTML/SVG elements frequently abused for code injection (svg, iframe, object, embed, body).",
        pattern=re.compile(r"<\s*/?\s*(iframe|svg|object|embed|applet|body|meta|link|base)[\s/>]", re.IGNORECASE),
        example_indicator="<svg>"
    ),
    XSSRule(
        rule_id="XSS-005",
        name="Attribute Delimiter Breakout Construct",
        category="ATTRIBUTE_INJECTION",
        severity="MEDIUM",
        description="Identifies input breaking out of HTML attribute contexts into new elements.",
        pattern=re.compile(r"""["']\s*>\s*<[a-z]""", re.IGNORECASE),
        example_indicator='"><tag'
    ),
    XSSRule(
        rule_id="XSS-006",
        name="JavaScript Execution Sink Call",
        category="JS_SINK",
        severity="MEDIUM",
        description="Identifies common JavaScript execution sinks (eval, document.cookie, document.write, alert, prompt).",
        pattern=re.compile(r"\b(eval|alert|prompt|confirm|document\.cookie|document\.write|window\.location)\s*\(", re.IGNORECASE),
        example_indicator="alert("
    ),
]
