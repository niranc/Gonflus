# Detailed Markdown Techniques

## RCE (Remote Code Execution)
1. **XSS chain Electron apps** - `<script>require('child_process').exec(...)` - VNote, Joplin, Electron apps - CVE-2024-41662
2. **VNote CVE-2024-41662** - XSS → RCE via img onerror - VNote - Exploited in-the-wild (2024)
3. **MarkText DOM XSS → RCE** - `<details open ontoggle="require(...)">` - MarkText - CVE-2023-2318
4. **md-to-pdf code injection** - JavaScript code injection in code blocks - md-to-pdf - CVE-2021-23639
5. **OOB buffer overflow** - Large content + XSS chain - C++ renderers - Potential RCE
6. **Internal exec** - Code blocks with shell commands - Internal tools - RCE via conversion
7. **Frontmatter JS eval (gray-matter / md-to-pdf)** - JavaScript front-matter evaluation via `---javascript` delimiters - CVE-2025-65108 ([`GHSA-547r-qmjm-8hvw`](https://github.com/advisories/GHSA-547r-qmjm-8hvw))

## SSRF (Server-Side Request Forgery) - Indirect
1. **Image link** - `![Image](http://...)` fetched by renderer - Markdown to PDF endpoints - CVE-2025-55161 (Stirling-PDF)
2. **Internal link** - Links to internal services - Thumbnailers, converters - CVE-2025-57818 (Firecrawl)
3. **Markdown to PDF conversion** - Links/images fetched during conversion - PDF conversion tools - SSRF chain

## XSS (Cross-Site Scripting)
1. **Details ontoggle** - `<details open ontoggle=alert(1)>` - All Markdown renderers - CVE-2025-61413, CVE-2025-57901
2. **Script tag** - `<script>alert(document.cookie)</script>` - All renderers - CVE-2025-49420, CVE-2025-46734
3. **Img onerror** - `<img src=x onerror=alert(1)>` - All renderers - Stored XSS
4. **SVG onload** - `<svg onload=alert(1)>` - All renderers - DOM XSS
5. **Mermaid diagram** - XSS in Mermaid code blocks - Mermaid renderers - XSS via diagrams
6. **Iframe src** - `<iframe src="javascript:alert(1)">` - HTML renderers - XSS bypass
7. **Clipboard paste** - Clipboard exfiltration via XSS - Editors - CVE-2025 (GitLab clipboard XSS)

## Information Leak
1. **Local file read** - `fetch('file:///etc/passwd')` via XSS - Electron apps - CVE-2023-0835 (markdown-pdf)
2. **DOM leak** - Exfiltration of cookies/URLs via XSS - All web renderers - Information disclosure
3. **Markdown PDF read** - Local file read via Node.js in PDF conversion - markdown-pdf - CVE-2023-0835
4. **Credentials exfil** - Exfiltration of localStorage/sessionStorage - Web apps - Credential theft

## DoS / Crash
1. **Nested lists** - Deeply nested lists causing parser crash - All parsers - DoS via recursion
2. **Infinite loop** - Circular references in links - Link parsers - DoS via loops
3. **Large table** - Extremely large tables - Table parsers - Memory exhaustion

## OOB (Out-of-Bounds) - Indirect
1. **Buffer overflow** - Large content causing buffer overflow in C++ renderers - C++ parsers - Potential RCE
2. **String parsing** - Malformed brackets causing OOB in string parsing - Text parsers - Potential leak

**Note**: Markdown is a text format, but vulnerabilities mainly come from HTML/JavaScript rendering in applications (editors, converters). RCE is possible via XSS chain in Electron apps (VNote, Joplin, MarkText). Indirect SSRF is possible through Markdown→PDF converters. Exploits are often used in-the-wild (2024-2025 in Markdown editors).

