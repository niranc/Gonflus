# Detailed Text File Techniques

## TXT/CSV/RTF
- **XSS script tag** - File content - HTML parsers
- **XSS img onerror** - File content - HTML parsers
- **XSS CSV =HYPERLINK("javascript:alert(1)","click")** - CSV content - Excel, Google Sheets (when auto-open)
- **XSS RTF {\field{\*\fldinst { HYPERLINK "javascript:alert(1)" }}}** - RTF content - WordPad, Word Windows
- **XSS RTF {\object\objdata javascript:alert(1)}** - RTF content - Very old Word Windows
- **SSRF Direct URL** - File content - URL parsers
- **SSRF HYPERLINK (RTF)** - RTF field - Word, LibreOffice
- **Path Traversal relative** - File content - File parsers
- **Path Traversal Windows** - File content - Windows parsers
- **Path Traversal double slash** - File content - File parsers
- **RCE Pipe** - File content - Command injection
- **RCE Semicolon** - File content - Command injection
- **RCE Backtick** - File content - Command injection
- **RCE Dollar** - File content - Command injection

