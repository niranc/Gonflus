# Detailed XML Techniques

## XML
- **XXE ENTITY** - XML root - All XML parsers
- **XXE HTTPS** - XML root - All XML parsers
- **XXE file://** - XML root - All XML parsers
- **XXE Parameter entity** - XML root - All XML parsers
- **XXE DOCTYPE** - XML root - All XML parsers
- **XSS script tag** - XML root - HTML parsers
- **XSS CDATA** - XML root - HTML parsers
- **XSS <?xml-stylesheet href="javascript:alert(1)"?>** - XML root - IE11, old Edge, some XSLT preview
- **XSS <svg onload=alert(1)> in XML** - XML root - LibreOffice, OnlyOffice, some parsers
- **Path Traversal relative** - XML content - File parsers
- **Path Traversal Windows** - XML content - Windows parsers

