# Detailed Archive Techniques

## ZIP/JAR/EPUB
- **XXE DOCTYPE + ENTITY** - XML in archive - All XML parsers
- **XXE Parameter entity** - XML in archive - All XML parsers
- **Path Traversal relative** - Filename in archive - All extractors
- **Path Traversal Windows** - Filename in archive - Windows extractors
- **RCE PHP system()** - shell.php in archive - PHP servers (ZIP/JAR only)
- **RCE PHP exec()** - shell.php in archive - PHP servers (ZIP/JAR only)
- **XSS ZIP Filename = <svg onload=alert(1)>.svg + extraction preview** - Filename in ZIP - Windows Explorer, some antivirus
- **XSS EPUB <script>alert(1)</script> in a .xhtml file** - OEBPS/chapter1.xhtml - Calibre, Apple Books, some readers

