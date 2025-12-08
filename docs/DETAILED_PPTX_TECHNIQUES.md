# Detailed PPTX Techniques

## PPTX
- **SSRF presentation.xml.rels External** - ppt/_rels/presentation.xml.rels - POI, OpenXml
- **XXE DOCTYPE + ENTITY** - ppt/presentation.xml - POI, OpenXml
- **XXE Parameter entity** - ppt/presentation.xml - POI, OpenXml
- **XSS =HYPERLINK("javascript:alert(1)","click") in notes or text** - ppt/slides/slide1.xml - PowerPoint, Impress
- **XSS <a:href>javascript:alert(1)</a:href> in ppt/slides/slide1.xml** - ppt/slides/slide1.xml - LibreOffice Impress

