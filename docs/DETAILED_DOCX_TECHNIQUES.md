# Detailed DOCX Techniques

## XSS
1. **<w:hyperlink r:id="rId1"> + rels Target="javascript:alert(1)"** - word/_rels/document.xml.rels - Word Windows, old Word Online
2. **{\field{\*\fldinst { HYPERLINK "javascript:alert(1)" }}}** - word/document.xml - Word Windows

## SSRF
1. **document.xml.rels → TargetMode="External"** - word/_rels/document.xml.rels - Apache POI 5.3+, OpenXml, LibreOffice, OnlyOffice
2. **header/footer.xml.rels → TargetMode="External"** - word/_rels/header1.xml.rels - POI, OpenXml, LibreOffice
3. **Images remote (blip r:link)** - word/document.xml → a:blip r:link - POI, OpenXml, Syncfusion, Aspose.Words
4. **webSettings.xml → attachedTemplate remote .dotm** - word/webSettings.xml - Word, LibreOffice, .NET parsers
5. **customXml → remote schema** - customXml/_rels/item1.xml.rels - POI, OpenXml

## LFI
1. **attachedTemplate file:///** - word/webSettings.xml + rels - LibreOffice, old Word

## XXE
1. **customXml/item1.xml DOCTYPE + ENTITY** - customXml/item1.xml - POI, OpenXml

