# Detailed OpenDocument Techniques

## ODT/ODS/ODP
- **XXE DOCTYPE + ENTITY** - content.xml - LibreOffice, Apache OpenOffice
- **XXE Parameter entity** - content.xml - LibreOffice, Apache OpenOffice
- **XSS <text:a xlink:href="javascript:alert(1)">click</text:a>** - content.xml - LibreOffice, OnlyOffice

## Info Disclosure (ODT/ODS)
1. **CELL("filename")** - Cell (ODS) / content (ODT) + meta.xml → meta:initial-creator - Extracts the filename - The information appears in the document properties (Creator/Author)
2. **INFO("version")** - Cell (ODS) / content (ODT) + meta.xml → meta:initial-creator - Extracts LibreOffice/Office version - Displays the version in the metadata
3. **INFO("system")** - Cell (ODS) / content (ODT) + meta.xml → meta:initial-creator - Extracts system information - Displays the system in the metadata
4. **NOW()** - Cell (ODS) / content (ODT) + meta.xml → meta:initial-creator - Extracts current date/time - Displays the date in the metadata
5. **INFO("directory")** - Cell (ODS) / content (ODT) + meta.xml → meta:initial-creator - Extracts the file directory - Displays the path in the metadata

**Note**: These payloads use Excel/Office formulas in the cells (for ODS) or content (for ODT) and modify the meta.xml metadata to place the formulas in meta:initial-creator. After opening the file, check the document properties (right-click → Properties) to see the formula results in the Creator/Author field.

