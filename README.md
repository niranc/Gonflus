
// Start of Selection
# UploadRenderAllTheThings

Comprehensive payload generator for security testing of file uploads. Generates all possible payloads for SSRF, XXE, RCE, XSS, Path Traversal, NTLM Leak, LFI, and other vulnerabilities in all common file formats.

## Installation

```bash
pip3 install -r requirements.txt
```

## Usage

```bash
./uploadrenderallthethings [burp-collab] [-e extension] [-d]
```

Examples:
```bash
./uploadrenderallthethings abc123.burpcollaborator.net
./uploadrenderallthethings abc123.burpcollaborator.net -e pdf
./uploadrenderallthethings abc123.burpcollaborator.net -e svg
./uploadrenderallthethings abc123.burpcollaborator.net -e all
./uploadrenderallthethings -d
```

**Note**: The `-d` option can be used alone to delete all generated folders without needing to specify Burp Collaborator.

Options:
- `-e, --extension`: Specify the extension to generate:
  - `pdf`, `docx`, `xlsx`, `pptx`: Office Documents
  - `svg`, `xml`, `html`: Web Formats
  - `png`, `jpg`, `jpeg`, `gif`: Images
  - `zip`, `jar`, `epub`: Archives
  - `txt`, `csv`, `rtf`: Text Files
  - `odt`, `ods`, `odp`: OpenDocument
  - `all`: Generates all payloads (default)
- `-d, --delete`: Deletes all generated folders before creating new payloads (can be used alone)

## Directory Structure

The tool creates the following structure:
```
<extension>/
  ├── ssrf/
  │   └── ssrf1_technique.<ext>
  ├── xxe/
  │   └── xxe1_technique.<ext>
  ├── ntlm/
  │   └── ntlm1_technique.<ext>
  ├── lfi/
  │   └── lfi1_technique.<ext>
  └── master.<ext>
```

Each payload is named with the technique number and a synthetic name of the technique used.

## OOB Endpoints Table

When you receive an OOB request on your Burp Collaborator, use this table to identify the vulnerability and technique used:

| OOB Endpoint | Extension | Vulnerability | Technique | Affected File/Element |
|-------------|-----------|---------------|-----------|------------------------|
| `/img1` | PDF | SSRF | XObject Image remote URL | /XObject → /Subtype /Image → /URL |
| `/font.ttf` | PDF | SSRF | FontFile2/FontFile3 remote | /Font → /FontFile2 or /FontFile3 |
| `/link1` | PDF | SSRF | Annot → /A → /URI (hyperlink) | /Annot → /A → /URI |
| `/remote.pdf` | PDF | SSRF | Annot → /A → /GoToR → /F remote PDF | /Annot → /A → /GoToR → /F |
| `/xmp` | PDF | SSRF | XMP metadata remote include | XMP packet |
| `/evil.icc` | PDF | SSRF | ICC profile remote | /ColorSpace → /ICCBased |
| `/evil.zip` | PDF | SSRF | EmbeddedFiles → /EF → /F remote | /Names → /EmbeddedFiles |
| `/xfa-img` | PDF | SSRF | XFA → <image href="http://…"> | /AcroForm → /XFA |
| `/file` | PDF | SSRF | JavaScript this.importDataObject | /Names → /JavaScript |
| `/evil.exe` | PDF | SSRF | Action Launch remote file | /Annot → /A → /Launch → /F |
| `/iframe` | PDF | SSRF | JavaScript iframe HTML | /OpenAction → /JavaScript → iframe src |
| `/xhr` | PDF | SSRF | JavaScript XMLHttpRequest | /OpenAction → /JavaScript → XMLHttpRequest |
| `/fetch` | PDF | SSRF | JavaScript Fetch API | /OpenAction → /JavaScript → fetch() |
| `/embed` | PDF | SSRF | JavaScript embed HTML | /OpenAction → /JavaScript → embed src |
| `/base` | PDF | SSRF | JavaScript base HTML | /OpenAction → /JavaScript → base href |
| `/link` | PDF | SSRF | JavaScript link HTML | /OpenAction → /JavaScript → link src |
| `/script` | PDF | SSRF | JavaScript script HTML | /OpenAction → /JavaScript → script src |
| `/meta` | PDF | SSRF | JavaScript meta refresh HTML | /OpenAction → /JavaScript → meta refresh |
| `/img` | PDF | SSRF | JavaScript img HTML | /OpenAction → /JavaScript → img src |
| `/svg` | PDF | SSRF | JavaScript svg HTML | /OpenAction → /JavaScript → svg src |
| `/input` | PDF | SSRF | JavaScript input image HTML | /OpenAction → /JavaScript → input type="image" |
| `/video` | PDF | SSRF | JavaScript video HTML | /OpenAction → /JavaScript → video src |
| `/audio` | PDF | SSRF | JavaScript audio HTML | /OpenAction → /JavaScript → audio src |
| `/audio-source` | PDF | SSRF | JavaScript audio source HTML | /OpenAction → /JavaScript → audio source |
| `\\<burp>\\pwn.png` | PDF | NTLM Leak | XObject Image UNC path | /XObject → /Subtype /Image → /URL or /SMask |
| `\\<burp>\\font.ttf` | PDF | NTLM Leak | FontFile2/3 UNC path | /Font → /FontFile2 or /FontFile3 |
| `file:///etc/passwd` | PDF | LFI | GoToR file:/// | /Annot → /A → /GoToR → /F |
| `/xxe-xmp` | PDF | XXE | XMP packet DOCTYPE + ENTITY | metadata stream |
| `/xfa-xxe` | PDF | XXE | XFA forms DOCTYPE + ENTITY | /AcroForm → /XFA |
| `/h1` | DOCX | SSRF | document.xml.rels → TargetMode="External" | word/_rels/document.xml.rels |
| `/h2` | DOCX | SSRF | header/footer.xml.rels → TargetMode="External" | word/_rels/header1.xml.rels |
| `/img1.png` | DOCX | SSRF | Images remote (blip r:link) | word/document.xml → a:blip r:link |
| `/evil.dotm` | DOCX | SSRF | webSettings.xml → attachedTemplate remote .dotm | word/webSettings.xml |
| `/schema.xsd` | DOCX | SSRF | customXml → remote schema | customXml/_rels/item1.xml.rels |
| `file:///c:/windows/win.ini` | DOCX | LFI | attachedTemplate file:/// | word/webSettings.xml + rels |
| `/xxe-docx` | DOCX | XXE | customXml/item1.xml DOCTYPE + ENTITY | customXml/item1.xml |
| `/x1` | XLSX | SSRF | workbook.xml.rels → TargetMode="External" | xl/_rels/workbook.xml.rels |
| `/h1` | XLSX | SSRF | =HYPERLINK("http://…") | xl/worksheets/sheet1.xml |
| `/img-xlsx.png` | XLSX | SSRF | Images remote via drawing → blip r:link | xl/drawings/drawing1.xml + rels |
| `file:///etc/passwd` | XLSX | LFI | =HYPERLINK("file:///etc/passwd") | xl/worksheets/sheet1.xml |
| `/xxe-xlsx` | XLSX | XXE | sharedStrings.xml / workbook.xml DOCTYPE | xl/sharedStrings.xml or workbook.xml |
| `/s1` | SVG | SSRF | <image href="http://…"> | SVG root |
| `file:///etc/passwd` | SVG | LFI | <image href="file:///etc/passwd"> | SVG root |
| `/xxe-svg` | SVG | XXE | DOCTYPE + ENTITY direct | SVG root |
| `/xxe-png` | PNG | XXE/SSRF | iTXt chunk "XML:com.adobe.xmp" with DOCTYPE + URL | iTXt chunk |
| `/xxe-jpg` | JPEG | XXE/SSRF | COM segment (0xFFFE) with DOCTYPE + URL | COM marker |
| `/xxe-gif` | GIF | XXE/SSRF | Repeated comment blocks with DOCTYPE + URL | GIF comment extension |
| `/rce-ghostscript` | PDF | RCE | Ghostscript PostScript injection | /Contents → PostScript code |
| `/rce-postscript` | PDF | RCE | PostScript file operator | /Contents → PostScript %pipe% |
| `/rce-imagemagick` | PNG | RCE | ImageMagick delegate command injection | iTXt chunk with delegate |
| `/rce-delegate` | PNG | RCE | ImageMagick delegate wget/curl | iTXt chunk with delegate |
| `/xxe-xml-1` | XML | XXE | DOCTYPE + ENTITY | XML root |
| `/xxe-xml-4` | XML | XXE | Parameter entity | XML root |
| `/xss-xml-script` | XML | XSS | Script tag | XML root |
| `/ssrf-html-img` | HTML | SSRF | img src | HTML root |
| `/ssrf-html-link` | HTML | SSRF | link href | HTML root |
| `/ssrf-html-script` | HTML | SSRF | script src | HTML root |
| `/ssrf-html-iframe` | HTML | SSRF | iframe src | HTML root |
| `/xss-html-script` | HTML | XSS | script tag | HTML root |
| `/rce-html-eval` | HTML | RCE | eval() | HTML script |
| `/xxe-pptx-1` | PPTX | XXE | presentation.xml DOCTYPE | ppt/presentation.xml |
| `/ssrf-pptx-1` | PPTX | SSRF | presentation.xml.rels External | ppt/_rels/presentation.xml.rels |
| `/xxe-zip-1` | ZIP | XXE | XML DOCTYPE in archive | XML in ZIP |
| `/xxe-jar-1` | JAR | XXE | XML DOCTYPE in archive | XML in JAR |
| `/xxe-epub-1` | EPUB | XXE | XML DOCTYPE in archive | XML in EPUB |
| `/rce-zip-system` | ZIP | RCE | PHP system() | shell.php in ZIP |
| `/rce-jar-system` | JAR | RCE | PHP system() | shell.php in JAR |
| `/xss-txt-script` | TXT | XSS | script tag | TXT content |
| `/ssrf-txt-1` | TXT | SSRF | Direct URL | TXT content |
| `/rce-txt-pipe` | TXT | RCE | Pipe command injection | TXT content |
| `/xss-csv-script` | CSV | XSS | script tag | CSV content |
| `/ssrf-csv-1` | CSV | SSRF | Direct URL | CSV content |
| `/rce-csv-pipe` | CSV | RCE | Pipe command injection | CSV content |
| `/ssrf-rtf-1` | RTF | SSRF | HYPERLINK field | RTF field |
| `/xss-rtf-script` | RTF | XSS | script tag | RTF content |
| `/rce-rtf-pipe` | RTF | RCE | Pipe command injection | RTF content |
| `/xxe-odt-1` | ODT | XXE | content.xml DOCTYPE | content.xml |
| `/xxe-ods-1` | ODS | XXE | content.xml DOCTYPE | content.xml |
| `/xxe-odp-1` | ODP | XXE | content.xml DOCTYPE | content.xml |
| `/xxe-zip-2` | ZIP | XXE | XML Parameter entity | XML in ZIP |
| `/xxe-jar-2` | JAR | XXE | XML Parameter entity | XML in JAR |
| `/xxe-epub-2` | EPUB | XXE | XML Parameter entity | XML in EPUB |
| `/rce-zip-exec` | ZIP | RCE | PHP exec() | shell.php in ZIP |
| `/rce-jar-exec` | JAR | RCE | PHP exec() | shell.php in JAR |
| `/xss-txt-img` | TXT | XSS | img onerror | TXT content |
| `/ssrf-txt-2` | TXT | SSRF | HTTPS URL | TXT content |
| `/rce-txt-semicolon` | TXT | RCE | Semicolon command injection | TXT content |
| `/rce-txt-backtick` | TXT | RCE | Backtick command injection | TXT content |
| `/rce-txt-dollar` | TXT | RCE | Dollar command injection | TXT content |
| `/xss-csv-img` | CSV | XSS | img onerror | CSV content |
| `/ssrf-csv-2` | CSV | SSRF | HTTPS URL | CSV content |
| `/rce-csv-semicolon` | CSV | RCE | Semicolon command injection | CSV content |
| `/rce-csv-backtick` | CSV | RCE | Backtick command injection | CSV content |
| `/rce-csv-dollar` | CSV | RCE | Dollar command injection | CSV content |
| `/ssrf-rtf-2` | RTF | SSRF | HTTPS HYPERLINK | RTF field |
| `/xss-rtf-img` | RTF | XSS | img onerror | RTF content |
| `/rce-rtf-semicolon` | RTF | RCE | Semicolon command injection | RTF content |
| `/rce-rtf-backtick` | RTF | RCE | Backtick command injection | RTF content |
| `/rce-rtf-dollar` | RTF | RCE | Dollar command injection | RTF content |
| `/xxe-odt-2` | ODT | XXE | content.xml Parameter entity | content.xml |
| `/xxe-ods-2` | ODS | XXE | content.xml Parameter entity | content.xml |
| `/xxe-odp-2` | ODP | XXE | content.xml Parameter entity | content.xml |
| `/xxe-xml-2` | XML | XXE | HTTPS ENTITY | XML root |
| `/xxe-xml-3` | XML | XXE | file:// ENTITY | XML root |
| `/xxe-xml-5` | XML | XXE | DOCTYPE ENTITY | XML root |
| `/xss-xml-cdata` | XML | XSS | CDATA script | XML root |
| `/ssrf-pptx-2` | PPTX | SSRF | HTTPS presentation.xml.rels | ppt/_rels/presentation.xml.rels |
| `/xxe-pptx-2` | PPTX | XXE | presentation.xml Parameter entity | ppt/presentation.xml |
| `/xss-html-img` | HTML | XSS | img onerror | HTML root |
| `/rce-html-function` | HTML | RCE | Function() | HTML script |

## Supported File Formats

### Office Documents
- **PDF**: SSRF (24 techniques), NTLM Leak (2 techniques), LFI (2 techniques), XXE (2 techniques), RCE (6 techniques incluant Ghostscript/PostScript et JavaScript), XSS (12 techniques incluant sandbox bypass et injections), Info Disclosure (5 techniques utilisant fonctions Excel/Office)
- **DOCX**: SSRF (5 techniques), LFI (1 technique), XXE (1 technique), XSS (2 techniques)
- **XLSX**: SSRF (3 techniques), LFI (1 technique), XXE (1 technique), XSS (2 techniques), Info Disclosure (5 techniques utilisant fonctions Excel)
- **ODT/ODS/ODP**: XXE (2 techniques), XSS (1 technique), Info Disclosure (5 techniques pour ODT/ODS utilisant fonctions Excel/Office)
- **PPTX**: SSRF (2 techniques), XXE (2 techniques), XSS (2 techniques)

### Web Formats
- **HTML**: XSS (2 techniques), SSRF (4 techniques), RCE (2 techniques)
- **SVG**: SSRF (1 technique), LFI (1 technique), XXE (1 technique), XSS (3 techniques)
- **XML**: XXE (5 techniques), XSS (4 techniques), Path Traversal (2 techniques)

### Images
- **GIF**: SSRF/XXE (1 technique via comment blocks), XSS (1 technique via comment blocks)
- **JPG/JPEG**: SSRF/XXE (1 technique via COM segment), XSS (1 technique via COM segment)
- **PNG**: SSRF/XXE (1 technique via iTXt chunk), RCE (2 techniques ImageMagick), XSS (1 technique via iTXt chunk)

### Archives
- **ZIP**: XXE (2 techniques), Path Traversal (2 techniques), RCE (2 techniques PHP), XSS (1 technique via filename)
- **JAR**: XXE (2 techniques), Path Traversal (2 techniques), RCE (2 techniques PHP)
- **EPUB**: XXE (2 techniques), Path Traversal (2 techniques), XSS (1 technique via .xhtml)

### Text Files
- **TXT**: XSS (2 techniques), SSRF (2 techniques), Path Traversal (3 techniques), RCE (4 techniques)
- **CSV**: XSS (3 techniques), SSRF (2 techniques), Path Traversal (3 techniques), RCE (4 techniques)
- **RTF**: SSRF (2 techniques), XSS (4 techniques), Path Traversal (3 techniques), RCE (4 techniques)

## Master Payloads

For each extension, a "master" payload is generated that combines all vulnerabilities of the extension into a single file. The idea is to first try uploading this master, test as much as possible, and then if no feedback, upload the payloads one by one.

Master payloads are available at the root of each extension directory:
- `pdf/master.pdf` - Contains all techniques SSRF, NTLM, LFI, XXE
- `pdf/master2_rce.pdf` - Contains only RCE techniques (Ghostscript/PostScript) as they may break the main master
- `docx/master.docx` - Contains all techniques SSRF, LFI, XXE
- `xlsx/master.xlsx` - Contains all techniques SSRF, LFI, XXE
- `svg/master.svg` - Contains all techniques SSRF, LFI, XXE
- `png/master.png` - Contains SSRF/XXE techniques
- `png/master2_rce.png` - Contains only RCE techniques (ImageMagick)
- `jpg/master.jpg` - Contains SSRF/XXE techniques
- `gif/master.gif` - Contains SSRF/XXE techniques
- `zip/master.zip` - Contains XXE, Path Traversal, RCE techniques
- `jar/master.jar` - Contains XXE, Path Traversal, RCE techniques
- `epub/master.epub` - Contains XXE, Path Traversal techniques
- `txt/master.txt` - Contains XSS, SSRF, Path Traversal, RCE techniques
- `csv/master.csv` - Contains XSS, SSRF, Path Traversal, RCE techniques
- `rtf/master.rtf` - Contains SSRF, XSS, Path Traversal, RCE techniques
- `odt/master.odt` - Contains XXE techniques
- `ods/master.ods` - Contains XXE techniques
- `odp/master.odp` - Contains XXE techniques
- `xml/master.xml` - Contains XXE, XSS, Path Traversal techniques
- `html/master.html` - Contains XSS, SSRF, RCE techniques
- `pptx/master.pptx` - Contains SSRF, XXE techniques

## Detailed PDF Techniques

### XSS
1. **JavaScript sandbox bypass avec generator functions** - `/Names → /JavaScript` - Comprend si les APIs Acrobat Javascript sont supportées, bypass sandbox - Taux pop: Variable selon viewer
2. **Data URI scheme avec script** - `/Annot → /A → /URI` - Tente d'exécuter du Javascript arbitraire via data URI - Taux pop: Variable selon viewer
3. **Injection Javascript via annotations** - `/Annot → /T` - Injection de code via champ Title d'annotation - Taux pop: Variable selon viewer
4. **URI avec payload XSS details** - `/Annot → /A → /URI` - Injection via URI avec payload HTML - Taux pop: Variable selon viewer
5. **JavaScript bypass Acrobat APIs** - `/Names → /JavaScript` - Bypass des APIs Acrobat pour exécuter du code arbitraire - Taux pop: Variable selon viewer
6. **javascript: URI scheme** - `/Annot → /A → /URI` - Exécution via protocole javascript: - Taux pop: Variable selon viewer
7. **Annotation /V injection (Apryse WebViewer)** - `/Annot → /V` - Injection via champ V d'annotation, fonctionne sur Apryse PDF Webviewer vulnérables - Taux pop: Variable selon version
8. **FontMatrix injection (PDF.js)** - `/Font → /FontMatrix` - Injection via FontMatrix, fonctionne sur PDF.js vulnérables - Taux pop: Variable selon version
9. **Javascript sandbox bypass Apryse WebViewer SDK** - `/Names → /JavaScript` - Bypass sandbox dans Apryse WebViewer SDK (10.9.x - 10.12.0) - Taux pop: Variable selon version
10-12. **Versions simples pour tests** - Payloads XSS simples sans Burp Collaborator pour tests rapides

### Info Disclosure
1. **CELL("filename")** - `/Info → /Author` et `/Creator` - Formule directement dans les métadonnées Info du PDF - Les informations apparaissent dans les propriétés du document (Author/Creator)
2. **INFO("version")** - `/Info → /Author` et `/Creator` - Formule directement dans les métadonnées Info du PDF - Affiche la version dans les métadonnées
3. **INFO("system")** - `/Info → /Author` et `/Creator` - Formule directement dans les métadonnées Info du PDF - Affiche le système dans les métadonnées
4. **NOW()** - `/Info → /Author` et `/Creator` - Formule directement dans les métadonnées Info du PDF - Affiche la date dans les métadonnées
5. **INFO("directory")** - `/Info → /Author` et `/Creator` - Formule directement dans les métadonnées Info du PDF - Affiche le chemin dans les métadonnées

**Note**: Ces payloads mettent directement les formules Excel/Office dans les métadonnées Info du PDF (`/Info` objet avec `/Author` et `/Creator`). Après ouverture du PDF, vérifiez les propriétés du document (clic droit → Propriétés) pour voir les résultats des formules dans les champs Author/Creator. Pas besoin de JavaScript, les formules sont directement dans les métadonnées.

### SSRF
1. **XObject Image remote URL** - `/XObject → /Subtype /Image → /URL` - iText7, PDFBox 3.x, TCPDF::Image(@), Syncfusion, Aspose, SelectPdf
2. **FontFile2/FontFile3 remote** - `/Font → /FontFile2 or /FontFile3` - iText7, TCPDF, mPDF
3. **Annot → /A → /URI (hyperlink)** - `/Annot → /A → /URI` - All parsers
4. **Annot → /A → /GoToR → /F remote PDF** - `/Annot → /A → /GoToR → /F` - wkhtmltopdf, Puppeteer, iText7, PDFBox
5. **XMP metadata remote include** - XMP packet - PDFBox 3.x, iText7 XMP, .NET parsers
6. **ICC profile remote** - `/ColorSpace → /ICCBased` - iText7, PDFBox, Ghostscript
7. **EmbeddedFiles → /EF → /F remote** - `/Names → /EmbeddedFiles` - PDFBox, iText7 (extraction)
8. **XFA → <image href="http://…">** - `/AcroForm → /XFA` - iText7 XmlParser, PDFBox XFA
9. **JavaScript this.importDataObject** - `/Names → /JavaScript` - Acrobat Reader server (rare)
10. **Action Launch remote file** - `/Annot → /A → /Launch → /F` - Old iText/PDFBox
11. **JavaScript iframe HTML** - `/OpenAction → /JavaScript → iframe src` - Acrobat Reader with JavaScript
12. **JavaScript XMLHttpRequest** - `/OpenAction → /JavaScript → XMLHttpRequest` - Acrobat Reader with JavaScript
13. **JavaScript Fetch API** - `/OpenAction → /JavaScript → fetch()` - Acrobat Reader with JavaScript
14. **JavaScript embed HTML** - `/OpenAction → /JavaScript → embed src` - Acrobat Reader with JavaScript
15. **JavaScript base HTML** - `/OpenAction → /JavaScript → base href` - Acrobat Reader with JavaScript
16. **JavaScript link HTML** - `/OpenAction → /JavaScript → link src` - Acrobat Reader with JavaScript
17. **JavaScript script HTML** - `/OpenAction → /JavaScript → script src` - Acrobat Reader with JavaScript
18. **JavaScript meta refresh HTML** - `/OpenAction → /JavaScript → meta refresh` - Acrobat Reader with JavaScript
19. **JavaScript img HTML** - `/OpenAction → /JavaScript → img src` - Acrobat Reader with JavaScript
20. **JavaScript svg HTML** - `/OpenAction → /JavaScript → svg src` - Acrobat Reader with JavaScript
21. **JavaScript input image HTML** - `/OpenAction → /JavaScript → input type="image"` - Acrobat Reader with JavaScript
22. **JavaScript video HTML** - `/OpenAction → /JavaScript → video src` - Acrobat Reader with JavaScript
23. **JavaScript audio HTML** - `/OpenAction → /JavaScript → audio src` - Acrobat Reader with JavaScript
24. **JavaScript audio source HTML** - `/OpenAction → /JavaScript → audio source` - Acrobat Reader with JavaScript

### NTLM Leak
25. **XObject Image UNC path** - `/XObject → /Subtype /Image → /URL or /SMask` - Windows + iText7, PDFBox, Syncfusion, Aspose, wkhtmltopdf
26. **FontFile2/3 UNC path** - `/Font → /FontFile2 or /FontFile3` - Windows + iText7, TCPDF

### LFI
27. **GoToR file:///** - `/Annot → /A → /GoToR → /F` - wkhtmltopdf, old parsers
28. **URI file:// pour accès fichiers Windows** - `/Annot → /A → /URI` - Tente d'accéder à des fichiers locaux via file:// - Windows uniquement

### XXE
29. **XMP packet DOCTYPE + ENTITY** - metadata stream - PDFBox, iText7, exiftool
30. **XFA forms DOCTYPE + ENTITY** - `/AcroForm → /XFA` - iText7 XmlParser, PDFBox XFA

### RCE
31. **Ghostscript PostScript injection** - `/Contents → PostScript code` - Ghostscript (bypass -dSAFER) - CVE-2019-10216, CVE-2019-14811
32. **PostScript file operator** - `/Contents → PostScript %pipe%` - Ghostscript, old parsers
33. **app.openDoc() pour exécution Windows** - `/Names → /JavaScript` - Tente d'exécuter des commandes Windows via app.openDoc() - Windows uniquement
34. **URI START pour exécution Windows** - `/Annot → /A → /URI` - Tente d'exécuter via protocole START sur Windows - Windows uniquement
35. **app.launchURL() pour exécution Windows** - `/Names → /JavaScript` - Tente d'exécuter via app.launchURL() - Windows uniquement
36. **app.launchURL() avec fichier** - `/Names → /JavaScript` - Tente d'exécuter un fichier local via app.launchURL() - Windows uniquement

## Detailed DOCX Techniques

### XSS
1. **<w:hyperlink r:id="rId1"> + rels Target="javascript:alert(1)"** - word/_rels/document.xml.rels - Word Windows, Word Online ancien - Taux pop: 95%
2. **{\field{\*\fldinst { HYPERLINK "javascript:alert(1)" }}}** - word/document.xml - Word Windows - Taux pop: 92%

### SSRF
1. **document.xml.rels → TargetMode="External"** - word/_rels/document.xml.rels - Apache POI 5.3+, OpenXml, LibreOffice, OnlyOffice
2. **header/footer.xml.rels → TargetMode="External"** - word/_rels/header1.xml.rels - POI, OpenXml, LibreOffice
3. **Images remote (blip r:link)** - word/document.xml → a:blip r:link - POI, OpenXml, Syncfusion, Aspose.Words
4. **webSettings.xml → attachedTemplate remote .dotm** - word/webSettings.xml - Word, LibreOffice, .NET parsers
5. **customXml → remote schema** - customXml/_rels/item1.xml.rels - POI, OpenXml

### LFI
7. **attachedTemplate file:///** - word/webSettings.xml + rels - LibreOffice, old Word

### XXE
8. **customXml/item1.xml DOCTYPE + ENTITY** - customXml/item1.xml - POI, OpenXml

## Detailed XLSX Techniques

### XSS
1. **=HYPERLINK("javascript:alert(1)","click ici")** - xl/worksheets/sheet1.xml - Excel Windows, Google Sheets (pop quand clic), LibreOffice - Taux pop: 99%
2. **<xml><x><![CDATA[<svg onload=alert(1)>]]></x></xml> dans customXml ou sharedStrings** - customXml/item1.xml ou xl/sharedStrings.xml - LibreOffice/OnlyOffice preview - Taux pop: 88%

### SSRF
1. **workbook.xml.rels → TargetMode="External"** - xl/_rels/workbook.xml.rels - POI, PhpSpreadsheet, EPPlus
2. **=HYPERLINK("http://…")** - xl/worksheets/sheet1.xml - All
3. **Images remote via drawing → blip r:link** - xl/drawings/drawing1.xml + rels - POI, EPPlus

### LFI
4. **=HYPERLINK("file:///etc/passwd")** - xl/worksheets/sheet1.xml - Excel, LibreOffice

### XXE
5. **sharedStrings.xml / workbook.xml DOCTYPE** - xl/sharedStrings.xml or workbook.xml - POI, PhpSpreadsheet (lxml)

### Info Disclosure
1. **CELL("filename")** - Cellule + docProps/core.xml → dc:creator - Extrait le nom du fichier - Les informations apparaissent dans les propriétés du document (Creator/Author)
2. **INFO("version")** - Cellule + docProps/core.xml → dc:creator - Extrait la version d'Excel/Office - Affiche la version dans les métadonnées
3. **INFO("system")** - Cellule + docProps/core.xml → dc:creator - Extrait les informations système - Affiche le système dans les métadonnées
4. **NOW()** - Cellule + docProps/core.xml → dc:creator - Extrait la date/heure actuelle - Affiche la date dans les métadonnées
5. **INFO("directory")** - Cellule + docProps/core.xml → dc:creator - Extrait le répertoire du fichier - Affiche le chemin dans les métadonnées

**Note**: Ces payloads utilisent les formules Excel dans les cellules et modifient les métadonnées core.xml pour mettre les formules dans dc:creator. Après ouverture du fichier, vérifiez les propriétés du document (clic droit → Propriétés) pour voir les résultats des formules dans le champ Creator/Author.

## Detailed SVG Techniques

### XSS
1. **<svg onload=alert(1)> ou <script>alert(1)</script>** - SVG root - TOUS les parsers SVG (Batik, librsvg, Chrome, ImageMagick, browsers) - Taux pop: 99.9%
2. **<image href="x" onerror=alert(1)>** - SVG root - TOUS - Taux pop: 99%
3. **<animate onbegin=alert(1)>** - SVG root - Tous sauf certains WAF - Taux pop: 98%

### SSRF
1. **<image href="http://…">** - SVG root - Batik, librsvg, ImageMagick, Resvg

### LFI
2. **<image href="file:///etc/passwd">** - SVG root - librsvg, ImageMagick

### XXE
3. **DOCTYPE + ENTITY direct** - SVG root - Batik, Inkscape

## Detailed Image Techniques

### PNG
- **iTXt chunk "XML:com.adobe.xmp" with DOCTYPE + URL** - iTXt chunk - ImageMagick, exiftool
- **ImageMagick delegate command injection** - iTXt chunk with delegate - ImageMagick (CVE-2016-3714, ImageTragick)
- **ImageMagick delegate wget/curl** - iTXt chunk with delegate SVG - ImageMagick
- **XSS iTXt chunk avec <svg onload=alert(1)> → ImageMagick ou preview HTML** - iTXt chunk - Quelques vieux parsers - Taux pop: 18%

### JPEG
- **COM segment (0xFFFE) with DOCTYPE + URL** - COM marker - ImageMagick, exiftool
- **XSS COM segment avec <script>alert(1)</script> → ImageMagick -label** - COM marker - Très rares (seulement vieux ImageMagick + HTML output) - Taux pop: 12%

### GIF
- **Repeated comment blocks with DOCTYPE + URL** - GIF comment extension - ImageMagick
- **XSS Comment block avec <script>alert(1)</script> → ImageMagick -label ou preview** - GIF comment extension - Très rares (seulement vieux ImageMagick + HTML output) - Taux pop: 15%

## Detailed Archive Techniques

### ZIP/JAR/EPUB
- **XXE DOCTYPE + ENTITY** - XML in archive - All XML parsers
- **XXE Parameter entity** - XML in archive - All XML parsers
- **Path Traversal relative** - Filename in archive - All extractors
- **Path Traversal Windows** - Filename in archive - Windows extractors
- **RCE PHP system()** - shell.php in archive - PHP servers (ZIP/JAR only)
- **RCE PHP exec()** - shell.php in archive - PHP servers (ZIP/JAR only)
- **XSS ZIP Nom de fichier = <svg onload=alert(1)>.svg + extraction preview** - Nom de fichier dans ZIP - Windows Explorer, certains antivirus - Taux pop: 70%
- **XSS EPUB <script>alert(1)</script> dans un fichier .xhtml** - OEBPS/chapter1.xhtml - Calibre, Apple Books, certains lecteurs - Taux pop: 92%

## Detailed Text File Techniques

### TXT/CSV/RTF
- **XSS script tag** - File content - HTML parsers - Taux pop: <5% (seulement si mauvais Content-Type)
- **XSS img onerror** - File content - HTML parsers - Taux pop: <5% (seulement si mauvais Content-Type)
- **XSS CSV =HYPERLINK("javascript:alert(1)","click")** - CSV content - Excel, Google Sheets (quand ouverture auto) - Taux pop: 99%
- **XSS RTF {\field{\*\fldinst { HYPERLINK "javascript:alert(1)" }}}** - RTF content - WordPad, Word Windows - Taux pop: 94%
- **XSS RTF {\object\objdata javascript:alert(1)}** - RTF content - Word Windows très ancien - Taux pop: 45%
- **SSRF Direct URL** - File content - URL parsers
- **SSRF HYPERLINK (RTF)** - RTF field - Word, LibreOffice
- **Path Traversal relative** - File content - File parsers
- **Path Traversal Windows** - File content - Windows parsers
- **Path Traversal double slash** - File content - File parsers
- **RCE Pipe** - File content - Command injection
- **RCE Semicolon** - File content - Command injection
- **RCE Backtick** - File content - Command injection
- **RCE Dollar** - File content - Command injection

## Detailed OpenDocument Techniques

### ODT/ODS/ODP
- **XXE DOCTYPE + ENTITY** - content.xml - LibreOffice, Apache OpenOffice
- **XXE Parameter entity** - content.xml - LibreOffice, Apache OpenOffice
- **XSS <text:a xlink:href="javascript:alert(1)">click</text:a>** - content.xml - LibreOffice, OnlyOffice - Taux pop: 96%

### Info Disclosure (ODT/ODS)
1. **CELL("filename")** - Cellule (ODS) / contenu (ODT) + meta.xml → meta:initial-creator - Extrait le nom du fichier - Les informations apparaissent dans les propriétés du document (Creator/Author)
2. **INFO("version")** - Cellule (ODS) / contenu (ODT) + meta.xml → meta:initial-creator - Extrait la version de LibreOffice/Office - Affiche la version dans les métadonnées
3. **INFO("system")** - Cellule (ODS) / contenu (ODT) + meta.xml → meta:initial-creator - Extrait les informations système - Affiche le système dans les métadonnées
4. **NOW()** - Cellule (ODS) / contenu (ODT) + meta.xml → meta:initial-creator - Extrait la date/heure actuelle - Affiche la date dans les métadonnées
5. **INFO("directory")** - Cellule (ODS) / contenu (ODT) + meta.xml → meta:initial-creator - Extrait le répertoire du fichier - Affiche le chemin dans les métadonnées

**Note**: Ces payloads utilisent les formules Excel/Office dans les cellules (pour ODS) ou le contenu (pour ODT) et modifient les métadonnées meta.xml pour mettre les formules dans meta:initial-creator. Après ouverture du fichier, vérifiez les propriétés du document (clic droit → Propriétés) pour voir les résultats des formules dans le champ Creator/Author.

## Detailed XML Techniques

### XML
- **XXE ENTITY** - XML root - All XML parsers
- **XXE HTTPS** - XML root - All XML parsers
- **XXE file://** - XML root - All XML parsers
- **XXE Parameter entity** - XML root - All XML parsers
- **XXE DOCTYPE** - XML root - All XML parsers
- **XSS script tag** - XML root - HTML parsers
- **XSS CDATA** - XML root - HTML parsers
- **XSS <?xml-stylesheet href="javascript:alert(1)"?>** - XML root - IE11, vieux Edge, certains XSLT preview - Taux pop: 65%
- **XSS <svg onload=alert(1)> dans le XML** - XML root - LibreOffice, OnlyOffice, certains parsers - Taux pop: 90%
- **Path Traversal relative** - XML content - File parsers
- **Path Traversal Windows** - XML content - Windows parsers

## Detailed HTML Techniques

### HTML
- **XSS script tag** - HTML root - All browsers - Taux pop: 100%
- **XSS svg onload** - HTML root - All browsers - Taux pop: 100%
- **SSRF img src** - HTML root - HTML parsers
- **SSRF link href** - HTML root - HTML parsers
- **SSRF script src** - HTML root - HTML parsers
- **SSRF iframe src** - HTML root - HTML parsers
- **RCE eval()** - HTML script - Browsers with JavaScript
- **RCE Function()** - HTML script - Browsers with JavaScript

## Detailed PPTX Techniques

### PPTX
- **SSRF presentation.xml.rels External** - ppt/_rels/presentation.xml.rels - POI, OpenXml
- **XXE DOCTYPE + ENTITY** - ppt/presentation.xml - POI, OpenXml
- **XXE Parameter entity** - ppt/presentation.xml - POI, OpenXml
- **XSS =HYPERLINK("javascript:alert(1)","click") dans notes ou texte** - ppt/slides/slide1.xml - PowerPoint, Impress - Taux pop: 98%
- **XSS <a:href>javascript:alert(1)</a:href> dans ppt/slides/slide1.xml** - ppt/slides/slide1.xml - LibreOffice Impress - Taux pop: 90%

## Notes

- This tool is intended for authorized security testing only
- Make sure you have permission before testing
- Generated files are for testing purposes only
- Monitor your Burp Collaborator for successful payload executions
- Master payloads might cause issues if certain techniques are incompatible - in such cases, use individual payloads

## Test Application

A web application is included in the `test-app/` directory to test uploaded files and view their rendered content.

### Run the Test Server

```bash
cd test-app
npm install
npm start
```

The server will be available at `http://localhost:3000`

Features:
- File upload via drag & drop or file browser
- View uploaded files (images, PDFs, HTML, XML, etc.)
- Download or delete uploaded files
- Test all generated payloads for vulnerabilities

See `test-app/README.md` for more details.

## Contribution

Feel free to add new file formats or vulnerability types by creating new generator modules in the `generators/` directory.
