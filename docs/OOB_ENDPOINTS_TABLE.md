# OOB Endpoints Table

If your collaborator is triggered by a payload, use `Ctrl + F` to search for the specific upload that caused the SSRF, RCE, XXE, or other vulnerabilities. This will help you identify the appropriate OOB endpoint, vulnerability type, and technique used. Once identified, reference the section on OOB Endpoints to understand the affected file or element, ensuring a quicker resolution and comprehension of the security issue.

| OOB Endpoint | Extension | Vulnerability | Technique | Affected File/Element |
|-------------|-----------|---------------|-----------|------------------------|
| `/img1` | PDF | SSRF | XObject Image remote URL | /XObject → /Subtype /Image → /URL |
| `/font.ttf` | PDF | SSRF | FontFile2/FontFile3 remote | /Font → /FontFile2 or /FontFile3 |
| `/link1` | PDF | SSRF | Annot → /A → /URI (hyperlink) | /Annot → /A → /URI |
| `/remote.pdf` | PDF | SSRF | Annot → /A → /GoToR → /F remote PDF | /Annot → /GoToR → /F |
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
| `/make-entire-document-clickable` | PDF | SSRF | jsPDF SubmitForm | /Annot → /A → /SubmitForm |
| `/track-when-opening-pdf-filesystem` | PDF | SSRF | jsPDF track opening | /Annot → /AA → /PV → /JavaScript |
| `/track-when-closing-pdf-filesystem` | PDF | SSRF | jsPDF track closing | /Annot → /AA → /PC → /JavaScript |
| `/enumerator` | PDF | SSRF | jsPDF object enumerator | /Annot → /A → /JavaScript |
| `/pdf-ssrf` | PDF | SSRF | jsPDF Chrome submitForm | /Annot → /A → /JavaScript → submitForm |
| `/extracting-text` | PDF | SSRF | jsPDF Chrome text extraction | /Annot → /A → /JavaScript → submitForm |
| `/injection-overwrite-url` | PDF | SSRF | jsPDF Chrome URL overwrite | /Annot → /A → /URI |
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
| `/img1` | SVG | SSRF | <image xlink:href="http://…"> | SVG root |
| `/use1` | SVG | SSRF | <use xlink:href="http://…"> | SVG root |
| `/css-link` | SVG | SSRF | <link rel="stylesheet" href="http://…"> | SVG root |
| `/css-import` | SVG | SSRF | @import url(http://…) | SVG style |
| `/xml-stylesheet` | SVG | SSRF | <?xml-stylesheet href="http://…"?> | SVG root |
| `/xslt` | SVG | SSRF | <?xml-stylesheet href="http://…" type="text/xsl"?> | SVG root |
| `/script-external` | SVG | SSRF | <script src="http://…"> | SVG root |
| `/foreignobject-iframe` | SVG | SSRF | <foreignObject><iframe src="http://…"> | SVG root |
| `file:///etc/passwd` | SVG | LFI | <image href="file:///etc/passwd"> | SVG root |
| `/xxe-svg` | SVG | XXE | DOCTYPE + ENTITY direct | SVG root |
| `/xxe-png`, `/xxe-xmp`, `/xxe-xmp-file`, `/xxe-xmp-param`, `/xxe-xmp-nested`, `/xxe-svg`, `/xxe-xmp-data`, `/xxe-xmp-nested-send`, `/xxe-gopher`, `/xxe-php` | PNG | XXE | iTXt chunk "XML:com.adobe.xmp" with various DOCTYPE + URL techniques | iTXt chunk |
| `/ssrf-mvg`, `/ssrf-mvg-http`, `/ssrf-svg-https`, `/ssrf-svg-http`, `/ssrf-svg-ftp`, `/ssrf-gopher`, `/ssrf-ldap`, `/ssrf-image-https`, `/ssrf-image-http`, `/ssrf-svg-embedded`, `/ssrf-msl`, `/ssrf-epi`, `/ssrf-ps`, `/ssrf-text`, `/ssrf-multi-https`, `/ssrf-multi-http`, `/ssrf-multi-ftp`, `/ssrf-rar`, `/ssrf-zip` | PNG | SSRF | MVG/SVG with various delegate protocols (https, http, ftp, gopher, ldap, file, msl, epi, ps, text, rar, zip) | iTXt chunk with ImageMagick keyword |
| `/rce-imagemagick`, `/rce-delegate`, `/rce-mvg`, `/rce-https`, `/rce-http`, `/rce-ftp`, `/rce-msl`, `/rce-text`, `/rce-epi`, `/rce-ps`, `/rce-svg-delegate`, `/rce-svg-script`, `/rce-backtick`, `/rce-dollar`, `/rce-exec`, `/rce-svg-https`, `/rce-svg-http`, `/rce-rar`, `/rce-zip` | PNG | RCE | ImageMagick delegate command injection via MVG/SVG with various techniques (url(), image over, backticks, $(), exec:, msl:, epi:, ps:, text:, rar:, zip:) | iTXt chunk with ImageMagick keyword |
| `/xxe-jpg` | JPEG | XXE/SSRF | COM segment (0xFFFE) with DOCTYPE + URL | COM marker |
| `/xxe-gif` | GIF | XXE/SSRF | Repeated comment blocks with DOCTYPE + URL | GIF comment extension |
| `/rce-ghostscript` | PDF | RCE | Ghostscript PostScript injection | /Contents → PostScript code |
| `/rce-postscript` | PDF | RCE | PostScript file operator | /Contents → PostScript %pipe% |
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

