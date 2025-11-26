## Overview of Known Vulnerabilities and PoCs by Rendered Format

This document lists known rendering behaviors, associated vulnerabilities (SSRF, XXE, RCE, XSS, LFI, Information Leak, DoS, etc.), public CVEs when available, and the main public PoCs/repositories.

It is organized by **file extension** supported by `UploadRenderAllTheThings`.

---

## PDF

| Vulnerability type | CVE / Specific context | Method / attack surface | PoC / Reference | Tool payload(s) (folder/file) | Affected technologies / libs (approx. versions) | Confidence |
|--------------------|------------------------|---------------------------|-----------------|------------------------------------|--------------------------------------------------|---------------------|
| RCE | (generic) – PDF JavaScript & forms | JavaScript in `/OpenAction`, `/Names → /JavaScript`, XFA forms, `submitForm`, `XMLHttpRequest`, `fetch` that can reach dangerous APIs or trigger code execution in vulnerable viewers/integrations | [`PortSwigger/portable-data-exfiltration`](https://github.com/PortSwigger/portable-data-exfiltration) | `pdf/rce/rce1_ghostscript.pdf`, `pdf/rce/rce2_postscript.pdf`, `pdf/rce/rce3_openDoc.pdf`, `pdf/rce/rce4_uri_start.pdf`, `pdf/rce/rce5_launchURL.pdf`, `pdf/rce/rce6_launchURL_file.pdf`, `pdf/master2_rce.pdf`, `pdf/master.pdf` | Adobe Acrobat/Reader (Desktop & Server), PDF.js, jsPDF, pdf-lib, various web PDF viewers (2010–2025) | 🟢 |
| Exfiltration | (generic) – PDF JavaScript & forms | JavaScript in `/OpenAction`, `/Names → /JavaScript`, XFA forms, `submitForm`, `XMLHttpRequest`, `fetch` used to send document data to attacker-controlled endpoints | [`PortSwigger/portable-data-exfiltration`](https://github.com/PortSwigger/portable-data-exfiltration) | `pdf/rce/rce1_ghostscript.pdf`, `pdf/rce/rce2_postscript.pdf`, `pdf/rce/rce3_openDoc.pdf`, `pdf/rce/rce4_uri_start.pdf`, `pdf/rce/rce5_launchURL.pdf`, `pdf/rce/rce6_launchURL_file.pdf`, `pdf/master2_rce.pdf`, `pdf/master.pdf` | Adobe Acrobat/Reader (Desktop & Server), PDF.js, jsPDF, pdf-lib, various web PDF viewers (2010–2025) | 🟢 |
| SSRF | (generic) – PDF JavaScript & forms | JavaScript in `/OpenAction`, `/Names → /JavaScript`, XFA forms, `submitForm`, `XMLHttpRequest`, `fetch` that perform HTTP/HTTPS requests to internal or external targets | [`PortSwigger/portable-data-exfiltration`](https://github.com/PortSwigger/portable-data-exfiltration) | `pdf/rce/rce1_ghostscript.pdf`, `pdf/rce/rce2_postscript.pdf`, `pdf/rce/rce3_openDoc.pdf`, `pdf/rce/rce4_uri_start.pdf`, `pdf/rce/rce5_launchURL.pdf`, `pdf/rce/rce6_launchURL_file.pdf`, `pdf/master2_rce.pdf`, `pdf/master.pdf` | Adobe Acrobat/Reader (Desktop & Server), PDF.js, jsPDF, pdf-lib, various web PDF viewers (2010–2025) | 🟢 |
| XXE | CVE-2021-22204 (ExifTool DJVU – same meta-XML logic) | XMP / XML metadata with `<!DOCTYPE>` + `<!ENTITY xxe SYSTEM "http://...">` or `file:///...` parsed by image/metadata libraries | Various examples in PATT + ExifTool advisories | `pdf/xxe/*`, `pdf/master.pdf` | ExifTool < 12.24, ImageMagick 6/7 before hardened XML parsing, third‑party XMP libraries | 🟢 |
| SSRF | CVE-2021-22204 (ExifTool DJVU – same meta-XML logic) | XMP / XML metadata with external HTTP entities (`SYSTEM "http://<collab>/..."`) causing outbound requests during parsing | Various examples in PATT + ExifTool advisories | `pdf/xxe/*`, `pdf/master.pdf` | ExifTool < 12.24, ImageMagick 6/7 before hardened XML parsing, third‑party XMP libraries | 🟢 |
| RCE (Ghostscript) | CVE-2019-10216, CVE-2019-14811 | Malicious PostScript in `/Contents` (privileged operators, `%pipe%`) executed by Ghostscript during conversion/printing/thumbnail generation | PoCs and examples in [`jonaslejon/malicious-pdf`](https://github.com/jonaslejon/malicious-pdf), [`luigigubello/PayloadsAllThePDFs`](https://github.com/luigigubello/PayloadsAllThePDFs) | `pdf/rce/rce1_ghostscript.pdf`, `pdf/master2_rce.pdf` | Ghostscript 9.x before ~9.27/9.50, tools that embed Ghostscript (ImageMagick, PDF converters) | 🟢 |
| XSS | (generic) – URL actions | `/Annot → /A → /URI (javascript:alert(1))`, `/OpenAction` JavaScript that executes in the viewer’s JS context | Various payloads in [`luigigubello/PayloadsAllThePDFs`](https://github.com/luigigubello/PayloadsAllThePDFs) and [`jonaslejon/malicious-pdf`](https://github.com/jonaslejon/malicious-pdf) | `pdf/xss/*`, `pdf/ssrf/*`, `pdf/master.pdf` | Web PDF viewers (older Chrome/Firefox PDF.js variants), embedded viewers in desktop apps | 🟢 |
| SSRF | (generic) – URL actions | `/Annot → /A → /URI (http://...)`, `/OpenAction` JavaScript that loads external HTTP/HTTPS resources to attacker‑controlled endpoints | Various payloads in [`luigigubello/PayloadsAllThePDFs`](https://github.com/luigigubello/PayloadsAllThePDFs) and [`jonaslejon/malicious-pdf`](https://github.com/jonaslejon/malicious-pdf) | `pdf/xss/*`, `pdf/ssrf/*`, `pdf/master.pdf` | Web PDF viewers (older Chrome/Firefox PDF.js variants), embedded viewers in desktop apps | 🟢 |

---

## DOCX / XLSX / PPTX (OOXML) / OpenDocument / EPUB

### DOCX

| Vulnerability type | CVE / Specific context | Method / attack surface | PoC / Reference | Tool payload(s) (folder/file) | Affected technologies / libs (approx. versions) | Confidence |
|--------------------|------------------------|---------------------------|-----------------|------------------------------------|--------------------------------------------------|---------------------|
| SSRF | (well-known pattern, no single CVE) | External relationships in `word/_rels/document.xml.rels` / `header*.rels` with `Target="http://<collab>/"` and `TargetMode="External"` | Office examples in [`swisskyrepo/PayloadsAllTheThings`](https://github.com/swisskyrepo/PayloadsAllTheThings) | `docx/ssrf/ssrf1_document_rels.docx`, `docx/ssrf/ssrf2_header_rels.docx`, `docx/ssrf/ssrf3_images_remote.docx`, `docx/ssrf/ssrf4_websettings.docx`, `docx/ssrf/ssrf5_customxml.docx`, `docx/master.docx` | Microsoft Word (2007–O365), LibreOffice, Apache POI, OpenXML SDK, DOCX converters server-side | 🟡 |
| SSRF | (well-known pattern) | `word/webSettings.xml` with `attachedTemplate` pointing to `http://host/template.dotm` (remote template load on client/server) | PoCs in various write‑ups & PATT | `docx/ssrf/ssrf4_websettings.docx`, `docx/ssrf/ssrf5_customxml.docx`, `docx/lfi/lfi7_websettings.docx`, `docx/master.docx` | Word for Windows (pre‑hardening), LibreOffice, custom DOCX parsers | 🟡 |
| LFI | (well-known pattern) | `word/webSettings.xml` with `attachedTemplate` pointing to `file:///c:/windows/win.ini` or other local paths (probing/local file read) | PoCs in various write‑ups & PATT | `docx/ssrf/ssrf4_websettings.docx`, `docx/ssrf/ssrf5_customxml.docx`, `docx/lfi/lfi7_websettings.docx`, `docx/master.docx` | Word for Windows (pre‑hardening), LibreOffice, custom DOCX parsers | 🟡 |
| XXE | (well-known pattern) | `customXml/item1.xml` containing DOCTYPE/ENTITY (HTTP or file://) | Tools like `oxml_xxe` and examples in PATT | `docx/xxe/xxe8_customxml.docx`, `docx/master.docx` | Apache POI, .NET OpenXML, Java/PHP/XML libraries before XXE was disabled | 🟡 |
| XSS | (well-known pattern) | `HYPERLINK "javascript:alert(1)"` fields in `document.xml` or embedded RTF | PoCs in PATT / Office XSS blog posts | `docx/xss/xss1_hyperlink_js.docx`, `docx/xss/xss2_field_hyperlink_js.docx`, `docx/master.docx` | Word/WordPad on Windows (older versions), RTF viewers embedding IE/Trident | 🟡 |

### XLSX

| Vulnerability type | CVE / Specific context | Method / attack surface | PoC / Reference | Tool payload(s) (folder/file) | Affected technologies / libs (approx. versions) | Confidence |
|--------------------|------------------------|---------------------------|-----------------|------------------------------------|--------------------------------------------------|---------------------|
| SSRF | (well-known pattern) | `xl/_rels/workbook.xml.rels` with `TargetMode="External"` pointing to `http://<collab>/` | Samples in PATT (XLSX SSRF) | `xlsx/ssrf/ssrf1_workbook_rels.xlsx`, `xlsx/ssrf/ssrf2_hyperlink.xlsx`, `xlsx/ssrf/ssrf3_images_remote.xlsx`, `xlsx/master.xlsx` | Apache POI, PhpSpreadsheet, EPPlus, LibreOffice Calc, preview services | 🟡 |
| SSRF | (well-known pattern, CSV/Excel injection) | Formulas like `=HYPERLINK("http://<collab>/")` that trigger network access when the XLSX is opened | CSV/Excel injection section in PATT | `xlsx/ssrf/ssrf2_hyperlink.xlsx`, `xlsx/lfi/lfi4_hyperlink_file.xlsx`, `xlsx/xss/xss1_hyperlink_js.xlsx`, `xlsx/xss/xss2_customxml_svg.xlsx`, `xlsx/master.xlsx` | Microsoft Excel (Windows/macOS), Google Sheets, LibreOffice Calc (pre‑hardening of formula handling) | 🟢 |
| LFI | (well-known pattern, CSV/Excel injection) | Formulas like `=HYPERLINK("file:///etc/passwd")` or other local paths potentially opening sensitive files | CSV/Excel injection section in PATT | `xlsx/ssrf/ssrf2_hyperlink.xlsx`, `xlsx/lfi/lfi4_hyperlink_file.xlsx`, `xlsx/xss/xss1_hyperlink_js.xlsx`, `xlsx/xss/xss2_customxml_svg.xlsx`, `xlsx/master.xlsx` | Microsoft Excel (Windows/macOS), Google Sheets, LibreOffice Calc (pre‑hardening of formula handling) | 🟢 |
| XSS | (well-known pattern, CSV/Excel injection) | Formulas/hyperlinks `javascript:alert(1)` or crafted contents reinterpreted as HTML/JS | CSV/Excel injection section in PATT | `xlsx/ssrf/ssrf2_hyperlink.xlsx`, `xlsx/lfi/lfi4_hyperlink_file.xlsx`, `xlsx/xss/xss1_hyperlink_js.xlsx`, `xlsx/xss/xss2_customxml_svg.xlsx`, `xlsx/master.xlsx` | Microsoft Excel (Windows/macOS), Google Sheets, LibreOffice Calc (pre‑hardening of formula handling) | 🟢 |
| XXE | (well-known pattern) | DOCTYPE/ENTITY inserted in `sharedStrings.xml` or `workbook.xml` | XLSX XXE examples in PATT / `oxml_xxe` tools | `xlsx/xxe/xxe5_sharedstrings.xlsx`, `xlsx/master.xlsx` | XML‑based parsers (libxml2, Java XML, .NET XML) not configured in secure mode | 🟡 |

### PPTX

| Vulnerability type | CVE / Specific context | Method / attack surface | PoC / Reference | Tool payload(s) (folder/file) | Affected technologies / libs (approx. versions) | Confidence |
|--------------------|------------------------|---------------------------|-----------------|------------------------------------|--------------------------------------------------|---------------------|
| SSRF | (well-known pattern) | External relationships in `ppt/_rels/presentation.xml.rels` pointing to HTTP/HTTPS URLs | PPTX SSRF examples in PATT | `pptx/ssrf/ssrf1_http.pptx`, `pptx/ssrf/ssrf2_https.pptx`, `pptx/master.pptx` | PowerPoint, LibreOffice Impress, POI/oxml PPTX, PPTX converters | 🟡 |
| XXE | (well-known pattern) | DOCTYPE/ENTITY injected in `ppt/presentation.xml` | PPTX XXE examples in PATT | `pptx/xxe/xxe1_doctype.pptx`, `pptx/xxe/xxe2_parameter.pptx`, `pptx/master.pptx` | XML parsers in Java/.NET/PHP stacks handling PPTX | 🟡 |
| XSS | (well-known pattern) | `javascript:alert(1)` hyperlinks or similar in `ppt/slides/slide1.xml` | PATT / PowerPoint XSS write‑ups | `pptx/xss/xss1_hyperlink_js.pptx`, `pptx/xss/xss2_href_js.pptx`, `pptx/master.pptx` | PowerPoint (older versions), web PPTX viewers without proper filtering | 🟡 |

### ODT / ODS / ODP (OpenDocument)

| Vulnerability type | CVE / Specific context | Method / attack surface | PoC / Reference | Tool payload(s) (folder/file) | Affected technologies / libs (approx. versions) | Confidence |
|--------------------|------------------------|---------------------------|-----------------|------------------------------------|--------------------------------------------------|---------------------|
| XXE | (well-known pattern) | DOCTYPE/ENTITY in `content.xml` (ODT/ODS/ODP) | PoCs in PATT and XXE articles for LibreOffice/OpenOffice | `odt/xxe/xxe1_doctype.odt`, `odt/xxe/xxe2_parameter.odt`, `ods/xxe/xxe1_doctype.ods`, `ods/xxe/xxe2_parameter.ods`, `odp/xxe/xxe1_doctype.odp`, `odp/xxe/xxe2_parameter.odp`, `odt/master.odt`, `ods/master.ods`, `odp/master.odp` | LibreOffice / Apache OpenOffice (pre‑XXE hardening versions) | 🟡 |
| XSS | (well-known pattern) | `<text:a xlink:href="javascript:alert(1)">` in `content.xml` | OpenDocument XSS examples in PATT / blog posts | `odt/xss/xss1_hyperlink.odt`, `ods/xss/xss1_hyperlink.ods`, `odp/xss/xss1_hyperlink.odp` | LibreOffice / OnlyOffice, OpenDocument viewers (2010–2020) | 🟡 |

### EPUB

| Vulnerability type | CVE / Specific context | Method / attack surface | PoC / Reference | Affected technologies / libs (approx. versions) | Confidence |
|--------------------|------------------------|---------------------------|-----------------|--------------------------------------------------|---------------------|
| XXE | (well-known pattern) | DOCTYPE/ENTITY in `content.opf` or other XML files inside the EPUB | XXE EPUB examples in PATT and Calibre/reader write‑ups | Calibre, EPUB readers based on standard XML stacks (before XXE was disabled) | 🟡 |
| XSS | (well-known pattern) | `<script>alert(1)</script>` in a `.xhtml` chapter of the book | PoCs in PATT and security research on EPUB readers | Calibre, Apple Books, readers based on WebKit/Gecko | 🟡 |

---

## SVG / XML / HTML

### SVG

| Vulnerability type | CVE / Specific context | Method / attack surface | PoC / Reference | Tool payload(s) (folder/file) | Affected technologies / libs (approx. versions) | Confidence |
|--------------------|------------------------|---------------------------|-----------------|------------------------------------|--------------------------------------------------|---------------------|
| SSRF | (well-known pattern) | `<image>`, `<use>`, `<link>`, `@import`, `<?xml-stylesheet?>` referencing `http://<collab>/...` | [`allanlw/svg-cheatsheet`](https://github.com/allanlw/svg-cheatsheet) | `svg/ssrf/ssrf1_image.svg`, `ssrf2_use.svg`, `ssrf3_css_link.svg`, `ssrf4_css_import.svg`, `ssrf5_xml_stylesheet.svg`, `ssrf6_xslt.svg`, `ssrf7_script_external.svg`, `ssrf8_foreignobject_iframe.svg`, `svg/master.svg` | Batik, librsvg, ImageMagick, browsers, SVG converters (2005–2025) | 🟡 |
| XXE | (well-known pattern) | DOCTYPE/ENTITY directly inside the SVG document | Examples in PATT & SVG cheatsheets | `svg/xxe/xxe1_doctype.svg`, `svg/master.svg` | Non‑hardened XML/SVG parsers (Java, .NET, C/C++ libs) | 🟡 |
| XSS | (well-known pattern) | `<svg onload=alert(1)>`, `<script>alert(1)</script>`, `<image onerror=alert(1)>`, `<foreignObject><iframe ...>` | PATT, SVG XSS blog posts | `svg/xss/xss1_onload.svg`, `xss2_script.svg`, `xss3_image_error.svg`, `xss4_animate.svg`, `xss5_script_external.svg`, `xss6_image_onload.svg`, `xss7_foreignobject.svg`, `svg/master.svg` | Browsers (Chrome/Firefox/Safari/Edge), embedded SVG viewers | 🟢 |
| LFI | (well-known pattern) | `<image href="file:///etc/passwd">` resolved by SVG parsers/previewers | SSRF/LFI exploits in Batik, ImageMagick | `svg/lfi/lfi1_image_file.svg`, `svg/master.svg` | Batik, ImageMagick, converters that resolve `file://` | 🟡 |

### XML

| Vulnerability type | CVE / Specific context | Method / attack surface | PoC / Reference | Tool payload(s) (folder/file) | Affected technologies / libs (approx. versions) | Confidence |
|--------------------|------------------------|---------------------------|-----------------|------------------------------------|--------------------------------------------------|---------------------|
| XXE | (classic pattern) | DOCTYPE with ENTITY `SYSTEM "file:///..."` or external DTD aimed at reading local files or internal resources | XXE section of [`swisskyrepo/PayloadsAllTheThings`](https://github.com/swisskyrepo/PayloadsAllTheThings) | `xml/xxe/xxe1_entity.xml`, `xxe2_https.xml`, `xxe3_file.xml`, `xxe4_parameter.xml`, `xxe5_doctype.xml`, `xml/master.xml` | libxml2, Java XML parsers (JAXP), .NET XML, PHP XML (pre‑XXE hardening) | 🟢 |
| SSRF | (classic pattern) | DOCTYPE with ENTITY `SYSTEM "http://<collab>/..."` triggering outbound HTTP requests during XML parsing | XXE section of [`swisskyrepo/PayloadsAllTheThings`](https://github.com/swisskyrepo/PayloadsAllTheThings) | `xml/xxe/xxe1_entity.xml`, `xxe2_https.xml`, `xxe3_file.xml`, `xxe4_parameter.xml`, `xxe5_doctype.xml`, `xml/master.xml` | libxml2, Java XML parsers (JAXP), .NET XML, PHP XML (pre‑XXE hardening) | 🟢 |
| DoS | (classic pattern – Billion Laughs, entity expansion) | DTD with recursive or massively expanded entities (`billion laughs`) causing CPU/memory exhaustion | XXE section of [`swisskyrepo/PayloadsAllTheThings`](https://github.com/swisskyrepo/PayloadsAllTheThings) | `xml/xxe/xxe1_entity.xml`, `xxe2_https.xml`, `xxe3_file.xml`, `xxe4_parameter.xml`, `xxe5_doctype.xml`, `xml/master.xml` | libxml2, Java XML parsers (JAXP), .NET XML, PHP XML (pre‑XXE hardening) | 🟢 |
| XSS | (well-known pattern) | `<script>alert(1)</script>` or `<?xml-stylesheet href="javascript:alert(1)"?>` rendered in a browser/viewer | PoCs in IE/XML XSS write‑ups | `xml/xss/xss1_script.xml`, `xss2_cdata.xml`, `xss3_svg.xml`, `xss4_stylesheet.xml`, `xml/master.xml` | IE/Edge Legacy, older built‑in XML viewers (Windows) | 🟡 |

### HTML

| Vulnerability type | CVE / Specific context | Method / attack surface | PoC / Reference | Tool payload(s) (folder/file) | Affected technologies / libs (approx. versions) | Confidence |
|--------------------|------------------------|---------------------------|-----------------|------------------------------------|--------------------------------------------------|---------------------|
| XSS | (very widespread, multi‑CVE) | `<script>`, `<img onerror>`, `<svg onload>` in HTML rendered client‑side or in viewers | PATT, generic XSS tutorials | `html/xss/xss1_script.html`, `xss2_img.html`, `xss3_svg.html`, `html/master.html` | Browsers (all families), HTML template engines, embedded viewers | 🟢 |
| SSRF | (well-known pattern) | `img src`, `link href`, `script src`, `iframe src` pointing to `http://<collab>/...` when fetching is done server‑side | SSRF via HTML renderers (proxies, converters) | `html/ssrf/ssrf1_img.html`, `ssrf2_link.html`, `ssrf3_script.html`, `ssrf4_iframe.html`, `html/master.html` | Server‑side HTML rendering/conversion engines (wkhtmltopdf, headless Chrome driven by backends, proxies) | 🟡 |
| RCE | (context‑specific) | `eval()`, `Function()` or non‑sandboxed JS in Node/Electron contexts | Exploits against Electron/Node‑based renderers | `html/rce/rce1_eval.html`, `rce2_function.html`, `html/master.html` | Electron / Node.js apps using non‑isolated webviews | 🟠 |

---

## Images – PNG / JPG / GIF

### PNG

| Vulnerability type | CVE / Specific context | Method / attack surface | PoC / Reference | Tool payload(s) (folder/file) | Affected technologies / libs (approx. versions) | Confidence |
|--------------------|------------------------|---------------------------|-----------------|------------------------------------|--------------------------------------------------|---------------------|
| RCE (ImageMagick) | CVE-2016-3714 and related (ImageTragick) | PNG (or other formats) with text/iTXt/label containing shell commands (`|`, `@`, etc.) interpreted by ImageMagick delegates | ImageTragick PoC repos + PATT | `png/rce/rce1_imagemagick.png`, `png/rce/rce2_imagemagick_delegate.png`, `png/master2_rce.png` | ImageMagick 6/7 before 2016–2017, tools using it (convert, webapps, CMS) | 🟢 |
| XXE | (well-known pattern) | iTXt / XMP chunk `"XML:com.adobe.xmp"` with malicious DOCTYPE/ENTITY, parsed by exiftool or converters | PoCs in ExifTool advisories and PATT | `png/ssrf/ssrf1_itxt.png`, `png/xxe/xxe1_itxt.png`, `png/master.png` | ExifTool < 12.24, XMP parsers, image indexing pipelines | 🟢 |
| SSRF | (well-known pattern) | iTXt / XMP chunk containing URLs (`SYSTEM "http://<collab>/..."`) that trigger outbound requests | PoCs in ExifTool advisories and PATT | `png/ssrf/ssrf1_itxt.png`, `png/xxe/xxe1_itxt.png`, `png/master.png` | ExifTool < 12.24, XMP parsers, image indexing pipelines | 🟢 |
| XXE | (well-known – polyglot) | SVG/XML content appended after IEND with DOCTYPE/ENTITY, interpreted by SVG/XML parsers | `ytiskw/png-svg-polyglot` tool, examples in PATT | `png/xss/xss1_itxt.svg.png`, `png/master.png` | ImageMagick, librsvg, other XML/SVG parsers invoked on embedded content | 🟡 |
| SSRF | (well-known – polyglot) | SVG/ZIP/JAR content appended after IEND with external HTTP references, causing SSRF when processed by other parsers | `ytiskw/png-svg-polyglot` tool, examples in PATT | `png/xss/xss1_itxt.svg.png`, `png/master.png` | ImageMagick, librsvg, unzip/Java JAR loaders, HTML viewers depending on the chain | 🟡 |
| RCE (polyglot) | (well-known – polyglot) | PNG+ZIP/JAR where the ZIP/JAR part contains code or gadgets leading to RCE when processed by unzip/JVM | `ytiskw/png-svg-polyglot` tool, examples in PATT | `png/xss/xss1_itxt.svg.png`, `png/master.png` | unzip, JAR/Java loaders, tools that treat the appended portion as an archive | 🟡 |
| XSS | (well-known – polyglot) | SVG/HTML appended after IEND containing `<script>` or event handlers, rendered in a browser/HTML viewer | `ytiskw/png-svg-polyglot` tool, examples in PATT | `png/xss/xss1_itxt.svg.png`, `png/master.png` | Browsers, HTML viewers that display embedded content | 🟡 |

### JPG / JPEG

| Vulnerability type | CVE / Specific context | Method / attack surface | PoC / Reference | Tool payload(s) (folder/file) | Affected technologies / libs (approx. versions) | Confidence |
|--------------------|------------------------|---------------------------|-----------------|------------------------------------|--------------------------------------------------|---------------------|
| XXE | (well-known pattern) | COM segment (0xFFFE) containing XML with DOCTYPE/ENTITY, parsed by exiftool/ImageMagick | Examples in PATT / image XXE blogs | `jpg/ssrf/ssrf1_com.jpg`, `jpg/xxe/xxe1_com.jpg`, `jpg/master.jpg` | ExifTool, ImageMagick, JPEG metadata libraries | 🟡 |
| SSRF | (well-known pattern) | COM segment (0xFFFE) containing external HTTP/HTTPS entities causing outbound requests | Examples in PATT / image XXE blogs | `jpg/ssrf/ssrf1_com.jpg`, `jpg/xxe/xxe1_com.jpg`, `jpg/master.jpg` | ExifTool, ImageMagick, JPEG metadata libraries | 🟡 |
| XSS | (well-known pattern) | COM segment with `<script>alert(1)</script>` used in HTML output (`convert -label`) | PoCs in Malicious Image research / PATT | `jpg/xss/xss1_com.jpg` | Pipelines that generate HTML from ImageMagick labels | 🟡 |
| RCE | (well-known pattern) | JPG+ZIP/JPG+PHAR containing code or gadgets that lead to code execution when processed by PHP/zip/JVM | PATT, image polyglot tools | (not explicitly generated by the tool – pattern only) | PHP interpreters (PHAR), unzip, PDF/ZIP renderers | 🟡 |
| Polyglot abuse | (well-known pattern) | JPG+PDF, JPG+ZIP, JPG+PHAR used to bypass filters (type misdetection) and reach other parsers | PATT, image polyglot tools | (not explicitly generated by the tool – pattern only) | Pipelines relying on extension/MIME without validating the real type | 🟡 |

### GIF

| Vulnerability type | CVE / Specific context | Method / attack surface | PoC / Reference | Tool payload(s) (folder/file) | Affected technologies / libs (approx. versions) | Confidence |
|--------------------|------------------------|---------------------------|-----------------|------------------------------------|--------------------------------------------------|---------------------|
| XXE | (well-known pattern) | GIF comment blocks containing XML with DOCTYPE/ENTITY, processed later by XML/XMP parsers | Examples in PATT / ImageMagick docs | `gif/ssrf/ssrf1_comment.gif`, `gif/xxe/xxe1_comment.gif`, `gif/xss/xss1_comment.gif`, `gif/master.gif` | ImageMagick, indexing/metadata pipelines | 🟡 |
| SSRF | (well-known pattern) | GIF comment blocks with entities or metadata pointing to `http://<collab>/...`, resolved by external tools | Examples in PATT / ImageMagick docs | `gif/ssrf/ssrf1_comment.gif`, `gif/xxe/xxe1_comment.gif`, `gif/xss/xss1_comment.gif`, `gif/master.gif` | ImageMagick, indexers or viewers that follow these URLs | 🟡 |
| XSS | (well-known pattern) | GIF comment blocks containing `<script>` that are injected into HTML pages (labels, tooltips, etc.) | Examples in PATT / ImageMagick docs | `gif/ssrf/ssrf1_comment.gif`, `gif/xxe/xxe1_comment.gif`, `gif/xss/xss1_comment.gif`, `gif/master.gif` | GIF viewers or web UIs that reuse comments in an HTML context | 🟡 |
| RCE Java (GIFAR) | (classic, many write‑ups) | Polyglot GIF+JAR file interpreted as GIF by some viewers and as JAR by the JVM | Historical GIFAR research + PoCs on GitHub | (not generated by the tool – documentation pattern) | JVM (Java 1.4–8), applets / vulnerable JAR loaders | 🟡 |

---

## Video – WEBM / MP4

### WEBM

| Vulnerability type | CVE / Specific context | Method / attack surface | PoC / Reference | Tool payload(s) (folder/file) | Affected technologies / libs (approx. versions) | Confidence |
|--------------------|------------------------|---------------------------|-----------------|------------------------------------|--------------------------------------------------|---------------------|
| Heap overflow | CVE-2023-5217 (libvpx) | Malformed VP8/VP9 frames (VP9 superframe) causing a heap overflow in libvpx (zero‑click) | Chromium/libvpx advisories / BLASTPASS‑like write‑ups | `webm/rce/rce1_cve_2023_5217.webm`, `webm/master.webm` | libvpx before 2023 fixes, Chrome/Firefox/Edge/Telegram using this library | 🟢 |
| RCE | CVE-2023-5217 (libvpx) | Exploiting the libvpx heap overflow to run arbitrary code via malicious WEBM files | Chromium/libvpx advisories / BLASTPASS‑like write‑ups | `webm/rce/rce1_cve_2023_5217.webm`, `webm/master.webm` | libvpx before 2023 fixes, Chrome/Firefox/Edge/Telegram using this library | 🟢 |
| Heap overflow | CVE-2023-4863 (libwebp) | Corrupted WebP Huffman table inside a container (often WEBM) leading to heap overflow in libwebp | BLASTPASS advisory / Google & Citizen Lab analyses | `webm/rce/rce2_cve_2023_4863.webm`, `webm/rce/rce3_blastpass.webm`, `webm/master.webm` | libwebp < ~1.3.2, Chrome/Firefox/Safari, WebP‑using apps (WhatsApp, iOS) | 🟢 |
| RCE | CVE-2023-4863 (libwebp) | Exploiting the heap overflow in libwebp to execute code via malicious images/WEBM | BLASTPASS advisory / Google & Citizen Lab analyses | `webm/rce/rce2_cve_2023_4863.webm`, `webm/rce/rce3_blastpass.webm`, `webm/master.webm` | libwebp < ~1.3.2, Chrome/Firefox/Safari, WebP‑using apps (WhatsApp, iOS) | 🟢 |

### MP4

| Vulnerability type | CVE / Specific context | Method / attack surface | PoC / Reference | Tool payload(s) (folder/file) | Affected technologies / libs (approx. versions) | Confidence |
|--------------------|------------------------|---------------------------|-----------------|------------------------------------|--------------------------------------------------|---------------------|
| RCE (Android MediaCodec) | CVE-2019-2107 | Malformed H.264 MP4 (tiles) exploited via MediaCodec (WhatsApp 2019) | Android/WhatsApp advisories, public MP4 PoCs | `mp4/rce/rce1_cve_2019_2107.mp4`, `mp4/master.mp4` | Android Media Framework (Android < 2019 patches), WhatsApp mobile | 🟢 |
| Heap / OOB | CVE-2023-20069, CVE-2024-30194 | MP4 atoms (`moov`, `stsd`, `trak`…) with invalid sizes causing heap overflows / out‑of‑bounds in FFmpeg / media frameworks | FFmpeg advisories, CVE lists | `mp4/oob/oob1_moov_size.mp4`, `mp4/oob/oob2_stsd_overflow.mp4`, `mp4/oob/oob3_mov_read_dref.mp4`, `mp4/heap_overflow/heap1_stsd_trak_overflow.mp4`, `heap2_h264_tiles.mp4`, `heap3_atom_size_invalid.mp4`, `mp4/integer_overflow/int1_atom_size_overflow.mp4`, `int2_width_height_overflow.mp4`, `int3_allocation_negative.mp4`, `mp4/rce/rce2_cve_2023_20069.mp4`, `rce3_cve_2024_30194.mp4`, `mp4/master.mp4` | FFmpeg, GStreamer, video players using these libs (2018–2024) | 🟢 |
| RCE | CVE-2023-20069, CVE-2024-30194 | Exploiting memory corruptions (heap/OOB/integer overflow) in MP4 parsers to execute code | FFmpeg advisories, CVE lists | `mp4/oob/oob1_moov_size.mp4`, `mp4/oob/oob2_stsd_overflow.mp4`, `mp4/oob/oob3_mov_read_dref.mp4`, `mp4/heap_overflow/heap1_stsd_trak_overflow.mp4`, `heap2_h264_tiles.mp4`, `heap3_atom_size_invalid.mp4`, `mp4/integer_overflow/int1_atom_size_overflow.mp4`, `int2_width_height_overflow.mp4`, `int3_allocation_negative.mp4`, `mp4/rce/rce2_cve_2023_20069.mp4`, `rce3_cve_2024_30194.mp4`, `mp4/master.mp4` | FFmpeg, GStreamer, video players using these libs (2018–2024) | 🟢 |
| SSRF indirect | CVE-2022-31094 (GPAC) | Metadata/URLs inside media processed by GPAC / thumbnailers triggering requests to arbitrary endpoints | GPAC advisory and media SSRF write‑ups | `mp4/ssrf/ssrf1_thumbnailer_metadata.mp4`, `ssrf2_xfce_tumbler.mp4`, `mp4/dos/*`, `mp4/master.mp4` | GPAC, Linux thumbnailers (Nautilus, XFCE, etc. depending on config) | 🟢 |
| DoS indirect | CVE-2022-31094 (GPAC) | Malformed metadata/URLs or structures causing crashes/loops in GPAC / thumbnailers | GPAC advisory and media SSRF write‑ups | `mp4/ssrf/ssrf1_thumbnailer_metadata.mp4`, `ssrf2_xfce_tumbler.mp4`, `mp4/dos/*`, `mp4/master.mp4` | GPAC, Linux thumbnailers (Nautilus, XFCE, etc. depending on config) | 🟢 |
| XSS (web video players) | CVE-2021-23414 (Video.js) | `track src="javascript:..."` or other poorly‑filtered media fields in Video.js | npm/Video.js advisory, XSS PoCs | `mp4/xss/xss1_video_embed.mp4`, `xss2_track_src.mp4` | Video.js players < ~7.14.x embedded in websites | 🟢 |

---

## Markdown (MD)

| Vulnerability type | CVE / Specific context | Method / attack surface | PoC / Reference | Tool payload(s) (folder/file) | Affected technologies / libs (approx. versions) | Confidence |
|--------------------|------------------------|---------------------------|-----------------|------------------------------------|--------------------------------------------------|---------------------|
| RCE (Electron apps) | CVE-2024-41662 (VNote), CVE-2023-2318 (MarkText) | XSS in Markdown rendering (`<script>require('child_process').exec(...)`, `<img onerror=...>`, `<details ontoggle=...>`) leading to system command execution | VNote / MarkText advisories, public PoCs in GitHub issues | `md/rce/rce1_xss_electron.md`, `md/rce/rce2_vnote_cve.md`, `md/rce/rce3_marktext_dom.md`, `md/master.md` | VNote, MarkText, other vulnerable Electron‑based Markdown editors (2019–2025) | 🟢 |
| RCE (Node converters) | CVE-2023-0835 (markdown-pdf) | JS in code blocks or `<script>` executed in a Node context (`require('child_process')`) during MD→PDF/HTML conversion | markdown-pdf advisory, PoC in the CVE report | `md/info_leak/info3_markdown_pdf_read.md`, `md/master.md` | `markdown-pdf` npm < patched version, similar Node tools (markdown→PDF/HTML) | 🟢 |
| Information Leak / File read (Node converters) | CVE-2023-0835 (markdown-pdf) | JS in code blocks or `<script>` using `require('fs')` to read local files during MD→PDF/HTML conversion | markdown-pdf advisory, PoC in the CVE report | `md/info_leak/info3_markdown_pdf_read.md`, `md/master.md` | `markdown-pdf` npm < patched version, similar Node tools (markdown→PDF/HTML) | 🟢 |
| RCE (md-to-pdf codeblocks) | CVE-2021-23639 | JS code in blocks interpreted by md-to-pdf, allowing `child_process.exec` server‑side | npm/md-to-pdf advisory and PoC in the report | `md/rce/rce4_md_to_pdf.md` | `md-to-pdf` < ~5.1.x (pre‑fix) | 🟢 |
| RCE (md-to-pdf front‑matter JS) | CVE-2025-65108 / GHSA-547r-qmjm-8hvw | Front‑matter with `---javascript`/`---js` delimiters evaluated via gray-matter, executing `child_process.execSync(...)` | GitHub Advisory [`GHSA-547r-qmjm-8hvw`](https://github.com/advisories/GHSA-547r-qmjm-8hvw) | `md/rce/rce_md_to_pdf_cve.md`, `md/rce/rce7_frontmatter_js.md` | `md-to-pdf` < 5.2.5 using gray-matter with JS support | 🟢 |
| SSRF (Markdown→PDF/services) | CVE-2025-55161 (Stirling-PDF), CVE-2025-57818 (Firecrawl) | Markdown images/links (`![Image](http://...)`, `[Link](http://internal/...)`) fetched server‑side during conversion or crawling | Stirling-PDF / Firecrawl advisories, PoCs in reports | `md/ssrf/*`, `md/master.md` | Vulnerable Stirling-PDF, vulnerable Firecrawl, other Markdown→PDF services that fetch URLs server‑side | 🟢 |
| XSS (Git platforms / web editors) | multi‑CVE (GitLab, Gitea, etc.) | Dangerous HTML in Markdown (`<details ontoggle=...>`, `<script>`, `<img onerror>`, `<svg onload>`, `mermaid` blocks) not filtered correctly | GitLab/Gitea advisories, PoCs in issues and security bulletins | `md/xss/*`, `md/master.md` | GitLab, GitHub Enterprise, Gitea/Forgejo, various web Markdown editors (2015–2025) | 🟢 |

---

## Archives – ZIP / JAR / EPUB

### ZIP

| Vulnerability type | CVE / Specific context | Method / attack surface | PoC / Reference | Tool payload(s) (folder/file) | Affected technologies / libs (approx. versions) | Confidence |
|--------------------|------------------------|---------------------------|-----------------|------------------------------------|--------------------------------------------------|---------------------|
| Path Traversal (Zip Slip) | CVE-2018-1002200 and variants | ZIP entries with paths like `../../../../var/www/html/shell.php` (or others) extracted without normalization, allowing writes outside the intended directory | Zip Slip project (Snyk) and related PoCs | `zip/path_traversal/path1_relative.zip`, `zip/path_traversal/path2_windows.zip`, `zip/master.zip` | Vulnerable decompression libraries in Java, .NET, Go, Python, Node (pre‑2018) | 🟢 |
| RCE (Zip Slip) | CVE-2018-1002200 and variants | Exploiting ZIP path traversal to drop executable files (webshell, scripts) into sensitive locations and gain code execution | Zip Slip project (Snyk) and related PoCs | `zip/path_traversal/path1_relative.zip`, `zip/path_traversal/path2_windows.zip`, `zip/master.zip` | Applications that extract ZIPs into executable directories (webroots, script folders) | 🟢 |
| RCE (PHP) | (well-known pattern) | `shell.php` files with `system()/exec()` inside an archive extracted into a webroot, then triggered via HTTP | Classic web exploitation & PATT | `zip/rce/rce1_php_system.zip`, `zip/rce/rce2_php_exec.zip`, `zip/master.zip` | PHP servers (Apache/Nginx+PHP-FPM) where the ZIP is extracted into the webroot | 🟢 |
| XXE | (well-known pattern) | `.xml` files inside ZIP with DOCTYPE/ENTITY (XML in ZIP/JAR/EPUB) | XXE (ZIP/JAR/EPUB) section of PATT | `zip/xxe/xxe1_doctype.zip`, `zip/xxe/xxe2_parameter.zip`, `zip/master.zip` | Any stack that extracts then parses XML with non‑hardened parsers | 🟡 |
| SSRF | (well-known pattern) | `.xml` files inside ZIP with external HTTP/HTTPS entities causing outbound requests during parsing | XXE (ZIP/JAR/EPUB) section of PATT | `zip/xxe/xxe1_doctype.zip`, `zip/xxe/xxe2_parameter.zip`, `zip/master.zip` | Any stack that extracts then parses XML with non‑hardened parsers | 🟡 |
| XSS | (well-known pattern) | Files named `<svg onload=alert(1)>.svg` in a ZIP, shown in an explorer/antivirus that renders the name as HTML | ZIP filename XSS / Windows Explorer write‑ups | `zip/xss/xss1_filename.zip` | Explorers/antivirus products that render filenames inside an HTML UI (Windows, third‑party tools) | 🟡 |

### JAR

| Vulnerability type | CVE / Specific context | Method / attack surface | PoC / Reference | Tool payload(s) (folder/file) | Affected technologies / libs (approx. versions) | Confidence |
|--------------------|------------------------|---------------------------|-----------------|------------------------------------|--------------------------------------------------|---------------------|
| RCE Java (deserialization) | multi‑CVE (vulnerable Java libraries) | JAR containing ysoserial gadget chains loaded by a vulnerable app (remote/local deserialization attacks) | [`frohoff/ysoserial`](https://github.com/frohoff/ysoserial) and many PoCs | `jar/rce/rce1_php_system.jar`, `jar/rce/rce2_php_exec.jar`, `jar/master.jar` | Java frameworks (Spring, Struts, etc.) and vulnerable serialization libraries (2010–2020) | 🟢 |
| RCE Java (GIFAR) | (classic, many write‑ups) | Polyglot GIF+JAR served as an image but used as a JAR by the JVM | GIFAR research (BlackHat, security blogs) | (not generated by the tool – documentation pattern) | JVM 1.4–8, browsers with applet/Java Web Start support | 🟡 |

### EPUB

| Vulnerability type | CVE / Specific context | Method / attack surface | PoC / Reference | Tool payload(s) (folder/file) | Affected technologies / libs (approx. versions) | Confidence |
|--------------------|------------------------|---------------------------|-----------------|------------------------------------|--------------------------------------------------|---------------------|
| XXE | (well-known pattern) | XML with DOCTYPE/ENTITY inside the EPUB archive | XXE EPUB examples (PATT, Calibre/reader PoCs) | `epub/xxe/xxe1_doctype.epub`, `epub/xxe/xxe2_parameter.epub`, `epub/master.epub` | Calibre, custom EPUB readers, engines based on libxml2/Java XML | 🟡 |
| XSS | (well-known pattern) | `<script>alert(1)</script>` in a `.xhtml` chapter rendered by an EPUB reader | PoCs in EPUB security research | `epub/xss/xss1_script.epub` | Calibre, Apple Books, EPUB readers based on WebKit/Gecko | 🟡 |

---

## Text – TXT / CSV / RTF

### TXT

| Vulnerability type | CVE / Specific context | Method / attack surface | PoC / Reference | Tool payload(s) (folder/file) | Affected technologies / libs (approx. versions) | Confidence |
|--------------------|------------------------|---------------------------|-----------------|------------------------------------|--------------------------------------------------|---------------------|
| XSS | (well-known pattern) | Raw HTML/JS in `.txt` rendered by a browser or HTML viewer | Generic XSS in text content (PATT) | `txt/xss/xss1_script.txt`, `xss2_img.txt`, `txt/master.txt` | Any system that renders `.txt` as HTML (misconfigurations, previewers) | 🟡 |
| SSRF | (well-known pattern) | Direct HTTP/HTTPS URLs in `.txt` consumed by HTTP clients/parsers | PATT (text files SSRF section) | `txt/ssrf/ssrf1_http.txt`, `ssrf2_https.txt`, `txt/master.txt` | Log/index pipelines, scanners or tools that fetch URLs from text files | 🟡 |
| Path Traversal | (well-known pattern) | Relative/Windows-style paths in `.txt` used as file paths by parsers | PATT (text files path traversal section) | `txt/path_traversal/path1_relative.txt`, `path2_windows.txt`, `path3_double.txt`, `txt/master.txt` | File processing tools that trust paths from text content | 🟡 |
| RCE (command injection) | (well-known pattern) | TXT content injected into shell commands (e.g. `; curl http://<collab>/pwn`, `| nc ...`, backticks, `$()`) | Generic command injection exploits / PATT | `txt/rce/rce1_pipe.txt`, `rce2_semicolon.txt`, `rce3_backtick.txt`, `rce4_dollar.txt`, `txt/master.txt` | bash/Python/Node/PHP scripts concatenating TXT into `system`/`exec`/backticks | 🟡 |

### CSV

| Vulnerability type | CVE / Specific context | Method / attack surface | PoC / Reference | Tool payload(s) (folder/file) | Affected technologies / libs (approx. versions) | Confidence |
|--------------------|------------------------|---------------------------|-----------------|------------------------------------|--------------------------------------------------|---------------------|
| XSS (formula injection) | multi‑research (Excel, GSheets) | Cells starting with `=`, `+`, `-`, `@` (e.g. `=HYPERLINK("javascript:alert(1)")`) executed by spreadsheet apps | CSV injection section in [`swisskyrepo/PayloadsAllTheThings`](https://github.com/swisskyrepo/PayloadsAllTheThings) | `csv/xss/xss1_script.csv`, `xss2_img.csv`, `xss3_hyperlink.csv`, `csv/master.csv` | Excel desktop, Google Sheets, LibreOffice Calc, tools auto-opening CSV | 🟢 |
| SSRF | (well-known pattern) | HTTP/HTTPS URLs inside CSV cells fetched by importers/parsers | PATT (text/CSV SSRF patterns) | `csv/ssrf/ssrf1_http.csv`, `ssrf2_https.csv`, `csv/master.csv` | ETL pipelines, previewers or scanners that follow URLs from CSV | 🟡 |
| Path Traversal | (well-known pattern) | Filenames/paths in CSV cells used directly as file paths | PATT (path traversal in text/CSV) | `csv/path_traversal/path1_relative.csv`, `path2_windows.csv`, `path3_double.csv`, `csv/master.csv` | Import tools or scripts that read files based on CSV paths | 🟡 |
| RCE (formula-based) | multi‑research (Excel, GSheets) | Dangerous formulas like `=cmd|' /C calc'!A0` or shell invocations | CSV injection research / PATT | `csv/rce/rce1_pipe.csv`, `rce2_semicolon.csv`, `rce3_backtick.csv`, `rce4_dollar.csv`, `csv/master.csv` | Excel on Windows (DDE/command-injection scenarios), similar spreadsheet engines | 🟢 |

### RTF

| Vulnerability type | CVE / Specific context | Method / attack surface | PoC / Reference | Tool payload(s) (folder/file) | Affected technologies / libs (approx. versions) | Confidence |
|--------------------|------------------------|---------------------------|-----------------|------------------------------------|--------------------------------------------------|---------------------|
| XSS | (well-known pattern) | RTF fields/objects containing `javascript:` or script-like content rendered by viewers | PATT, RTF injection blogs | `rtf/xss/xss1_script.rtf`, `xss2_img.rtf`, `xss1_hyperlink.rtf`, `xss2_object.rtf`, `rtf/master.rtf` | Word/WordPad, RTF viewers that interpret `javascript:` or HTML-like content | 🟡 |
| SSRF | (well-known pattern) | RTF `HYPERLINK "http://<collab>/"` fields followed automatically by clients | PATT (RTF SSRF patterns) | `rtf/ssrf/ssrf1_hyperlink.rtf`, `ssrf2_hyperlink.rtf`, `rtf/master.rtf` | Word, LibreOffice, other RTF-capable clients following external links | 🟡 |
| RCE Office (Equation Editor / command injection) | CVE-2017-11882, CVE-2018-0802 (plus generic command indicators) | Malicious OLE/equation objects or command-like payloads leading to code execution | Public exploit kits, PATT, Equation Editor write‑ups | `rtf/rce/rce1_pipe.rtf`, `rce2_semicolon.rtf`, `rce3_backtick.rtf`, `rce4_dollar.rtf`, `rtf/master.rtf` | Microsoft Office (Word) before 2017–2018 Equation Editor patches, or scripts using RTF payloads for command injection | 🟢 |

---

## Summary

- Every format handled by `UploadRenderAllTheThings` has **public PoCs** or **documented patterns** that demonstrate:
  - **SSRF / XXE** via external resources (images, stylesheets, metadata, rels, DOCTYPE, etc.).
  - **RCE** via rendering engines (Ghostscript, ImageMagick, Office, Electron, media frameworks, Node.js).
  - **XSS / LFI / Information Leak / DoS** in different contexts (browsers, viewers, office suites, conversion services).
- Representative vulnerabilities such as:
  - **ImageTragick (CVE-2016-3714)**, **Ghostscript** (CVE-2019-10216, CVE-2019-14811),
  - **Equation Editor** (CVE-2017-11882), **libvpx/libwebp** (CVE-2023-5217, CVE-2023-4863),
  - **md-to-pdf** front‑matter JS (**CVE-2025-65108**, [`GHSA-547r-qmjm-8hvw`](https://github.com/advisories/GHSA-547r-qmjm-8hvw)),
  - **VNote / MarkText / markdown-pdf** (RCE via Markdown),
  - and the many **XXE**, **SSRF** and **CSV injection** cases listed in [`swisskyrepo/PayloadsAllTheThings`](https://github.com/swisskyrepo/PayloadsAllTheThings),
are the foundation for the behaviors modeled by the payloads generated by this project.


