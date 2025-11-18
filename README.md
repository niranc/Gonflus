# UploadRenderAllTheThings

A comprehensive payload generator for security testing of file uploads. It generates all possible payloads for SSRF, XXE, RCE, XSS, Path Traversal, NTLM Leak, LFI, and other vulnerabilities in all common file formats.

## Installation

```bash
pip3 install -r requirements.txt
```

## Usage

```bash
./uploadrenderallthethings [burp-collab] [-e extension] [-d] [--extended]
```

Examples:
```bash
./uploadrenderallthethings abc123.burpcollaborator.net
./uploadrenderallthethings abc123.burpcollaborator.net -e pdf
./uploadrenderallthethings abc123.burpcollaborator.net -e svg
./uploadrenderallthethings abc123.burpcollaborator.net -e all
./uploadrenderallthethings abc123.burpcollaborator.net -e xml --extended
./uploadrenderallthethings abc123.burpcollaborator.net -e png --extended
./uploadrenderallthethings -d
```

**Note**: The `-d` option can be used alone to delete all generated folders without needing to specify Burp Collaborator.

Options:
- `-e, --extension`: Specify the extension to generate:
  - `pdf`, `docx`, `xlsx`, `pptx`: Office Documents
  - `svg`, `xml`, `html`: Web Formats
  - `png`, `jpg`, `jpeg`, `gif`: Images
  - `webm`, `mp4`: Video Formats
  - `md`, `markdown`: Markdown Files
  - `zip`, `jar`, `epub`: Archives
  - `txt`, `csv`, `rtf`: Text Files
  - `odt`, `ods`, `odp`: OpenDocument
  - `all`: Generates all payloads (default)
- `-d, --delete`: Deletes all generated folders before creating new payloads (can be used alone)
- `--extended`: Generates extended payloads with other formats content but target extension (e.g., SVG content with .xml extension, HTML content with .png extension). Structure: `<extension>/extended/<source_format>/<vulnerability>/<payload_file>`

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
  ├── extended/          (only with --extended flag)
  │   ├── <source_format>/
  │   │   ├── <vulnerability>/
  │   │   │   └── <payload>.<target_ext>
  │   │   └── ...
  │   └── ...
  └── master.<ext>
```

**Extended Structure Example** (with `--extended` flag):
```
xml/
  ├── xxe/
  │   └── xxe1_entity.xml
  ├── extended/
  │   ├── svg/
  │   │   ├── xxe/
  │   │   │   └── xxe1_svg.xml        (SVG content, .xml extension)
  │   │   ├── xss/
  │   │   │   └── xss1_svg.xml        (SVG content, .xml extension)
  │   │   └── ssrf/
  │   │       └── ssrf1_svg.xml       (SVG content, .xml extension)
  │   └── html/
  │       ├── xss/
  │       │   └── xss1_html.xml       (HTML content, .xml extension)
  │       └── ssrf/
  │           └── ssrf1_html.xml      (HTML content, .xml extension)
  └── master.xml
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

## Extended Payloads OOB Endpoints Table

When using the `--extended` flag, additional payloads are generated with other formats content but target extension. Use this table to identify extended payload endpoints:

| OOB Endpoint | Target Extension | Source Format | Vulnerability | Technique | Notes |
|-------------|------------------|---------------|---------------|-----------|-------|
| `/xxe-svg-xml` | XML | SVG | XXE | DOCTYPE + ENTITY in SVG | SVG content with .xml extension |
| `/xxe-svg-xml-https` | XML | SVG | XXE | DOCTYPE + ENTITY HTTPS | SVG content with .xml extension |
| `/xss-svg-xml` | XML | SVG | XSS | SVG onload | SVG content with .xml extension |
| `/xss-svg-xml-script` | XML | SVG | XSS | SVG script tag | SVG content with .xml extension |
| `/ssrf-svg-xml` | XML | SVG | SSRF | SVG image xlink:href | SVG content with .xml extension |
| `/xss-html-xml` | XML | HTML | XSS | HTML script tag | HTML content with .xml extension |
| `/xss-html-xml-img` | XML | HTML | XSS | HTML img onerror | HTML content with .xml extension |
| `/ssrf-html-xml` | XML | HTML | SSRF | HTML img src | HTML content with .xml extension |
| `/xss-html-svg` | SVG | HTML | XSS | HTML iframe in SVG foreignObject | HTML content with .svg extension |
| `/xss-html-svg-script` | SVG | HTML | XSS | HTML script in SVG | HTML content with .svg extension |
| `/xxe-xml-svg` | SVG | XML | XXE | DOCTYPE + ENTITY in SVG | XML content with .svg extension |
| `/xss-svg-html` | HTML | SVG | XSS | SVG onload in HTML | SVG content with .html extension |
| `/ssrf-svg-html` | HTML | SVG | SSRF | SVG image in HTML | SVG content with .html extension |
| `/xxe-xml-html` | HTML | XML | XXE | DOCTYPE + ENTITY in HTML | XML content with .html extension |
| `/xss-md-html` | HTML | MD | XSS | Markdown script in HTML | Markdown content with .html extension |
| `/xss-html-txt` | TXT | HTML | XSS | HTML script tag | HTML content with .txt extension |
| `/xss-html-txt-img` | TXT | HTML | XSS | HTML img onerror | HTML content with .txt extension |
| `/xss-svg-txt` | TXT | SVG | XSS | SVG onload | SVG content with .txt extension |
| `/xxe-xml-txt` | TXT | XML | XXE | DOCTYPE + ENTITY | XML content with .txt extension |
| `/xss-csv-txt` | TXT | CSV | XSS | CSV script tag | CSV content with .txt extension |
| `/xss-md-txt` | TXT | MD | XSS | Markdown script | Markdown content with .txt extension |
| `/xss-html-csv` | CSV | HTML | XSS | HTML script tag | HTML content with .csv extension |
| `/xss-txt-csv` | CSV | TXT | XSS | TXT script tag | TXT content with .csv extension |
| `/xxe-xml-csv` | CSV | XML | XXE | DOCTYPE + ENTITY | XML content with .csv extension |
| `/xss-html-md` | MD | HTML | XSS | HTML script tag | HTML content with .md extension |
| `/xss-svg-md` | MD | SVG | XSS | SVG onload | SVG content with .md extension |
| `/xxe-xml-md` | MD | XML | XXE | DOCTYPE + ENTITY | XML content with .md extension |
| `/xss-html-markdown` | Markdown | HTML | XSS | HTML script tag | HTML content with .markdown extension |
| `/xss-svg-markdown` | Markdown | SVG | XSS | SVG onload | SVG content with .markdown extension |
| `/xxe-xml-markdown` | Markdown | XML | XXE | DOCTYPE + ENTITY | XML content with .markdown extension |
| `/xss-svg-png` | PNG | SVG | XSS | SVG onload in PNG iTXt metadata | SVG content in PNG metadata (real PNG binary) |
| `/ssrf-svg-png` | PNG | SVG | SSRF | SVG image in PNG iTXt metadata | SVG content in PNG metadata (real PNG binary) |
| `/xss-html-png` | PNG | HTML | XSS | HTML script in PNG iTXt metadata | HTML content in PNG metadata (real PNG binary) |
| `/xxe-xml-png` | PNG | XML | XXE | DOCTYPE + ENTITY in PNG iTXt metadata | XML content in PNG metadata (real PNG binary) |
| `/xss-svg-jpg` | JPG | SVG | XSS | SVG onload in JPG COM segment | SVG content in JPG metadata (real JPG binary) |
| `/ssrf-svg-jpg` | JPG | SVG | SSRF | SVG image in JPG COM segment | SVG content in JPG metadata (real JPG binary) |
| `/xss-html-jpg` | JPG | HTML | XSS | HTML script in JPG COM segment | HTML content in JPG metadata (real JPG binary) |
| `/xxe-xml-jpg` | JPG | XML | XXE | DOCTYPE + ENTITY in JPG COM segment | XML content in JPG metadata (real JPG binary) |
| `/xss-svg-jpeg` | JPEG | SVG | XSS | SVG onload in JPEG COM segment | SVG content in JPEG metadata (real JPEG binary) |
| `/ssrf-svg-jpeg` | JPEG | SVG | SSRF | SVG image in JPEG COM segment | SVG content in JPEG metadata (real JPEG binary) |
| `/xss-html-jpeg` | JPEG | HTML | XSS | HTML script in JPEG COM segment | HTML content in JPEG metadata (real JPEG binary) |
| `/xxe-xml-jpeg` | JPEG | XML | XXE | DOCTYPE + ENTITY in JPEG COM segment | XML content in JPEG metadata (real JPEG binary) |
| `/xss-svg-gif` | GIF | SVG | XSS | SVG onload in GIF comment block | SVG content in GIF metadata (real GIF binary) |
| `/ssrf-svg-gif` | GIF | SVG | SSRF | SVG image in GIF comment block | SVG content in GIF metadata (real GIF binary) |
| `/xss-html-gif` | GIF | HTML | XSS | HTML script in GIF comment block | HTML content in GIF metadata (real GIF binary) |
| `/xxe-xml-gif` | GIF | XML | XXE | DOCTYPE + ENTITY in GIF comment block | XML content in GIF metadata (real GIF binary) |

**Note**: Extended payloads for images (PNG, JPG, JPEG, GIF) are real binary image files with malicious metadata. They can be parsed by ImageMagick, exiftool, and other metadata parsers.

## Supported File Formats

### Office Documents
- **PDF**: SSRF (24 techniques), NTLM Leak (2 techniques), LFI (2 techniques), XXE (2 techniques), RCE (6 techniques including Ghostscript/PostScript and JavaScript), XSS (12 techniques including sandbox bypass and injections), Info Disclosure (5 techniques using Excel/Office functions)
- **DOCX**: SSRF (5 techniques), LFI (1 technique), XXE (1 technique), XSS (2 techniques)
- **XLSX**: SSRF (3 techniques), LFI (1 technique), XXE (1 technique), XSS (2 techniques), Info Disclosure (5 techniques using Excel functions)
- **ODT/ODS/ODP**: XXE (2 techniques), XSS (1 technique), Info Disclosure (5 techniques for ODT/ODS using Excel/Office functions)
- **PPTX**: SSRF (2 techniques), XXE (2 techniques), XSS (2 techniques)

### Web Formats
- **HTML**: XSS (2 techniques), SSRF (4 techniques), RCE (2 techniques)
- **SVG**: SSRF (8 techniques), LFI (1 technique), XXE (1 technique), XSS (7 techniques)
- **XML**: XXE (5 techniques), XSS (4 techniques), Path Traversal (2 techniques)

### Images
- **GIF**: SSRF/XXE (1 technique via comment blocks), XSS (1 technique via comment blocks)
- **JPG/JPEG**: SSRF/XXE (1 technique via COM segment), XSS (1 technique via COM segment)
- **PNG**: SSRF/XXE (1 technique via iTXt chunk), RCE (2 techniques ImageMagick), XSS (1 technique via iTXt chunk)

### Video Formats
- **WEBM**: OOB Read/Write (3 techniques), Heap Buffer Overflow (3 techniques), Use-After-Free (2 techniques), Integer Overflow (4 techniques), RCE (3 techniques), DoS/Crash (4 techniques), Information Leak (2 techniques)
- **MP4**: OOB Read/Write (3 techniques), Heap Buffer Overflow (3 techniques), Use-After-Free (2 techniques), Integer Overflow (3 techniques), RCE (3 techniques), DoS/Crash (4 techniques), Information Leak (3 techniques), SSRF (2 techniques indirect), XSS (2 techniques indirect)

### Archives
- **ZIP**: XXE (2 techniques), Path Traversal (2 techniques), RCE (2 techniques PHP), XSS (1 technique via filename)
- **JAR**: XXE (2 techniques), Path Traversal (2 techniques), RCE (2 techniques PHP)
- **EPUB**: XXE (2 techniques), Path Traversal (2 techniques), XSS (1 technique via .xhtml)

### Text Files
- **TXT**: XSS (2 techniques), SSRF (2 techniques), Path Traversal (3 techniques), RCE (4 techniques)
- **CSV**: XSS (3 techniques), SSRF (2 techniques), Path Traversal (3 techniques), RCE (4 techniques)
- **RTF**: SSRF (2 techniques), XSS (4 techniques), Path Traversal (3 techniques), RCE (4 techniques)
- **Markdown (MD)**: RCE (7 techniques via XSS chain, OOB, internal), SSRF (3 techniques indirect), XSS (7 techniques), Information Leak (4 techniques), DoS (3 techniques), OOB (2 techniques)

## Master Payloads

For each extension, a "master" payload is generated that combines all vulnerabilities of the extension into a single file. The idea is to first try uploading this master, test as much as possible, and then if no feedback, upload the payloads one by one.

Master payloads are available at the root of each extension directory:
- `pdf/master.pdf` - Contains all techniques SSRF, NTLM, LFI, XXE
- `pdf/master2_rce.pdf` - Contains only RCE techniques (Ghostscript/PostScript) as they may break the main master
- `docx/master.docx` - Contains all techniques SSRF, LFI, XXE
- `xlsx/master.xlsx` - Contains all techniques SSRF, LFI, XXE
- `svg/master.svg` - Contains all techniques SSRF (8 techniques), LFI, XXE, XSS (7 techniques)
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
- `webm/master.webm` - Contains OOB, Heap Overflow, UAF, Integer Overflow, RCE, DoS, Info Leak techniques
- `mp4/master.mp4` - Contains OOB, Heap Overflow, UAF, Integer Overflow, RCE, DoS, Info Leak, SSRF, XSS techniques
- `md/master.md` - Contains RCE (XSS chain, OOB, internal), SSRF, XSS, Info Leak, DoS, OOB techniques

## Detailed PDF Techniques

### XSS
1. **JavaScript sandbox bypass with generator functions** - `/Names → /JavaScript` - Understands if Acrobat JavaScript APIs are supported, bypasses sandbox
2. **Data URI scheme with script** - `/Annot → /A → /URI` - Attempts to execute arbitrary JavaScript via data URI
3. **JavaScript injection via annotations** - `/Annot → /T` - Code injection via annotation Title field
4. **URI with XSS payload details** - `/Annot → /A → /URI` - URI injection with HTML payload
5. **JavaScript bypass Acrobat APIs** - `/Names → /JavaScript` - Bypasses Acrobat APIs to execute arbitrary code
6. **javascript: URI scheme** - `/Annot → /A → /URI` - Execution via javascript: protocol
7. **Annotation /V injection (Apryse WebViewer)** - `/Annot → /V` - Injection via annotation V field, works on vulnerable Apryse PDF WebViewer
8. **FontMatrix injection (PDF.js)** - `/Font → /FontMatrix` - Injection via FontMatrix, works on vulnerable PDF.js
9. **JavaScript sandbox bypass Apryse WebViewer SDK** - `/Names → /JavaScript` - Sandbox bypass in Apryse WebViewer SDK (10.9.x - 10.12.0)
10-12. **Simple versions for tests** - Simple XSS payloads without Burp Collaborator for quick testing

### Info Disclosure
1. **CELL("filename")** - `/Info → /Author` and `/Creator` - Formula directly in the PDF Info metadata - The information appears in the document properties (Author/Creator)
2. **INFO("version")** - `/Info → /Author` and `/Creator` - Formula directly in the PDF Info metadata - Displays the version in the metadata
3. **INFO("system")** - `/Info → /Author` and `/Creator` - Formula directly in the PDF Info metadata - Displays the system in the metadata
4. **NOW()** - `/Info → /Author` and `/Creator` - Formula directly in the PDF Info metadata - Displays the date in the metadata
5. **INFO("directory")** - `/Info → /Author` and `/Creator` - Formula directly in the PDF Info metadata - Displays the path in the metadata

**Note**: These payloads directly place Excel/Office formulas in the PDF Info metadata (`/Info` object with `/Author` and `/Creator`). After opening the PDF, check the document properties (right-click → Properties) to see the formula results in the Author/Creator fields. No JavaScript is needed, the formulas are directly in the metadata.

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
28. **URI file:// for accessing Windows files** - `/Annot → /A → /URI` - Attempts to access local files via file:// - Windows only

### XXE
29. **XMP packet DOCTYPE + ENTITY** - metadata stream - PDFBox, iText7, exiftool
30. **XFA forms DOCTYPE + ENTITY** - `/AcroForm → /XFA` - iText7 XmlParser, PDFBox XFA

### RCE
31. **Ghostscript PostScript injection** - `/Contents → PostScript code` - Ghostscript (bypass -dSAFER) - CVE-2019-10216, CVE-2019-14811
32. **PostScript file operator** - `/Contents → PostScript %pipe%` - Ghostscript, old parsers
33. **app.openDoc() for Windows execution** - `/Names → /JavaScript` - Attempts to execute Windows commands via app.openDoc() - Windows only
34. **URI START for Windows execution** - `/Annot → /A → /URI` - Attempts execution via START protocol on Windows - Windows only
35. **app.launchURL() for Windows execution** - `/Names → /JavaScript` - Attempts execution via app.launchURL() - Windows only
36. **app.launchURL() with file** - `/Names → /JavaScript` - Attempts to execute a local file via app.launchURL() - Windows only

## Detailed DOCX Techniques

### XSS
1. **<w:hyperlink r:id="rId1"> + rels Target="javascript:alert(1)"** - word/_rels/document.xml.rels - Word Windows, old Word Online
2. **{\field{\*\fldinst { HYPERLINK "javascript:alert(1)" }}}** - word/document.xml - Word Windows

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
1. **=HYPERLINK("javascript:alert(1)","click here")** - xl/worksheets/sheet1.xml - Excel Windows, Google Sheets, LibreOffice
2. **<xml><x><![CDATA[<svg onload=alert(1)>]]></x></xml> in customXml or sharedStrings** - customXml/item1.xml or xl/sharedStrings.xml - LibreOffice/OnlyOffice preview

### SSRF
1. **workbook.xml.rels → TargetMode="External"** - xl/_rels/workbook.xml.rels - POI, PhpSpreadsheet, EPPlus
2. **=HYPERLINK("http://…")** - xl/worksheets/sheet1.xml - All
3. **Images remote via drawing → blip r:link** - xl/drawings/drawing1.xml + rels - POI, EPPlus

### LFI
4. **=HYPERLINK("file:///etc/passwd")** - xl/worksheets/sheet1.xml - Excel, LibreOffice

### XXE
5. **sharedStrings.xml / workbook.xml DOCTYPE** - xl/sharedStrings.xml or workbook.xml - POI, PhpSpreadsheet (lxml)

### Info Disclosure
1. **CELL("filename")** - Cell + docProps/core.xml → dc:creator - Extracts the filename - The information appears in the document properties (Creator/Author)
2. **INFO("version")** - Cell + docProps/core.xml → dc:creator - Extracts Excel/Office version - Displays the version in the metadata
3. **INFO("system")** - Cell + docProps/core.xml → dc:creator - Extracts system information - Displays the system in the metadata
4. **NOW()** - Cell + docProps/core.xml → dc:creator - Extracts current date/time - Displays the date in the metadata
5. **INFO("directory")** - Cell + docProps/core.xml → dc:creator - Extracts the file directory - Displays the path in the metadata

**Note**: These payloads use Excel formulas in cells and modify the core.xml metadata to place formulas in dc:creator. After opening the file, check the document properties (right-click → Properties) to see the formula results in the Creator/Author field.

## Detailed SVG Techniques

### SSRF
1. **<image xlink:href="http://…">** - SVG root - Batik, librsvg, ImageMagick, Resvg, Chrome, Firefox
2. **<use xlink:href="http://…">** - SVG root - Batik, librsvg, ImageMagick, Chrome, Firefox
3. **<link rel="stylesheet" href="http://…">** - SVG root - Batik, librsvg, Chrome, Firefox
4. **@import url(http://…)** - SVG style - Batik, librsvg, Chrome, Firefox
5. **<?xml-stylesheet href="http://…"?>** - SVG root - Batik, librsvg, Chrome, Firefox
6. **<?xml-stylesheet href="http://…" type="text/xsl"?>** - SVG root - XSLT processors, Chrome
7. **<script src="http://…">** - SVG root - Batik, librsvg, Chrome, Firefox
8. **<foreignObject><iframe src="http://…">** - SVG root - Chrome, Firefox, Batik

### LFI
1. **<image href="file:///etc/passwd">** - SVG root - librsvg, ImageMagick

### XXE
1. **DOCTYPE + ENTITY direct** - SVG root - Batik, Inkscape, XML parsers

### XSS
1. **<svg onload=alert(1)>** - SVG root - ALL SVG parsers (Batik, librsvg, Chrome, ImageMagick, browsers)
2. **<script>alert(1)</script>** - SVG root - ALL SVG parsers (Batik, librsvg, Chrome, ImageMagick, browsers)
3. **<image href="x" onerror=alert(1)>** - SVG root - ALL
4. **<animate onbegin=alert(1)>** - SVG root - All except some WAF
5. **<script src="javascript:alert(1)">** - SVG root - Chrome, Firefox
6. **<image onload="alert(1)">** - SVG root - Chrome, Firefox
7. **<foreignObject><iframe src="data:text/html,…">** - SVG root - Chrome, Firefox

## Detailed Image Techniques

### PNG
- **iTXt chunk "XML:com.adobe.xmp" with DOCTYPE + URL** - iTXt chunk - ImageMagick, exiftool
- **ImageMagick delegate command injection** - iTXt chunk with delegate - ImageMagick (CVE-2016-3714, ImageTragick)
- **ImageMagick delegate wget/curl** - iTXt chunk with delegate SVG - ImageMagick
- **XSS iTXt chunk with <svg onload=alert(1)> → ImageMagick or HTML preview** - iTXt chunk - Some old parsers

### JPEG
- **COM segment (0xFFFE) with DOCTYPE + URL** - COM marker - ImageMagick, exiftool
- **XSS COM segment with <script>alert(1)</script> → ImageMagick -label** - COM marker - Very rare (only old ImageMagick + HTML output)

### GIF
- **Repeated comment blocks with DOCTYPE + URL** - GIF comment extension - ImageMagick
- **XSS Comment block with <script>alert(1)</script> → ImageMagick -label or preview** - GIF comment extension - Very rare (only old ImageMagick + HTML output)

## Detailed Archive Techniques

### ZIP/JAR/EPUB
- **XXE DOCTYPE + ENTITY** - XML in archive - All XML parsers
- **XXE Parameter entity** - XML in archive - All XML parsers
- **Path Traversal relative** - Filename in archive - All extractors
- **Path Traversal Windows** - Filename in archive - Windows extractors
- **RCE PHP system()** - shell.php in archive - PHP servers (ZIP/JAR only)
- **RCE PHP exec()** - shell.php in archive - PHP servers (ZIP/JAR only)
- **XSS ZIP Filename = <svg onload=alert(1)>.svg + extraction preview** - Filename in ZIP - Windows Explorer, some antivirus
- **XSS EPUB <script>alert(1)</script> in a .xhtml file** - OEBPS/chapter1.xhtml - Calibre, Apple Books, some readers

## Detailed Text File Techniques

### TXT/CSV/RTF
- **XSS script tag** - File content - HTML parsers
- **XSS img onerror** - File content - HTML parsers
- **XSS CSV =HYPERLINK("javascript:alert(1)","click")** - CSV content - Excel, Google Sheets (when auto-open)
- **XSS RTF {\field{\*\fldinst { HYPERLINK "javascript:alert(1)" }}}** - RTF content - WordPad, Word Windows
- **XSS RTF {\object\objdata javascript:alert(1)}** - RTF content - Very old Word Windows
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
- **XSS <text:a xlink:href="javascript:alert(1)">click</text:a>** - content.xml - LibreOffice, OnlyOffice

### Info Disclosure (ODT/ODS)
1. **CELL("filename")** - Cell (ODS) / content (ODT) + meta.xml → meta:initial-creator - Extracts the filename - The information appears in the document properties (Creator/Author)
2. **INFO("version")** - Cell (ODS) / content (ODT) + meta.xml → meta:initial-creator - Extracts LibreOffice/Office version - Displays the version in the metadata
3. **INFO("system")** - Cell (ODS) / content (ODT) + meta.xml → meta:initial-creator - Extracts system information - Displays the system in the metadata
4. **NOW()** - Cell (ODS) / content (ODT) + meta.xml → meta:initial-creator - Extracts current date/time - Displays the date in the metadata
5. **INFO("directory")** - Cell (ODS) / content (ODT) + meta.xml → meta:initial-creator - Extracts the file directory - Displays the path in the metadata

**Note**: These payloads use Excel/Office formulas in the cells (for ODS) or content (for ODT) and modify the meta.xml metadata to place the formulas in meta:initial-creator. After opening the file, check the document properties (right-click → Properties) to see the formula results in the Creator/Author field.

## Detailed XML Techniques

### XML
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

## Detailed HTML Techniques

### HTML
- **XSS script tag** - HTML root - All browsers
- **XSS svg onload** - HTML root - All browsers
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
- **XSS =HYPERLINK("javascript:alert(1)","click") in notes or text** - ppt/slides/slide1.xml - PowerPoint, Impress
- **XSS <a:href>javascript:alert(1)</a:href> in ppt/slides/slide1.xml** - ppt/slides/slide1.xml - LibreOffice Impress

## Detailed WEBM Techniques

### OOB Read/Write (Out-of-Bounds)
1. **Chunk size overflow** - EBML chunk with invalid size - libvpx, libwebm, Chrome, Firefox - CVE-2023-5217, CVE-2023-4863
2. **VP8 frame overflow** - Malformed VP8 frame data - libvpx parsers - CVE-2018-1000116
3. **Matroska segment overflow** - Invalid segment size in Matroska container - libwebm, FFmpeg - CVE-2019-11470

### Heap Buffer Overflow
1. **Superframe VP9 malformed** - Invalid VP9 superframe structure - libvpx - CVE-2023-5217 (exploited in-the-wild)
2. **Corrupted Huffman table** - Corrupted WebP Huffman table in WEBM - libwebp - CVE-2023-4863 (BLASTPASS Pegasus)
3. **Invalid chunk size** - Invalid chunk size causing heap overflow - All WEBM parsers - Multiple CVEs

### Use-After-Free
1. **Double-free** - Double-free in libvpx/libwebm - libvpx, Chrome - CVE-2020-6418, CVE-2024-38365
2. **Premature free** - Premature free in VP8/VP9 decoder - libvpx, Firefox - CVE-2020-6418

### Integer Overflow / Underflow
1. **Width overflow** - Width value > 2³² causing integer overflow - All WEBM parsers - CVE-2023-44488
2. **Height overflow** - Height value > 2³² causing integer overflow - All WEBM parsers - CVE-2023-44488
3. **Frame size overflow** - Frame size > 2³² leading to OOB - libvpx, libwebm - CVE-2017-0641
4. **Timestamp overflow** - Timestamp > 2⁶⁴ causing integer overflow - Matroska parsers - CVE-2023-44488

### RCE (Remote Code Execution)
1. **CVE-2023-5217 (libvpx)** - Heap buffer overflow in VP8/VP9 decoder - Chrome, Firefox, Telegram - Zero-click possible
2. **CVE-2023-4863 (libwebp)** - Heap buffer overflow in WebP decoder - Chrome, Firefox, iOS - BLASTPASS Pegasus exploit
3. **BLASTPASS exploit chain** - Combination of heap overflow + UAF - iOS, Chrome - Zero-click RCE

### DoS / Crash
1. **Invalid chunk** - Malformed EBML chunk causing immediate segfault - All parsers - Very easy to trigger
2. **Malformed EBML header** - Invalid EBML header structure - All parsers - Immediate crash
3. **Corrupted header** - Corrupted Matroska/WEBM header - FFmpeg, libwebm - Crash on parse
4. **Segfault trigger** - Specific byte pattern causing segfault - libvpx, Chrome - CVE-2018-1000116

### Information Leak
1. **OOB read** - Out-of-bounds read leaking heap addresses - libvpx, Chrome - CVE-2018-1000116
2. **Heap leak** - Heap memory leak via malformed chunk - All parsers - Information disclosure

**Note**: WEBM is based on the binary EBML/Matroska format. Vulnerabilities are mainly related to binary parsing (heap overflow, OOB, UAF) and not classic web vulnerabilities (XXE, SSRF, XSS). Exploits are often used in-the-wild (zero-click RCE).

## Detailed MP4 Techniques

### RCE (Remote Code Execution)
1. **CVE-2019-2107 (Android MediaCodec)** - RCE via H.264 tiles overflow - Android MediaCodec, WhatsApp - Exploited in-the-wild (WhatsApp 2019)
2. **CVE-2023-20069 (FFmpeg)** - Heap buffer overflow in MP4 parser - FFmpeg, GStreamer - RCE via OOB chain
3. **CVE-2024-30194 (Integer overflow → RCE)** - Integer overflow leading to RCE - FFmpeg, MediaCodec - Zero-click possible

### OOB Read/Write (Out-of-Bounds)
1. **moov atom size overflow** - Invalid moov atom size causing OOB - FFmpeg, MediaCodec, GStreamer - CVE-2024-47537, CVE-2018-13302
2. **stsd/trak overflow** - Malformed stsd/trak atoms causing OOB read/write - All MP4 parsers - CVE-2023-20069
3. **mov_read_dref OOB** - OOB read in mov_read_dref function - FFmpeg - CVE-2018-13302

### Heap Buffer Overflow
1. **stsd/trak overflow** - Invalid stsd/trak atom size causing heap overflow - FFmpeg, MediaCodec - CVE-2024-30194
2. **H.264 tiles overflow** - Malformed H.264 tiles in MP4 - Android MediaCodec - CVE-2019-2107
3. **Atom size invalid** - Invalid atom size causing heap overflow - All MP4 parsers - Multiple CVEs

### Use-After-Free (UAF)
1. **Double-free in mov.c** - Double-free in MP4 mov parser - FFmpeg - CVE-2024-30194
2. **Premature free** - Premature memory free in MP4 decoder - MediaCodec, FFmpeg - HackerOne reports

### Integer Overflow / Underflow
1. **Atom size overflow** - Atom size > 2³² causing integer overflow - All MP4 parsers - CVE-2024-30194, CVE-2018-13302
2. **Width/height overflow** - Width/height values > 2³² - All MP4 parsers - CVE-2024-30194
3. **Allocation negative** - Integer overflow leading to negative allocation - FFmpeg - CVE-2024-30194

### DoS / Crash
1. **Invalid atom** - Malformed atom causing immediate segfault - All parsers - Very easy to trigger
2. **Malformed ftyp** - Invalid ftyp atom structure - All parsers - Immediate crash
3. **Corrupted moov** - Corrupted moov atom header - FFmpeg, MediaCodec - Crash on parse
4. **Segfault trigger** - Specific byte pattern causing segfault - All parsers - CVE-2019-11931 (WhatsApp)

### Information Leak
1. **OOB read** - Out-of-bounds read leaking heap addresses - FFmpeg, MediaCodec - CVE-2018-13302
2. **Heap leak** - Heap memory leak via malformed atom - All parsers - Information disclosure
3. **Memory disclosure** - Memory disclosure via corrupted atoms - NGINX MP4 module - CVE-2022-41742

### SSRF (Server-Side Request Forgery) - Indirect
1. **Thumbnailer metadata** - MP4 metadata with remote URL fetched by thumbnailer - XFCE Tumbler, thumbnailers - CVE-2022-31094 (GPAC)
2. **XFCE Tumbler** - XFCE Tumbler fetching cover art from remote URL - XFCE Tumbler - GitHub issues

### XSS (Cross-Site Scripting) - Indirect
1. **Video embed** - Embedding MP4 with script in metadata - Video.js, browsers - CVE-2021-23414
2. **Track src bypass** - Track src with javascript: protocol - Video.js - CVE-2021-23414

**Note**: MP4 uses binary format based on "atoms" (boxes). Vulnerabilities are mainly in binary parsing (heap overflow, OOB, UAF, integer overflow) leading to RCE. Exploits are often used in-the-wild (WhatsApp 2019, BLASTPASS). Indirect SSRF and XSS are possible through thumbnailers or web parsers, but not directly in pure MP4 format.

## Detailed Markdown Techniques

### RCE (Remote Code Execution)
1. **XSS chain Electron apps** - `<script>require('child_process').exec(...)` - VNote, Joplin, Electron apps - CVE-2024-41662
2. **VNote CVE-2024-41662** - XSS → RCE via img onerror - VNote - Exploited in-the-wild (2024)
3. **MarkText DOM XSS → RCE** - `<details open ontoggle="require(...)">` - MarkText - CVE-2023-2318
4. **md-to-pdf code injection** - JavaScript code injection in code blocks - md-to-pdf - CVE-2021-23639
5. **OOB buffer overflow** - Large content + XSS chain - C++ renderers - Potential RCE
6. **Internal exec** - Code blocks with shell commands - Internal tools - RCE via conversion
7. **Frontmatter JS eval** - YAML frontmatter with JS eval - gray-matter lib - Potential 0-day

### SSRF (Server-Side Request Forgery) - Indirect
1. **Image link** - `![Image](http://...)` fetched by renderer - Markdown to PDF endpoints - CVE-2025-55161 (Stirling-PDF)
2. **Internal link** - Links to internal services - Thumbnailers, converters - CVE-2025-57818 (Firecrawl)
3. **Markdown to PDF conversion** - Links/images fetched during conversion - PDF conversion tools - SSRF chain

### XSS (Cross-Site Scripting)
1. **Details ontoggle** - `<details open ontoggle=alert(1)>` - All Markdown renderers - CVE-2025-61413, CVE-2025-57901
2. **Script tag** - `<script>alert(document.cookie)</script>` - All renderers - CVE-2025-49420, CVE-2025-46734
3. **Img onerror** - `<img src=x onerror=alert(1)>` - All renderers - Stored XSS
4. **SVG onload** - `<svg onload=alert(1)>` - All renderers - DOM XSS
5. **Mermaid diagram** - XSS in Mermaid code blocks - Mermaid renderers - XSS via diagrams
6. **Iframe src** - `<iframe src="javascript:alert(1)">` - HTML renderers - XSS bypass
7. **Clipboard paste** - Clipboard exfiltration via XSS - Editors - CVE-2025 (GitLab clipboard XSS)

### Information Leak
1. **Local file read** - `fetch('file:///etc/passwd')` via XSS - Electron apps - CVE-2023-0835 (markdown-pdf)
2. **DOM leak** - Exfiltration of cookies/URLs via XSS - All web renderers - Information disclosure
3. **Markdown PDF read** - Local file read via Node.js in PDF conversion - markdown-pdf - CVE-2023-0835
4. **Credentials exfil** - Exfiltration of localStorage/sessionStorage - Web apps - Credential theft

### DoS / Crash
1. **Nested lists** - Deeply nested lists causing parser crash - All parsers - DoS via recursion
2. **Infinite loop** - Circular references in links - Link parsers - DoS via loops
3. **Large table** - Extremely large tables - Table parsers - Memory exhaustion

### OOB (Out-of-Bounds) - Indirect
1. **Buffer overflow** - Large content causing buffer overflow in C++ renderers - C++ parsers - Potential RCE
2. **String parsing** - Malformed brackets causing OOB in string parsing - Text parsers - Potential leak

**Note**: Markdown is a text format, but vulnerabilities mainly come from HTML/JavaScript rendering in applications (editors, converters). RCE is possible via XSS chain in Electron apps (VNote, Joplin, MarkText). Indirect SSRF is possible through Markdown→PDF converters. Exploits are often used in-the-wild (2024-2025 in Markdown editors).

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

## References

- [SVG SSRF Cheatsheet](https://github.com/allanlw/svg-cheatsheet) - Comprehensive cheatsheet for exploiting server-side SVG processors
- [Malicious PDF](https://github.com/jonaslejon/malicious-pdf) - Collection of malicious PDF files for security testing
- [PayloadsAllThePDFs](https://github.com/luigigubello/PayloadsAllThePDFs) - Collection of PDF payloads for security testing

## Contribution

Feel free to add new file formats or vulnerability types by creating new generator modules in the `generators/` directory.
```
