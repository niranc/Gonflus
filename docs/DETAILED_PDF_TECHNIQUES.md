# Detailed PDF Techniques

## XSS
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
13. **pdf-lib Acrobat alert 1 of PDF injection** - `/Annot → /A → /JavaScript` - pdf-lib generated PDFs with JavaScript alert injection
14. **pdf-lib Acrobat steal contents of PDF with JS** - `/Annot → /A → /JavaScript` - pdf-lib generated PDFs extracting PDF contents via JavaScript
15. **pdf-lib Acrobat steal contents of PDF without JS** - PDF structure manipulation - pdf-lib generated PDFs extracting contents without JavaScript
16. **jsPDF Acrobat executing automatically when closed** - `/Annot → /AA → /PC → /JavaScript` - jsPDF generated PDFs executing JavaScript on close
17. **jsPDF Acrobat executing automatically without click** - `/Annot → /AA → /PV → /JavaScript` - jsPDF generated PDFs executing JavaScript automatically
18. **jsPDF hybrid** - `/Annot → /A → /JavaScript` - jsPDF generated hybrid PDFs with JavaScript execution
19. **jsPDF Chrome JS execution** - `/Annot → /A → /JavaScript` - jsPDF generated PDFs for Chrome with JavaScript execution
20. **jsPDF Chrome enumerator** - `/Annot → /A → /JavaScript` - jsPDF generated PDFs for Chrome with object enumeration

## Info Disclosure
1. **CELL("filename")** - `/Info → /Author` and `/Creator` - Formula directly in the PDF Info metadata - The information appears in the document properties (Author/Creator)
2. **INFO("version")** - `/Info → /Author` and `/Creator` - Formula directly in the PDF Info metadata - Displays the version in the metadata
3. **INFO("system")** - `/Info → /Author` and `/Creator` - Formula directly in the PDF Info metadata - Displays the system in the metadata
4. **NOW()** - `/Info → /Author` and `/Creator` - Formula directly in the PDF Info metadata - Displays the date in the metadata
5. **INFO("directory")** - `/Info → /Author` and `/Creator` - Formula directly in the PDF Info metadata - Displays the path in the metadata

**Note**: These payloads directly place Excel/Office formulas in the PDF Info metadata (`/Info` object with `/Author` and `/Creator`). After opening the PDF, check the document properties (right-click → Properties) to see the formula results in the Author/Creator fields. No JavaScript is needed, the formulas are directly in the metadata.

## SSRF
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
25. **jsPDF Acrobat make entire document clickable** - `/Annot → /A → /SubmitForm` - jsPDF generated PDFs with form submission
26. **jsPDF Acrobat track when opening PDF filesystem** - `/Annot → /AA → /PV → /JavaScript` - jsPDF generated PDFs tracking file system access
27. **jsPDF Acrobat track when closing PDF filesystem** - `/Annot → /AA → /PC → /JavaScript` - jsPDF generated PDFs tracking file system access on close
28. **jsPDF Acrobat enumerator** - `/Annot → /A → /JavaScript` - jsPDF generated PDFs with object enumeration
29. **jsPDF Chrome PDF SSRF** - `/Annot → /A → /JavaScript → submitForm` - jsPDF generated PDFs with form submission to remote URL
30. **jsPDF Chrome extracting text** - `/Annot → /A → /JavaScript → submitForm` - jsPDF generated PDFs extracting text and submitting
31. **jsPDF Chrome injection overwrite URL** - `/Annot → /A → /URI` - jsPDF generated PDFs with URL overwrite injection

## NTLM Leak
1. **XObject Image UNC path** - `/XObject → /Subtype /Image → /URL or /SMask` - Windows + iText7, PDFBox, Syncfusion, Aspose, wkhtmltopdf
2. **FontFile2/3 UNC path** - `/Font → /FontFile2 or /FontFile3` - Windows + iText7, TCPDF

## LFI
1. **GoToR file:///** - `/Annot → /A → /GoToR → /F` - wkhtmltopdf, old parsers
2. **URI file:// for accessing Windows files** - `/Annot → /A → /URI` - Attempts to access local files via file:// - Windows only

## XXE
1. **XMP packet DOCTYPE + ENTITY** - metadata stream - PDFBox, iText7, exiftool
2. **XFA forms DOCTYPE + ENTITY** - `/AcroForm → /XFA` - iText7 XmlParser, PDFBox XFA

## RCE
1. **Ghostscript PostScript injection** - `/Contents → PostScript code` - Ghostscript (bypass -dSAFER) - CVE-2019-10216, CVE-2019-14811
2. **PostScript file operator** - `/Contents → PostScript %pipe%` - Ghostscript, old parsers
3. **app.openDoc() for Windows execution** - `/Names → /JavaScript` - Attempts to execute Windows commands via app.openDoc() - Windows only
4. **URI START for Windows execution** - `/Annot → /A → /URI` - Attempts execution via START protocol on Windows - Windows only
5. **app.launchURL() for Windows execution** - `/Names → /JavaScript` - Attempts execution via app.launchURL() - Windows only
6. **app.launchURL() with file** - `/Names → /JavaScript` - Attempts to execute a local file via app.launchURL() - Windows only

