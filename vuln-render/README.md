# Vulnerable Render Lab - All File Types

Vulnerable web application that uploads and renders **all file types** server-side to trigger various vulnerabilities.

## Quick Start

```bash
cd vuln-render
docker build -t gonflus-render-all .
docker run --rm -p 8080:80 gonflus-render-all
```

Access: `http://localhost:8080`

## Features

### Legitimate Preview
The application displays file content legitimately:
- **Office Documents** (DOCX/XLSX/PPTX/ODT/ODS/ODP): text extraction, tables, slides, images
- **PDF**: text extraction, metadata, preview
- **Images** (PNG/JPG/GIF/WEBP/BMP): display with EXIF metadata
- **Videos** (WEBM/MP4): video player with metadata
- **SVG/XML**: structured display
- **HTML**: preview in iframe
- **Archives** (ZIP/JAR/EPUB): file listing
- **Text** (TXT/CSV/RTF/MD): formatted display (tables for CSV)

### Supported File Types
- **Images**: png, jpg, jpeg, gif, webp, bmp
- **Videos**: webm, mp4
- **Documents**: pdf, docx, xlsx, pptx, odt, ods, odp
- **Markup**: svg, xml, html, htm
- **Archives**: zip, jar, epub
- **Text**: txt, csv, rtf, md

## Vulnerabilities Tested

- **RCE**: Ghostscript, ImageMagick, ExifTool, FFmpeg, libpng/libjpeg
- **SSRF**: LibreOffice, ImageMagick, embedded URLs
- **XXE**: PHP XML parsers, LibreOffice, exiftool
- **XSS**: HTML/text rendering
- **Path Traversal**: Archive extraction
- **NTLM Leak**: UNC paths

## Technologies

- PHP 8.1 (vulnerable XML parsers)
- LibreOffice (Office document conversion)
- ImageMagick 6.9.3-10 (vulnerable version)
- Ghostscript 10.03.0 (CVE-2024-29510)
- exiftool (metadata extraction)
- pdftoppm (PDF rendering)
- FFmpeg (video processing)

## Test Labs

Individual Docker labs available for each file extension with automated testing. See `labs/README.md` for details.

## Warning

⚠️ **This environment is intentionally vulnerable** for security testing purposes only. Do not expose to the internet or use in production.
