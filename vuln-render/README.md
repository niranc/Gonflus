# Vulnerable Render Lab - All File Types

This Docker environment provides a vulnerable web application that uploads and renders **all file types** server-side to trigger various vulnerabilities:

- **RCE** (Remote Code Execution) - Ghostscript, ImageMagick delegates
- **SSRF** (Server-Side Request Forgery) - LibreOffice, ImageMagick, embedded URLs
- **XXE** (XML External Entity) - PHP XML parsers, LibreOffice, exiftool
- **XSS** (Cross-Site Scripting) - HTML/text rendering
- **Path Traversal** - Archive extraction without validation
- **NTLM Leak** - UNC paths in various formats

## Quick Start

```bash
# Build the Docker image
cd vuln-render
docker build -t gonflus-render-all .

# Run the container
docker run --rm -p 8080:80 gonflus-render-all
```

Access the application at: `http://localhost:8080`

## Supported File Types & Vulnerabilities

### PDF
- **RCE**: Ghostscript PostScript injection
- **SSRF**: pdftoppm, embedded URLs
- **XXE**: exiftool XMP parsing

### DOCX/XLSX/PPTX
- **XXE**: XML parsing in document.xml, sharedStrings.xml, presentation.xml
- **SSRF**: LibreOffice conversion, external resources in rels files

### ODT/ODS/ODP
- **XXE**: XML parsing in content.xml
- **SSRF**: LibreOffice conversion

### SVG
- **SSRF**: ImageMagick xlink:href delegates
- **XXE**: XML parsing

### XML
- **XXE**: PHP SimpleXML, DOMDocument, XMLReader with vulnerable flags

### HTML
- **XSS**: Direct rendering
- **SSRF**: Embedded URLs

### JPG/JPEG
- **RCE ExifTool DjVu polyglotte**: CVE-2021-22204 (GitLab 15k$ + PayPal bounty)
- **RCE PHP unserialize EXIF**: Comment/Artist fields (Facebook 35k$ + Shopify 25k$)
- **RCE Java ysoserial EXIF/XMP**: Adobe Experience Manager 40k$
- **SSRF ICC profile URL**: Cloudinary 10k$ + Imgix CDN
- **XXE XMP embedded APP1**: GitLab 12k$ + DAM systems
- **RCE PHP code in EXIF + LFI chain**: BookFresh/Square 2023
- **RCE libjpeg EXIF buffer overflow**: Vercel workers 8k$ + CVE-2023-47475
- **SSRF EXIF GPS GeoURL**: Intigriti bounties 2024
- **RCE ExifTool MakerNotes eval**: CVE-2022-45020

### PNG
- **RCE libpng chunk overflow tEXt**: Vercel 8k$ + CVE-2023-47475
- **SSRF iTXt chunk URL**: Imgix 10k$ + ImageMagick CVE-2016-3718
- **XXE XML in tEXt chunk**: Adobe 12k$ + PortSwigger PNG-XXE
- **RCE PHP/Java unserialize in tEXt chunk**: Facebook 25k$ + media SaaS
- **SSRF polyglotte PNG + ImageTragick MVG**: WordPress plugins + bounties 5-10k$
- **RCE Sharp/libvips TIFF-in-PNG overflow**: Netlify/Vercel functions 2024-2025
- **XMP in PNG (XXE)**: XMP metadata parsing
- **ImageMagick identify/mogrify/composite**: Multiple ImageMagick operations
- **Extraction et parsing de tous les chunks PNG**: zTXt, sPLT, iCCP, etc.
- **PHP GD imagecreatefrompng**: libpng overflow via GD

### WebM
- **RCE VP8 frame buffer overflow**: Netflix bounty 2024 + CVE-2023-4863 libwebp chain
- **SSRF EBML metadata URL**: Neex/HackerOne 12k$ + CVE-2021-38171
- **XXE XML timed text embed**: YouTube-like SaaS 10k$ + CVE-2024-1010
- **SSRF m3u8 playlist embed polyglotte**: Neex report 2021-2024 + CVE-2017-9693
- **RCE FFmpeg avformat_open_input overflow**: Streaming platforms 2023-2025

### ZIP/JAR/EPUB
- **Path Traversal**: Archive extraction without validation
- **XXE**: XML parsing of files in archive
- **RCE**: PHP execution if shell files extracted

### TXT/CSV/RTF/MD
- **XSS**: Direct rendering
- **Command Injection**: If content is executed

## Technologies Used

- **PHP 8.1** with vulnerable XML parsers
- **LibreOffice** for Office document conversion
- **ImageMagick 6.9.3-10** (vulnerable version)
- **Ghostscript** for PDF processing
- **exiftool** for metadata extraction
- **pdftoppm** for PDF rendering

## Tests et Payloads

Un dossier `generators/` contient des scripts Python pour générer des payloads de test pour chaque vulnérabilité:

```bash
cd generators
python3 generate_png_xxe.py
python3 generate_png_ssrf_itxt.py
python3 generate_png_mvg.py
python3 generate_png_unserialize.py
python3 generate_jpeg_xxe_xmp.py
python3 generate_jpeg_unserialize_exif.py
```

Voir `generators/README.md` pour plus de détails sur les payloads disponibles.

## Labs de Test Universels

Des labs Docker séparés sont disponibles pour **TOUTES les extensions** avec des tests automatiques pour chaque payload généré.

### 🚀 Quick Start

```bash
# 1. Générer tous les labs depuis les générateurs
cd vuln-render/labs
./build_all_from_generators.sh

# 2. Générer le docker-compose (fait automatiquement)
./generate_docker_compose.sh

# 3. Lancer un lab
cd vuln-png
docker-compose up --build
# Ouvrir http://localhost:8080

# OU lancer tous les labs (méthode recommandée)
./launch_all_labs.sh

# OU avec docker-compose (si compatible)
docker-compose -f docker-compose.all.yml up --build
```

**Note** : Le `docker-compose.all.yml` est généré automatiquement avec uniquement les labs qui existent.

Voir `labs/START_HERE.md` pour le guide complet.

### Extensions Supportées

- **Images**: png, jpg, jpeg, gif
- **Vidéos**: webm, mp4
- **Documents**: pdf, docx, xlsx, pptx, odt, ods, odp
- **Markup**: svg, xml, html, htm
- **Archives**: zip, jar, epub
- **Textes**: txt, csv, rtf, md

### Génération Automatique de Tous les Labs

```bash
cd labs
./build_all_labs.sh [chemin_vers_payloads]
```

Par défaut, cherche les payloads dans `../../tocheck/`

Cela génère automatiquement un lab pour chaque extension trouvée :
- `vuln-png/`, `vuln-jpg/`, `vuln-jpeg/`, `vuln-gif/`
- `vuln-webm/`, `vuln-mp4/`
- `vuln-pdf/`, `vuln-docx/`, `vuln-xlsx/`, `vuln-pptx/`
- `vuln-odt/`, `vuln-ods/`, `vuln-odp/`
- `vuln-svg/`, `vuln-xml/`, `vuln-html/`
- `vuln-zip/`, `vuln-jar/`, `vuln-epub/`
- `vuln-txt/`, `vuln-csv/`, `vuln-rtf/`, `vuln-md/`

### Utilisation d'un Lab Spécifique

```bash
cd labs/vuln-png  # ou n'importe quelle extension
docker-compose up --build
```

Accédez au lab à : http://localhost:8080

### Lancer TOUS les Labs en Une Fois

```bash
cd labs
docker-compose -f docker-compose.all.yml up --build
```

Chaque lab est accessible sur un port différent (8081-8103). Voir `labs/README.md` pour la liste complète.

### Fonctionnalités de Chaque Lab

- **Interface web** pour tester les payloads
- **Tests automatiques** pour chaque vulnérabilité (RCE, SSRF, XXE, XSS, etc.)
- **Résultats détaillés** (succès, déclenchement, erreur)
- **Sortie des commandes** exécutées (ImageMagick, ExifTool, FFmpeg, LibreOffice, etc.)
- **Test individuel** ou **test en masse** de tous les payloads

Voir `labs/README.md` pour plus de détails.

## Warning

⚠️ **This environment is intentionally vulnerable** for security testing purposes only. Do not expose to the internet or use in production.

