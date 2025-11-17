# File Upload Test Application

A simple web application to test file uploads and view rendered content for security testing purposes.

## Installation

**Note**: Requires Node.js 14+ (Node.js 18+ recommended)

If you have Node.js version issues, see `INSTALL.md` for troubleshooting.

```bash
cd test-app
npm install
```

## Usage

```bash
npm start
```

Or with auto-reload (requires nodemon):

```bash
npm run dev
```

The application will be available at `http://localhost:3000`

## Features

- **File Upload**: Drag and drop or browse to upload files
- **File Viewing**: View uploaded files directly in the browser
- **File Download**: Download uploaded files
- **File Management**: Delete uploaded files
- **Multiple Format Support**: 
  - Images (JPG, PNG, GIF, SVG) - displayed inline
  - PDFs - displayed in browser
  - HTML files - rendered as HTML
  - XML files - displayed as XML
  - Office documents (DOCX, XLSX, PPTX) - downloadable
  - Text files (TXT, CSV, RTF) - displayed as text

## Security Testing

This application is designed to test file upload vulnerabilities:

- **SSRF**: Test if uploaded files trigger server-side requests
- **XXE**: Test XML External Entity injection in XML-based files
- **RCE**: Test Remote Code Execution through malicious files
- **XSS**: Test Cross-Site Scripting in HTML/SVG files
- **Path Traversal**: Test directory traversal vulnerabilities

## Upload Directory

All uploaded files are stored in the `uploads/` directory.

## Vulnerabilities

This application is **intentionally vulnerable** for security testing:

- ❌ **No CSRF protection** - All endpoints are unprotected
- ❌ **No file type validation** - Accepts all file types
- ❌ **No file size limits** - Large files accepted
- ❌ **No sanitization** - HTML/XML files rendered as-is (XSS/XXE possible)
- ❌ **No path traversal protection** - Filenames not sanitized
- ❌ **No authentication** - Public access to all features

## Notes

⚠️ **Warning**: This application is intentionally vulnerable for security testing purposes. Do not use in production environments. Use only in isolated test environments.

