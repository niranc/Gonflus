# Detailed Image Techniques

## PNG

### SSRF (Server-Side Request Forgery) - 20 payloads
1. **ssrf1_itxt.png** - XMP iTXt chunk with DOCTYPE + URL - ImageMagick, exiftool
2. **ssrf2_mvg_url.png** - MVG with url(https://...) delegate - ImageMagick
3. **ssrf3_mvg_http.png** - MVG with url(http://...) delegate - ImageMagick
4. **ssrf4_mvg_ftp.png** - MVG with url(ftp://...) delegate - ImageMagick
5. **ssrf5_svg_https.png** - SVG with xlink:href https - ImageMagick
6. **ssrf6_svg_http.png** - SVG with xlink:href http - ImageMagick
7. **ssrf7_svg_ftp.png** - SVG with xlink:href ftp - ImageMagick
8. **ssrf8_mvg_gopher.png** - MVG with url(gopher://...) delegate - ImageMagick
9. **ssrf9_mvg_ldap.png** - MVG with url(ldap://...) delegate - ImageMagick
10. **ssrf10_mvg_file.png** - MVG with url(file://...) delegate - ImageMagick
11. **ssrf11_mvg_image_https.png** - MVG with image over https - ImageMagick
12. **ssrf12_mvg_image_http.png** - MVG with image over http - ImageMagick
13. **ssrf13_svg_embedded.png** - SVG with embedded image and xlink - ImageMagick
14. **ssrf14_mvg_msl.png** - MVG with msl: delegate - ImageMagick
15. **ssrf15_mvg_epi.png** - MVG with epi: delegate (PostScript) - ImageMagick
16. **ssrf16_mvg_ps.png** - MVG with ps: delegate - ImageMagick
17. **ssrf17_mvg_text.png** - MVG with text: delegate - ImageMagick
18. **ssrf18_svg_multi.png** - SVG with multiple protocols - ImageMagick
19. **ssrf19_mvg_rar.png** - MVG with rar: delegate - ImageMagick
20. **ssrf20_mvg_zip.png** - MVG with zip: delegate - ImageMagick

### RCE (Remote Code Execution) - 20 payloads
1. **rce1_imagemagick.png** - MVG with url() and curl command - ImageMagick (CVE-2016-3714, ImageTragick)
2. **rce2_imagemagick_delegate.png** - SVG with xlink:href and backticks - ImageMagick
3. **rce3_mvg_delegate.png** - MVG with image over and $() - ImageMagick
4. **rce4_mvg_label.png** - MVG with label: delegate - ImageMagick
5. **rce5_svg_delegate.png** - SVG clean without backticks - ImageMagick
6. **rce6_mvg_https_cmd.png** - MVG with https: and wget - ImageMagick
7. **rce7_mvg_http_cmd.png** - MVG with http: and curl - ImageMagick
8. **rce8_mvg_ftp.png** - MVG with ftp: delegate - ImageMagick
9. **rce9_mvg_msl.png** - MVG with msl: delegate (Magick Scripting Language) - ImageMagick
10. **rce10_mvg_text.png** - MVG with text: delegate - ImageMagick
11. **rce11_mvg_epi.png** - MVG with epi: delegate (PostScript) - ImageMagick
12. **rce12_mvg_ps.png** - MVG with ps: delegate - ImageMagick
13. **rce13_svg_multi.png** - SVG with multiple xlink:href - ImageMagick
14. **rce14_mvg_file.png** - MVG with file: delegate (local file read) - ImageMagick
15. **rce15_mvg_rar.png** - MVG with rar: delegate - ImageMagick
16. **rce16_mvg_zip.png** - MVG with zip: delegate - ImageMagick
17. **rce17_mvg_backtick.png** - MVG with backticks `id` - ImageMagick
18. **rce18_mvg_dollar.png** - MVG with $() command substitution - ImageMagick
19. **rce19_svg_script.png** - SVG with embedded script - ImageMagick
20. **rce20_mvg_exec.png** - MVG with exec: delegate - ImageMagick

### XXE (XML External Entity) - 10 payloads
**⚠ IMPORTANT**: XXE via XMP does NOT work with ImageMagick alone. ImageMagick reads XMP metadata but does NOT parse it as XML with a vulnerable XML parser. For XXE to work, you need tools like **exiftool**, **libexif**, or other XMP parsers that actually parse XML. These payloads are included for completeness and will work with exiftool or other XMP parsers, but NOT with ImageMagick.

1. **xxe1_itxt.png** - XMP iTXt chunk with basic DOCTYPE - exiftool, libexif (NOT ImageMagick)
2. **xxe2_xmp_entity.png** - XMP with proper entity declaration - exiftool, libexif (NOT ImageMagick)
3. **xxe3_xmp_file.png** - XMP with file:// protocol - exiftool, libexif (NOT ImageMagick)
4. **xxe4_xmp_param.png** - XMP with parameter entity - exiftool, libexif (NOT ImageMagick)
5. **xxe5_xmp_nested.png** - XMP with nested entities - exiftool, libexif (NOT ImageMagick)
6. **xxe6_svg_itxt.png** - SVG with DOCTYPE in iTXt chunk - ImageMagick (if SVG is parsed)
7. **xxe7_xmp_data.png** - XMP with data:// protocol - exiftool, libexif (NOT ImageMagick)
8. **xxe8_xmp_expect.png** - XMP with expect:// protocol - exiftool, libexif (NOT ImageMagick)
9. **xxe9_xmp_gopher.png** - XMP with gopher:// protocol - exiftool, libexif (NOT ImageMagick)
10. **xxe10_xmp_phpfilter.png** - XMP with php://filter - exiftool, libexif (NOT ImageMagick)

### XSS (Cross-Site Scripting)
- **xss1_itxt.svg.png** - iTXt chunk with <svg onload=alert(1)> → ImageMagick or HTML preview - Some old parsers

## JPEG
- **COM segment (0xFFFE) with DOCTYPE + URL** - COM marker - ImageMagick, exiftool
- **XSS COM segment with <script>alert(1)</script> → ImageMagick -label** - COM marker - Very rare (only old ImageMagick + HTML output)

## GIF
- **Repeated comment blocks with DOCTYPE + URL** - GIF comment extension - ImageMagick
- **XSS Comment block with <script>alert(1)</script> → ImageMagick -label or preview** - GIF comment extension - Very rare (only old ImageMagick + HTML output)

