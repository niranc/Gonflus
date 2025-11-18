#!/usr/bin/env python3
import sys
import argparse
from pathlib import Path

from generators.pdf_generator import generate_pdf_payloads
from generators.xlsx_generator import generate_xlsx_payloads
from generators.docx_generator import generate_docx_payloads
from generators.pptx_generator import generate_pptx_payloads
from generators.svg_generator import generate_svg_payloads
from generators.xml_generator import generate_xml_payloads
from generators.html_generator import generate_html_payloads
from generators.image_generator import generate_image_payloads
from generators.archive_generator import generate_archive_payloads
from generators.text_generator import generate_text_payloads
from generators.office_generator import generate_office_payloads
from generators.webm_generator import generate_webm_payloads
from generators.mp4_generator import generate_mp4_payloads
from generators.markdown_generator import generate_markdown_payloads
from generators.extended_generator import generate_extended_payloads

def main():
    parser = argparse.ArgumentParser(description='Generate all possible file upload payloads for security testing')
    parser.add_argument('burp_collab', nargs='?', help='Burp Collaborator URL (ex: abc123.burpcollaborator.net)')
    parser.add_argument('-e', '--extension', help='Extension to generate (pdf, svg, docx, xlsx, png, jpg, gif, webm, mp4, md, all). Default: all', default='all')
    parser.add_argument('-d', '--delete', action='store_true', help='Delete all generated directories before generating new payloads')
    parser.add_argument('--extended', action='store_true', help='Generate extended payloads (other formats with target extension)')
    args = parser.parse_args()

    base_dir = Path.cwd()
    
    if args.delete:
        print("[+] Deleting existing directories...")
        extensions_to_delete = ['pdf', 'xlsx', 'docx', 'pptx', 'svg', 'xml', 'html', 'gif', 'jpg', 'jpeg', 'png', 'zip', 'jar', 'txt', 'csv', 'rtf', 'odt', 'ods', 'odp', 'epub', 'webm', 'mp4', 'md', 'markdown']
        for ext in extensions_to_delete:
            ext_dir = base_dir / ext
            if ext_dir.exists():
                import shutil
                shutil.rmtree(ext_dir)
                print(f"[✓] Deleted {ext}/")
        print("[+] Cleanup completed\n")
        if not args.burp_collab:
            return
    
    if not args.burp_collab:
        parser.error("burp_collab is required unless using -d option")
    
    burp_collab = args.burp_collab
    ext_filter = args.extension.lower()
    
    print(f"[+] Generating payloads targeting: {burp_collab}")
    if ext_filter != 'all':
        print(f"[+] Filter: {ext_filter.upper()} only")
    print("[+] Creating directory structure...\n")
    
    generators = {
        'pdf': (generate_pdf_payloads, None),
        'xlsx': (generate_xlsx_payloads, None),
        'docx': (generate_docx_payloads, None),
        'pptx': (generate_pptx_payloads, None),
        'svg': (generate_svg_payloads, None),
        'xml': (generate_xml_payloads, None),
        'html': (generate_html_payloads, None),
        'gif': (generate_image_payloads, 'gif'),
        'jpg': (generate_image_payloads, 'jpg'),
        'jpeg': (generate_image_payloads, 'jpg'),
        'png': (generate_image_payloads, 'png'),
        'zip': (generate_archive_payloads, 'zip'),
        'jar': (generate_archive_payloads, 'jar'),
        'txt': (generate_text_payloads, 'txt'),
        'csv': (generate_text_payloads, 'csv'),
        'rtf': (generate_text_payloads, 'rtf'),
        'odt': (generate_office_payloads, 'odt'),
        'ods': (generate_office_payloads, 'ods'),
        'odp': (generate_office_payloads, 'odp'),
        'epub': (generate_archive_payloads, 'epub'),
        'webm': (generate_webm_payloads, None),
        'mp4': (generate_mp4_payloads, None),
        'md': (generate_markdown_payloads, None),
        'markdown': (generate_markdown_payloads, None),
    }

    try:
        if ext_filter == 'all':
            extensions_to_generate = list(generators.keys())
        else:
            if ext_filter not in generators:
                print(f"[!] Error: Extension '{ext_filter}' not supported")
                print(f"[!] Supported extensions: {', '.join(generators.keys())}, all")
                sys.exit(1)
            extensions_to_generate = [ext_filter]
        
        for ext in extensions_to_generate:
            generator_func, ext_param = generators[ext]
            print(f"[+] Generating {ext.upper()} payloads...")
            ext_dir = base_dir / ext
            ext_dir.mkdir(exist_ok=True)
            
            if ext_param:
                generator_func(ext_dir, ext_param, burp_collab)
            else:
                generator_func(ext_dir, burp_collab)
            
            if args.extended:
                print(f"[+] Generating extended {ext.upper()} payloads...")
                generate_extended_payloads(ext_dir, ext, burp_collab)
                print(f"[✓] Extended {ext.upper()} completed")
            
            print(f"[✓] {ext.upper()} completed\n")

        print("[+] All payloads generated successfully!")
        print(f"[+] Files created in: {base_dir}")
        if args.extended:
            print(f"[+] Structure: <extension>/<vulnerability>/<payload_file>")
            print(f"[+] Extended structure: <extension>/extended/<source_format>/<vulnerability>/<payload_file>")
        else:
            print(f"[+] Structure: <extension>/<vulnerability>/<payload_file>")
    except Exception as error:
        print(f"[!] Error during generation: {error}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
