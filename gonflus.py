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
from generators.webshell_generator import generate_webshell_payloads
from generators.ai_generator import generate_ai_payloads

def normalize_payload_types(payload_types):
    """
    Normalise les types de payloads :
    - oob -> xxe, ssrf, rce, deserialization, ntlm
    - all -> tous les types
    """
    valid_types = {'xxe', 'ssrf', 'rce', 'oob', 'xss', 'ssti', 'deserialization', 'lfi', 'path_traversal', 'info', 'info_leak', 'dos', 'ntlm', 'all'}
    
    payload_list = [p.strip().lower() for p in payload_types.split(',')]
    normalized = set()
    
    for payload_type in payload_list:
        if payload_type not in valid_types:
            raise ValueError(f"Type de payload invalide: {payload_type}. Types valides: {', '.join(sorted(valid_types))}")
        
        if payload_type == 'all':
            return {'all'}
        elif payload_type == 'oob':
            normalized.update(['xxe', 'ssrf', 'rce', 'deserialization', 'ntlm'])
        else:
            normalized.add(payload_type)
    
    return normalized

def requires_burp(payload_types):
    """Vérifie si les types de payloads nécessitent --burp-oob"""
    oob_types = {'oob', 'xxe', 'ssrf', 'rce', 'deserialization', 'ntlm'}
    return bool(payload_types & oob_types) or 'all' in payload_types

def main():
    parser = argparse.ArgumentParser(description='Generate all possible file upload payloads for security testing')
    parser.add_argument('--burp-oob', dest='burp_collab', help='Burp Collaborator URL (ex: abc123.burpcollaborator.net)')
    parser.add_argument('-e', '--extension', help='Extension to generate (pdf, svg, docx, xlsx, png, jpg, gif, webm, mp4, md, all). Default: all', default='all')
    parser.add_argument('--tech', help='Backend technology filter (all, java, php, python, ruby, dotnet, nodejs). Default: all', default='all', choices=['all', 'java', 'php', 'python', 'ruby', 'dotnet', 'nodejs'])
    parser.add_argument('--payloads', help='Types de payloads à générer (xxe, ssrf, rce, oob, xss, ssti, deserialization, lfi, path_traversal, info, info_leak, dos, ntlm, all). Séparer par virgules. oob inclut xxe,ssrf,rce,deserialization,ntlm. Default: all', default='all')
    parser.add_argument('-d', '--delete', action='store_true', help='Delete all generated directories before generating new payloads')
    parser.add_argument('--polyglot', action='store_true', help='Generate polyglot payloads (other formats with target extension)')
    parser.add_argument('--webshell', action='store_true', help='Generate webshell payloads for all backends in <extension>/webshell/<backend>/ structure')
    parser.add_argument('--prompt-ai', dest='prompt_ai', help='Prompt AI à intégrer dans des fichiers dédiés dans <extension>/ai/')
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
        if not args.burp_collab and not args.prompt_ai:
            return
    
    has_burp = bool(args.burp_collab)
    has_ai = bool(args.prompt_ai)
    
    try:
        payload_types = normalize_payload_types(args.payloads)
    except ValueError as e:
        parser.error(str(e))
    
    if requires_burp(payload_types) and not has_burp:
        parser.error(f"--burp-oob is required for payload types: {', '.join(sorted(payload_types & {'oob', 'xxe', 'ssrf', 'rce', 'deserialization', 'ntlm', 'all'}))}")
    
    if not has_burp and not has_ai and not args.delete:
        if not requires_burp(payload_types):
            pass
        else:
            parser.error(f"--burp-oob is required for payload types: {', '.join(sorted(payload_types & {'oob', 'xxe', 'ssrf', 'rce', 'deserialization', 'ntlm', 'all'}))}")
    
    burp_collab = args.burp_collab
    ext_filter = args.extension.lower()
    tech_filter = args.tech.lower()
    
    if has_burp:
        print(f"[+] Generating payloads targeting: {burp_collab}")
        if tech_filter != 'all':
            print(f"[+] Backend filter: {tech_filter.upper()} (will include 'all' payloads)")
        if payload_types == {'all'}:
            print(f"[+] Payload types: all")
        else:
            print(f"[+] Payload types: {', '.join(sorted(payload_types))}")
    elif has_ai:
        print("[+] Generating AI payloads only (no Burp OOB target)")
    else:
        if payload_types == {'all'}:
            print(f"[+] Generating payloads (no Burp OOB target)")
        else:
            print(f"[+] Generating payloads: {', '.join(sorted(payload_types))} (no Burp OOB target)")
    
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
            if has_burp:
                print(f"[+] Generating all extensions")
            elif has_ai:
                print(f"[+] Generating AI for all extensions")
            else:
                print(f"[+] Generating all extensions (no Burp OOB)")
        else:
            ext_list = [e.strip() for e in ext_filter.split(',')]
            extensions_to_generate = []
            invalid_extensions = []
            
            for ext in ext_list:
                if ext in generators:
                    extensions_to_generate.append(ext)
                else:
                    invalid_extensions.append(ext)
            
            if invalid_extensions:
                print(f"[!] Error: Extension(s) '{', '.join(invalid_extensions)}' not supported")
                print(f"[!] Supported extensions: {', '.join(generators.keys())}, all")
                sys.exit(1)
            
            if len(extensions_to_generate) == 1:
                print(f"[+] Filter: {extensions_to_generate[0].upper()} only")
            else:
                print(f"[+] Filter: {', '.join([e.upper() for e in extensions_to_generate])}")
        
        print("[+] Creating directory structure...\n")
        
        for ext in extensions_to_generate:
            generator_func, ext_param = generators[ext]
            ext_dir = base_dir / ext
            ext_dir.mkdir(exist_ok=True)

            if has_burp or (not has_ai and not requires_burp(payload_types)):
                if has_burp:
                    print(f"[+] Generating {ext.upper()} payloads...")
                else:
                    print(f"[+] Generating {ext.upper()} payloads (no Burp OOB)...")
                burp_param = burp_collab if has_burp else 'localhost'
                if ext_param:
                    if ext in ['png', 'jpg', 'jpeg', 'gif']:
                        generator_func(ext_dir, ext_param, burp_param, tech_filter=tech_filter, payload_types=payload_types)
                    elif ext in ['zip', 'jar', 'epub', 'txt', 'csv', 'rtf', 'odt', 'ods', 'odp']:
                        generator_func(ext_dir, ext_param, burp_param, tech_filter=tech_filter, payload_types=payload_types)
                    elif ext in ['svg', 'xml', 'html', 'pdf', 'docx', 'xlsx', 'pptx', 'md', 'markdown', 'webm', 'mp4']:
                        generator_func(ext_dir, burp_param, tech_filter=tech_filter, payload_types=payload_types)
                    else:
                        generator_func(ext_dir, ext_param, burp_param, tech_filter=tech_filter, payload_types=payload_types)
                else:
                    if ext in ['png', 'jpg', 'jpeg', 'gif']:
                        generator_func(ext_dir, burp_param, tech_filter=tech_filter, payload_types=payload_types)
                    elif ext in ['svg', 'xml', 'html', 'pdf', 'docx', 'xlsx', 'pptx', 'md', 'markdown', 'webm', 'mp4']:
                        generator_func(ext_dir, burp_param, tech_filter=tech_filter, payload_types=payload_types)
                    else:
                        generator_func(ext_dir, burp_param, tech_filter=tech_filter, payload_types=payload_types)
                
                if args.polyglot:
                    print(f"[+] Generating polyglot {ext.upper()} payloads...")
                    generate_extended_payloads(ext_dir, ext, burp_collab)
                    print(f"[✓] Polyglot {ext.upper()} completed")
                
                if args.webshell:
                    print(f"[+] Generating webshell {ext.upper()} payloads...")
                    generate_webshell_payloads(ext_dir, ext, burp_collab)
                    print(f"[✓] Webshell {ext.upper()} completed")

            if has_ai:
                print(f"[+] Generating AI {ext.upper()} payloads...")
                generate_ai_payloads(ext_dir, ext, args.prompt_ai)
                print(f"[✓] AI {ext.upper()} completed")
            
            if has_burp or (not has_ai and not requires_burp(payload_types)):
                print(f"[✓] {ext.upper()} completed\n")
            elif has_ai:
                print(f"[✓] AI {ext.upper()} completed only\n")
        
        if has_burp or (not has_ai and not requires_burp(payload_types)):
            print("[+] All payloads generated successfully!")
            print(f"[+] Files created in: {base_dir}")
            if args.polyglot:
                print(f"[+] Structure: <extension>/<vulnerability>/<payload_file>")
                print(f"[+] Polyglot structure: <extension>/polyglot/<source_format>/<vulnerability>/<payload_file>")
            if args.webshell:
                print(f"[+] Webshell structure: <extension>/webshell/<backend>/webshell{1,2,3}_<type>.<ext>")
            if not args.polyglot and not args.webshell:
                print(f"[+] Structure: <extension>/<vulnerability>/<payload_file>")
        elif has_ai:
            print("[+] All AI payloads generated successfully!")
            print(f"[+] Files created in: {base_dir}")
    except Exception as error:
        print(f"[!] Error during generation: {error}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
