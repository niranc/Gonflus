from pathlib import Path


def _write_text_file(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _generate_ai_for_html_like(ai_dir, ext, prompt):
    base_name = "ai"
    head_meta_description = (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        f'  <meta name="description" content="{prompt}">\n'
        "</head>\n"
        "<body>\n"
        "  <p>AI payload description metadata</p>\n"
        "</body>\n"
        "</html>\n"
    )
    _write_text_file(ai_dir / f"{base_name}_description.{ext}", head_meta_description)

    head_meta_author = (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        f'  <meta name="author" content="{prompt}">\n'
        "</head>\n"
        "<body>\n"
        "  <p>AI payload author metadata</p>\n"
        "</body>\n"
        "</html>\n"
    )
    _write_text_file(ai_dir / f"{base_name}_author.{ext}", head_meta_author)

    head_meta_other = (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        f'  <meta name="ai-prompt" content="{prompt}">\n'
        "</head>\n"
        "<body>\n"
        "  <p>AI payload other metadata</p>\n"
        "</body>\n"
        "</html>\n"
    )
    _write_text_file(ai_dir / f"{base_name}_metadata.{ext}", head_meta_other)

    body_content = (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        "  <title>AI body payload</title>\n"
        "</head>\n"
        "<body>\n"
        f"  <p>{prompt}</p>\n"
        "</body>\n"
        "</html>\n"
    )
    _write_text_file(ai_dir / f"{base_name}_body.{ext}", body_content)

    comment_content = (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        "  <title>AI comment payload</title>\n"
        "</head>\n"
        "<body>\n"
        f"  <!-- {prompt} -->\n"
        "  <p>Comment-based AI payload</p>\n"
        "</body>\n"
        "</html>\n"
    )
    _write_text_file(ai_dir / f"{base_name}_comment.{ext}", comment_content)


def _generate_ai_for_xml_like(ai_dir, ext, prompt):
    base_name = "ai"
    description_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f"<root description=\"{prompt}\">\n"
        "  <data>AI payload description metadata</data>\n"
        "</root>\n"
    )
    _write_text_file(ai_dir / f"{base_name}_description.{ext}", description_xml)

    author_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f"<root author=\"{prompt}\">\n"
        "  <data>AI payload author metadata</data>\n"
        "</root>\n"
    )
    _write_text_file(ai_dir / f"{base_name}_author.{ext}", author_xml)

    other_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<root>\n"
        f"  <metadata key=\"ai-prompt\">{prompt}</metadata>\n"
        "</root>\n"
    )
    _write_text_file(ai_dir / f"{base_name}_metadata.{ext}", other_xml)

    body_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<root>\n"
        f"  <body>{prompt}</body>\n"
        "</root>\n"
    )
    _write_text_file(ai_dir / f"{base_name}_body.{ext}", body_xml)

    comment_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<root>\n"
        f"  <!-- {prompt} -->\n"
        "  <body>Comment-based AI payload</body>\n"
        "</root>\n"
    )
    _write_text_file(ai_dir / f"{base_name}_comment.{ext}", comment_xml)


def _generate_ai_for_markdown(ai_dir, ext, prompt):
    base_name = "ai"
    description_md = f"---\ndescription: \"{prompt}\"\n---\n\nAI payload description metadata\n"
    _write_text_file(ai_dir / f"{base_name}_description.{ext}", description_md)

    author_md = f"---\nauthor: \"{prompt}\"\n---\n\nAI payload author metadata\n"
    _write_text_file(ai_dir / f"{base_name}_author.{ext}", author_md)

    other_md = f"---\nai_prompt: \"{prompt}\"\n---\n\nAI payload other metadata\n"
    _write_text_file(ai_dir / f"{base_name}_metadata.{ext}", other_md)

    body_md = f"{prompt}\n"
    _write_text_file(ai_dir / f"{base_name}_body.{ext}", body_md)

    comment_md = f"[//]: # ({prompt})\nComment-based AI payload\n"
    _write_text_file(ai_dir / f"{base_name}_comment.{ext}", comment_md)


def _generate_ai_for_text(ai_dir, ext, prompt):
    base_name = "ai"
    description_text = f"Title: AI payload\nDescription: {prompt}\n"
    _write_text_file(ai_dir / f"{base_name}_description.{ext}", description_text)

    author_text = f"Title: AI payload\nAuthor: {prompt}\n"
    _write_text_file(ai_dir / f"{base_name}_author.{ext}", author_text)

    other_text = f"Title: AI payload\nMetadata: ai_prompt={prompt}\n"
    _write_text_file(ai_dir / f"{base_name}_metadata.{ext}", other_text)

    body_text = f"{prompt}\n"
    _write_text_file(ai_dir / f"{base_name}_body.{ext}", body_text)

    if ext == "csv":
        comment_prefix = "#"
    else:
        comment_prefix = "#"
    comment_text = f"{comment_prefix} {prompt}\nComment-based AI payload\n"
    _write_text_file(ai_dir / f"{base_name}_comment.{ext}", comment_text)


def _generate_ai_for_pdf(ai_dir, ext, prompt):
    base_name = "ai"
    pdf_description = f"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 44 >>
stream
BT /F1 12 Tf 72 700 Td ({prompt}) Tj ET
endstream
endobj
5 0 obj
<< /Title ({prompt}) /Author ({prompt}) /Subject ({prompt}) >>
endobj
xref
0 6
0000000000 65535 f 
0000000010 00000 n 
0000000060 00000 n 
0000000114 00000 n 
0000000192 00000 n 
0000000293 00000 n 
trailer
<< /Size 6 /Root 1 0 R /Info 5 0 R >>
startxref
380
%%EOF
"""
    _write_text_file(ai_dir / f"{base_name}_description.{ext}", pdf_description)

    pdf_body = f"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 44 >>
stream
BT /F1 12 Tf 72 700 Td ({prompt}) Tj ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000010 00000 n 
0000000060 00000 n 
0000000114 00000 n 
0000000192 00000 n 
trailer
<< /Size 5 /Root 1 0 R >>
startxref
260
%%EOF
"""
    _write_text_file(ai_dir / f"{base_name}_body.{ext}", pdf_body)

    pdf_comment = f"""%PDF-1.4
% {prompt}
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 44 >>
stream
BT /F1 12 Tf 72 700 Td (Comment-based AI payload) Tj ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000010 00000 n 
0000000060 00000 n 
0000000114 00000 n 
0000000210 00000 n 
trailer
<< /Size 5 /Root 1 0 R >>
startxref
310
%%EOF
"""
    _write_text_file(ai_dir / f"{base_name}_comment.{ext}", pdf_comment)


def _generate_ai_for_generic(ai_dir, ext, prompt):
    base_name = "ai"
    description = f"AI file for .{ext}\nDescription: {prompt}\n"
    _write_text_file(ai_dir / f"{base_name}_description.{ext}", description)

    author = f"AI file for .{ext}\nAuthor: {prompt}\n"
    _write_text_file(ai_dir / f"{base_name}_author.{ext}", author)

    metadata = f"AI file for .{ext}\nMetadata: ai_prompt={prompt}\n"
    _write_text_file(ai_dir / f"{base_name}_metadata.{ext}", metadata)

    body = f"{prompt}\n"
    _write_text_file(ai_dir / f"{base_name}_body.{ext}", body)

    comment = f"# {prompt}\nComment-based AI payload for .{ext}\n"
    _write_text_file(ai_dir / f"{base_name}_comment.{ext}", comment)


def generate_ai_payloads(output_dir, ext, prompt):
    output_dir = Path(output_dir)
    ai_dir = output_dir / "ai"
    ai_dir.mkdir(parents=True, exist_ok=True)

    normalized_ext = ext.lower()

    if normalized_ext in {"html"}:
        _generate_ai_for_html_like(ai_dir, normalized_ext, prompt)
    elif normalized_ext in {"svg", "xml"}:
        _generate_ai_for_xml_like(ai_dir, normalized_ext, prompt)
    elif normalized_ext in {"md", "markdown"}:
        _generate_ai_for_markdown(ai_dir, normalized_ext, prompt)
    elif normalized_ext in {"txt", "csv", "rtf"}:
        _generate_ai_for_text(ai_dir, normalized_ext, prompt)
    elif normalized_ext == "pdf":
        _generate_ai_for_pdf(ai_dir, normalized_ext, prompt)
    else:
        _generate_ai_for_generic(ai_dir, normalized_ext, prompt)


