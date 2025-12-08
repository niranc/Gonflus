# Tools pour génération de payloads

Ce répertoire contient les outils nécessaires pour générer des payloads RCE fonctionnels pour différents backends.

## Installation automatique

```bash
cd tools
./install_tools.sh
```

## Installation manuelle

### ysoserial (Java deserialization)

```bash
cd tools
git clone https://github.com/frohoff/ysoserial.git
cd ysoserial
mvn clean package -DskipTests
```

Le JAR sera dans `target/ysoserial-*.jar`

### PHPGGC (PHP deserialization)

```bash
cd tools
git clone https://github.com/ambionics/phpggc.git
cd phpggc
composer install
chmod +x phpggc
```

### ysoserial.net (.NET deserialization)

```bash
cd tools
git clone https://github.com/pwntester/ysoserial.net.git
cd ysoserial.net
dotnet build -c Release
```

L'exécutable sera dans `bin/Release/net*/ysoserial.exe`

**Note:** Pour exécuter ysoserial.net, vous avez besoin de Mono:
```bash
sudo apt-get install mono-complete
```

## Langages supportés

### Java
- **ysoserial** : Désérialisation Java avec gadget chains
- Gadgets : CommonsCollections1-7, Groovy1, Spring1, etc.

### PHP
- **PHPGGC** : Désérialisation PHP avec gadget chains
- Gadgets : Monolog/RCE1, Guzzle/RCE1, Laravel/RCE1, etc.

### .NET / C#
- **ysoserial.net** : Désérialisation .NET
- Formatters : BinaryFormatter, ObjectDataProvider, TypeConfuseDelegate, etc.

### Python
- **pickle** : Module natif Python (génération automatique)
- **PyYAML** : Désérialisation YAML (génération automatique)

### Ruby
- **Marshal** : Format natif Ruby (génération automatique)
- **YAML** : Désérialisation YAML (génération automatique)

### Node.js / JavaScript
- **node-serialize** : Sérialisation JavaScript vulnérable (génération automatique)

### Template Injection (SSTI)
- **Jinja2** (Python)
- **FreeMarker** (Java)
- **Velocity** (Java)
- **Twig** (PHP)
- **Smarty** (PHP)
- **ERB** (Ruby)
- **Handlebars** (Node.js)
- **EJS** (Node.js)

## Utilisation

Les outils sont automatiquement utilisés par `image_generator.py` pour générer des payloads fonctionnels.

Si un outil n'est pas disponible, le générateur utilisera un payload placeholder.

