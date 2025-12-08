#!/bin/bash
# Script d'installation des outils ysoserial et PHPGGC

set -e

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$TOOLS_DIR"

echo "=== Installation des outils pour génération de payloads ==="
echo ""

# Installation de ysoserial
echo "1. Installation de ysoserial..."
if [ ! -d "ysoserial" ]; then
    git clone https://github.com/frohoff/ysoserial.git
    cd ysoserial
    mvn clean package -DskipTests
    cd ..
    echo "✓ ysoserial installé"
else
    echo "✓ ysoserial déjà présent"
fi

# Installation de PHPGGC
echo ""
echo "2. Installation de PHPGGC..."
if [ ! -d "phpggc" ]; then
    git clone https://github.com/ambionics/phpggc.git
    cd phpggc
    if command -v composer &> /dev/null; then
        composer install
    else
        echo "⚠ Composer non trouvé, installation manuelle nécessaire"
    fi
    chmod +x phpggc
    cd ..
    echo "✓ PHPGGC installé"
else
    echo "✓ PHPGGC déjà présent"
fi

# Installation de ysoserial.net
echo ""
echo "3. Installation de ysoserial.net (.NET)..."
if [ ! -d "ysoserial.net" ]; then
    git clone https://github.com/pwntester/ysoserial.net.git
    cd ysoserial.net
    if command -v dotnet &> /dev/null; then
        dotnet build -c Release
        echo "✓ ysoserial.net compilé"
    else
        echo "⚠ .NET SDK non trouvé, compilation manuelle nécessaire"
    fi
    cd ..
    echo "✓ ysoserial.net installé"
else
    echo "✓ ysoserial.net déjà présent"
fi

echo ""
echo "=== Installation terminée ==="
echo ""
echo "Vérification des outils:"
echo ""

# Vérifier Java
if command -v java &> /dev/null; then
    echo "✓ Java: $(java -version 2>&1 | head -n 1)"
else
    echo "✗ Java non trouvé (requis pour ysoserial)"
fi

# Vérifier Maven
if command -v mvn &> /dev/null; then
    echo "✓ Maven: $(mvn -version | head -n 1)"
else
    echo "✗ Maven non trouvé (requis pour compiler ysoserial)"
fi

# Vérifier PHP
if command -v php &> /dev/null; then
    echo "✓ PHP: $(php -v | head -n 1)"
else
    echo "✗ PHP non trouvé (requis pour PHPGGC)"
fi

# Vérifier Composer
if command -v composer &> /dev/null; then
    echo "✓ Composer: $(composer --version)"
else
    echo "⚠ Composer non trouvé (requis pour installer les dépendances PHPGGC)"
fi

# Vérifier .NET
if command -v dotnet &> /dev/null; then
    echo "✓ .NET: $(dotnet --version)"
else
    echo "⚠ .NET SDK non trouvé (requis pour compiler ysoserial.net)"
fi

# Vérifier Mono (pour exécuter ysoserial.net)
if command -v mono &> /dev/null; then
    echo "✓ Mono: $(mono --version | head -n 1)"
else
    echo "⚠ Mono non trouvé (requis pour exécuter ysoserial.net)"
fi

# Vérifier Ruby
if command -v ruby &> /dev/null; then
    echo "✓ Ruby: $(ruby -v)"
else
    echo "⚠ Ruby non trouvé (requis pour générer des payloads Ruby)"
fi

# Vérifier Node.js
if command -v node &> /dev/null; then
    echo "✓ Node.js: $(node -v)"
else
    echo "⚠ Node.js non trouvé (requis pour générer des payloads Node.js)"
fi

echo ""
echo "Pour utiliser les outils, exécutez:"
echo "  python3 ../generators/image_generator.py"

