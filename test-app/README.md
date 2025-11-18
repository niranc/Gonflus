# File Upload Test Application

Application web pour tester les vulnérabilités de visualisation de documents dans différents environnements (PHP, ASP, Java).

## Installation

**Note**: Nécessite Node.js 14+ (Node.js 18+ recommandé)

```bash
cd test-app
npm install
```

## Utilisation

```bash
npm start
```

Ou avec auto-reload (nécessite nodemon):

```bash
npm run dev
```

L'application sera disponible sur `http://localhost:3000`

## Fonctionnalités

L'application propose trois environnements volontairement vulnérables pour tester les vulnérabilités de visualisation de documents:

### Environnements disponibles

1. **Environnement PHP** (`/php`)
   - Simule un serveur PHP avec visualisation de documents
   - Vulnérabilités: SSRF, RCE, XXE, XSS, Path Traversal

2. **Environnement ASP/.NET** (`/asp`)
   - Simule un serveur ASP/.NET avec visualisation de documents
   - Vulnérabilités: SSRF, RCE, XXE, XSS, Deserialization

3. **Environnement Java** (`/java`)
   - Simule un serveur Java avec visualisation de documents
   - Vulnérabilités: SSRF, RCE, XXE, XSS, Deserialization

### Fonctionnalités par environnement

- **Upload de fichiers**: Glisser-déposer ou parcourir pour uploader des fichiers
- **Visualisation de documents**: Visualiser les fichiers uploadés directement dans le navigateur
- **Téléchargement**: Télécharger les fichiers uploadés
- **Gestion des fichiers**: Supprimer les fichiers uploadés
- **Support multi-formats**: 
  - Images (JPG, PNG, GIF, SVG) - affichées en ligne
  - PDFs - affichés dans le navigateur
  - Fichiers HTML - rendus comme HTML (XSS possible)
  - Fichiers XML - affichés comme XML (XXE possible)
  - Documents Office (DOCX, XLSX, PPTX, ODT, ODS, ODP) - téléchargeables
  - Fichiers texte (TXT, CSV, RTF, MD) - affichés comme texte (RCE/SSRF possible)

## Tests de sécurité

Cette application est conçue pour tester les vulnérabilités de visualisation de documents:

### SSRF (Server-Side Request Forgery)
- Les fichiers XML avec entités externes déclenchent des requêtes HTTP
- Les fichiers texte avec URLs déclenchent des requêtes HTTP
- Les fichiers SVG avec liens externes déclenchent des requêtes HTTP

### XXE (XML External Entity)
- Les fichiers XML avec `<!ENTITY` ou `<!DOCTYPE` sont parsés sans protection
- Les entités externes (http://, https://, file://) sont résolues
- Les fichiers Office (DOCX, XLSX, PPTX) peuvent contenir des XXE

### RCE (Remote Code Execution)
- Les fichiers texte avec commandes shell (|, ;, `, $()) sont exécutés
- Injection de commandes via contenu de fichier
- Pas de validation des commandes exécutées

### XSS (Cross-Site Scripting)
- Les fichiers HTML sont rendus sans sanitization
- Les fichiers SVG sont rendus sans sanitization
- Les fichiers Markdown sont rendus comme HTML

### Path Traversal
- Les noms de fichiers ne sont pas validés
- Pas de protection contre les chemins relatifs

## Structure des dossiers

```
uploads/
├── php/     # Fichiers uploadés pour l'environnement PHP
├── asp/     # Fichiers uploadés pour l'environnement ASP
└── java/    # Fichiers uploadés pour l'environnement Java
```

## Vulnérabilités intentionnelles

Cette application est **volontairement vulnérable** pour les tests de sécurité:

- ❌ **Pas de protection CSRF** - Tous les endpoints sont non protégés
- ❌ **Pas de validation de type de fichier** - Accepte tous les types de fichiers
- ❌ **Pas de limite de taille** - Les gros fichiers sont acceptés
- ❌ **Pas de sanitization** - Les fichiers HTML/XML sont rendus tels quels (XSS/XXE possible)
- ❌ **Pas de protection path traversal** - Les noms de fichiers ne sont pas sanitizés
- ❌ **Pas d'authentification** - Accès public à toutes les fonctionnalités
- ❌ **Parsing XML vulnérable** - XXE activé par défaut
- ❌ **Exécution de commandes** - RCE possible via contenu de fichier
- ❌ **Requêtes HTTP non validées** - SSRF possible via URLs dans les fichiers

## Notes

⚠️ **Avertissement**: Cette application est volontairement vulnérable pour les tests de sécurité. Ne pas utiliser en environnement de production. Utiliser uniquement dans des environnements de test isolés.

## Exemples de tests

### Test SSRF
1. Uploader un fichier XML avec une entité externe pointant vers votre serveur
2. Observer les requêtes HTTP reçues

### Test XXE
1. Uploader un fichier XML avec `<!DOCTYPE` et `<!ENTITY` pointant vers `file:///etc/passwd`
2. Observer le contenu du fichier dans la réponse

### Test RCE
1. Uploader un fichier TXT contenant `|whoami` ou `;id`
2. Observer l'exécution de la commande

### Test XSS
1. Uploader un fichier HTML contenant `<script>alert(1)</script>`
2. Observer l'exécution du script dans le navigateur
