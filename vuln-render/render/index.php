<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

$message = '';
$uploadDir = __DIR__ . '/uploads';
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0777, true);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];
    $allOutput = [];
    
    if ($file['error'] === UPLOAD_ERR_OK) {
        $origName = basename($file['name']);
        $ext = strtolower(pathinfo($origName, PATHINFO_EXTENSION));
        $targetPath = $uploadDir . '/' . uniqid() . '_' . $origName;
        
        if (move_uploaded_file($file['tmp_name'], $targetPath)) {
            $allOutput[] = "=== UPLOAD SUCCESS ===";
            $allOutput[] = "File saved to: " . $targetPath;
            $allOutput[] = "File size: " . filesize($targetPath) . " bytes";
            $allOutput[] = "Extension: " . $ext;
            $allOutput[] = "";
            
            // Render based on file type
            $renderOutput = renderFile($targetPath, $ext, $uploadDir, $origName);
            $allOutput = array_merge($allOutput, $renderOutput);
            
            // For HTML files, also display the content (XSS)
            if ($ext === 'html' || $ext === 'htm') {
                $htmlContent = file_get_contents($targetPath);
                $message = "<pre>" . htmlspecialchars(implode("\n", $allOutput), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . "</pre>";
                $message .= "<hr><h2>HTML Content (XSS possible):</h2><div style='border: 1px solid #ccc; padding: 1rem; background: #f9f9f9;'>" . $htmlContent . "</div>";
            } else {
                $message = "<pre>" . htmlspecialchars(implode("\n", $allOutput), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . "</pre>";
            }
        } else {
            $message = "Upload failed";
        }
    } else {
        $message = "Upload error: " . $file['error'];
    }
}

function renderFile($filePath, $ext, $uploadDir, $origName) {
    $output = [];
    
    switch ($ext) {
        case 'pdf':
        case 'eps':
            return renderPDF($filePath, $uploadDir, $origName, $output);
        case 'docx':
        case 'doc':
            return renderDOCX($filePath, $uploadDir, $origName, $output);
        case 'xlsx':
        case 'xls':
            return renderXLSX($filePath, $uploadDir, $origName, $output);
        case 'pptx':
        case 'ppt':
            return renderPPTX($filePath, $uploadDir, $origName, $output);
        case 'odt':
        case 'ods':
        case 'odp':
            return renderODT($filePath, $uploadDir, $origName, $output);
        case 'svg':
            return renderSVG($filePath, $uploadDir, $origName, $output);
        case 'xml':
            return renderXML($filePath, $uploadDir, $origName, $output);
        case 'html':
        case 'htm':
            return renderHTML($filePath, $uploadDir, $origName, $output);
        case 'png':
        case 'jpg':
        case 'jpeg':
        case 'gif':
            return renderImage($filePath, $uploadDir, $origName, $output, $ext);
        case 'webm':
            return renderWebM($filePath, $uploadDir, $origName, $output);
        case 'zip':
        case 'jar':
        case 'epub':
            return renderArchive($filePath, $uploadDir, $origName, $output);
        case 'txt':
        case 'csv':
        case 'rtf':
        case 'md':
            return renderText($filePath, $uploadDir, $origName, $output);
        default:
            $output[] = "=== UNSUPPORTED FILE TYPE ===";
            $output[] = "Extension: " . $ext;
            $output[] = "Trying generic rendering...";
            return renderGeneric($filePath, $uploadDir, $origName, $output);
    }
}

function renderPDF($filePath, $uploadDir, $origName, $output) {
    $ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
    $fileType = strtoupper($ext);
    $output[] = "=== RENDERING {$fileType} ===";
    $output[] = "Multiple rendering techniques to trigger vulnerabilities:";
    $output[] = "";
    
    // Technique 1: Ghostscript WITHOUT -dSAFER (RCE via PostScript injection)
    // Cette technique est VULNÉRABLE et déclenchera la RCE si le payload contient %pipe%
    // Ghostscript 10.03.0 est vulnérable à CVE-2024-29510 (bypass -dSAFER via uniprint)
    $output[] = "--- Technique 1: Ghostscript WITHOUT -dSAFER (RCE via PostScript/EPS) ---";
    $gsOut = $uploadDir . '/gs_' . uniqid() . '.png';
    $cmd = 'gs -dNOPAUSE -dBATCH -sDEVICE=png16m -r150 -o ' . escapeshellarg($gsOut) . ' ' . escapeshellarg($filePath) . ' 2>&1';
    $output[] = "Command: " . $cmd;
    $output[] = "⚠ -dSAFER flag removed (VULNERABLE TO RCE!)";
    $output[] = "⚠ Ghostscript 10.03.0 (CVE-2024-29510) - Les payloads avec %pipe% exécuteront des commandes shell!";
    $output[] = "⚠ Les exploits CVE-2024-29510 peuvent bypass -dSAFER via uniprint format string!";
    exec($cmd, $gsOutput, $gsRet);
    $output[] = "Exit code: " . $gsRet;
    $output[] = "Output:";
    $output = array_merge($output, array_slice($gsOutput, 0, 20));
    $output[] = "";
    
    // Technique 1b: Ghostscript pour EPS directement
    if ($ext === 'eps') {
        $output[] = "--- Technique 1b: Ghostscript EPS direct (RCE via PostScript) ---";
        $gsOut2 = $uploadDir . '/gs_eps_' . uniqid() . '.png';
        $cmd2 = 'gs -dNOPAUSE -dBATCH -sDEVICE=png16m -r150 -sOutputFile=' . escapeshellarg($gsOut2) . ' ' . escapeshellarg($filePath) . ' 2>&1';
        $output[] = "Command: " . $cmd2;
        $output[] = "⚠ -dSAFER flag removed (VULNERABLE TO RCE!)";
        $output[] = "⚠ CVE-2024-29510 exploitable via EPS!";
        exec($cmd2, $gsOutput2, $gsRet2);
        $output[] = "Exit code: " . $gsRet2;
        $output[] = "Output:";
        $output = array_merge($output, array_slice($gsOutput2, 0, 20));
        $output[] = "";
    }
    
    // Technique 2: pdftoppm (SSRF via embedded URLs)
    $output[] = "--- Technique 2: pdftoppm (may trigger SSRF) ---";
    $pdfOut = $uploadDir . '/pdf_' . uniqid() . '.png';
    $cmd2 = 'pdftoppm -png -singlefile ' . escapeshellarg($filePath) . ' ' . escapeshellarg($pdfOut) . ' 2>&1';
    $output[] = "Command: " . $cmd2;
    exec($cmd2, $pdfOutput, $pdfRet);
    $output[] = "Exit code: " . $pdfRet;
    $output[] = "Output:";
    $output = array_merge($output, array_slice($pdfOutput, 0, 20));
    $output[] = "";
    
    // Technique 3: exiftool (XXE via XMP)
    $output[] = "--- Technique 3: exiftool (XXE via XMP metadata) ---";
    $cmd3 = 'exiftool ' . escapeshellarg($filePath) . ' 2>&1';
    $output[] = "Command: " . $cmd3;
    exec($cmd3, $exifOutput, $exifRet);
    $output[] = "Exit code: " . $exifRet;
    $output[] = "Output (first 30 lines):";
    $output = array_merge($output, array_slice($exifOutput, 0, 30));
    $output[] = "";
    
    // Technique 4: Extract and parse PDF structure (XXE in XMP, XFA)
    $output[] = "--- Technique 4: Extract PDF objects and parse XML (XXE) ---";
    $pdfContent = file_get_contents($filePath);
    
    // Look for XMP packets
    if (preg_match('/<x:xmpmeta.*?<\/x:xmpmeta>/is', $pdfContent, $xmpMatches)) {
        $output[] = "✓ Found XMP packet in PDF";
        $xmpContent = $xmpMatches[0];
        libxml_disable_entity_loader(false);
        try {
            $dom = new DOMDocument();
            $dom->loadXML($xmpContent, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);
            $output[] = "✓ XMP parsed successfully (XXE may have been triggered!)";
        } catch (Exception $e) {
            $output[] = "Exception: " . $e->getMessage();
        }
    }
    $output[] = "";
    
    return $output;
}

function renderDOCX($filePath, $uploadDir, $origName, $output) {
    $output[] = "=== RENDERING DOCX ===";
    
    // Technique 1: LibreOffice (XXE, SSRF via external resources)
    $output[] = "--- Technique 1: LibreOffice convert to PDF (XXE/SSRF) ---";
    $pdfOut = $uploadDir . '/docx_' . uniqid() . '.pdf';
    $cmd = 'libreoffice --headless --convert-to pdf --outdir ' . escapeshellarg($uploadDir) . ' ' . escapeshellarg($filePath) . ' 2>&1';
    $output[] = "Command: " . $cmd;
    exec($cmd, $loOutput, $loRet);
    $output[] = "Exit code: " . $loRet;
    $output[] = "Output:";
    $output = array_merge($output, array_slice($loOutput, 0, 30));
    $output[] = "";
    
    // Technique 2: Extract and parse XML (XXE)
    $output[] = "--- Technique 2: Extract and parse XML (XXE) ---";
    $zip = new ZipArchive();
    if ($zip->open($filePath) === TRUE) {
        // Extract document.xml
        $docXml = $zip->getFromName('word/document.xml');
        if ($docXml) {
            $output[] = "✓ Extracted word/document.xml";
            $output[] = "Parsing with PHP XML parser (VULNERABLE TO XXE)...";
            
            // Parse with vulnerable XML parser
            libxml_disable_entity_loader(false);
            libxml_use_internal_errors(true);
            try {
                $dom = new DOMDocument();
                $dom->loadXML($docXml, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);
                $output[] = "✓ XML parsed successfully (XXE may have been triggered!)";
            } catch (Exception $e) {
                $output[] = "Exception: " . $e->getMessage();
            }
            
            // Extract rels (SSRF)
            $relsXml = $zip->getFromName('word/_rels/document.xml.rels');
            if ($relsXml) {
                $output[] = "✓ Extracted word/_rels/document.xml.rels";
                try {
                    $domRels = new DOMDocument();
                    $domRels->loadXML($relsXml, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);
                    $output[] = "✓ Rels XML parsed (SSRF may have been triggered!)";
                } catch (Exception $e) {
                    $output[] = "Exception: " . $e->getMessage();
                }
            }
        }
        $zip->close();
    }
    $output[] = "";
    
    return $output;
}

function renderXLSX($filePath, $uploadDir, $origName, $output) {
    $output[] = "=== RENDERING XLSX ===";
    
    // Technique 1: LibreOffice
    $output[] = "--- Technique 1: LibreOffice convert to PDF (XXE/SSRF) ---";
    $pdfOut = $uploadDir . '/xlsx_' . uniqid() . '.pdf';
    $cmd = 'libreoffice --headless --convert-to pdf --outdir ' . escapeshellarg($uploadDir) . ' ' . escapeshellarg($filePath) . ' 2>&1';
    $output[] = "Command: " . $cmd;
    exec($cmd, $loOutput, $loRet);
    $output[] = "Exit code: " . $loRet;
    $output[] = "Output:";
    $output = array_merge($output, array_slice($loOutput, 0, 30));
    $output[] = "";
    
    // Technique 2: Extract and parse XML (XXE)
    $output[] = "--- Technique 2: Extract and parse XML (XXE) ---";
    $zip = new ZipArchive();
    if ($zip->open($filePath) === TRUE) {
        $sharedStrings = $zip->getFromName('xl/sharedStrings.xml');
        if ($sharedStrings) {
            $output[] = "✓ Extracted xl/sharedStrings.xml";
            libxml_disable_entity_loader(false);
            try {
                $dom = new DOMDocument();
                $dom->loadXML($sharedStrings, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);
                $output[] = "✓ XML parsed successfully (XXE may have been triggered!)";
            } catch (Exception $e) {
                $output[] = "Exception: " . $e->getMessage();
            }
        }
        $zip->close();
    }
    $output[] = "";
    
    return $output;
}

function renderPPTX($filePath, $uploadDir, $origName, $output) {
    $output[] = "=== RENDERING PPTX ===";
    
    // Technique 1: LibreOffice
    $output[] = "--- Technique 1: LibreOffice convert to PDF (XXE/SSRF) ---";
    $pdfOut = $uploadDir . '/pptx_' . uniqid() . '.pdf';
    $cmd = 'libreoffice --headless --convert-to pdf --outdir ' . escapeshellarg($uploadDir) . ' ' . escapeshellarg($filePath) . ' 2>&1';
    $output[] = "Command: " . $cmd;
    exec($cmd, $loOutput, $loRet);
    $output[] = "Exit code: " . $loRet;
    $output[] = "Output:";
    $output = array_merge($output, array_slice($loOutput, 0, 30));
    $output[] = "";
    
    // Technique 2: Extract and parse XML (XXE)
    $output[] = "--- Technique 2: Extract and parse XML (XXE) ---";
    $zip = new ZipArchive();
    if ($zip->open($filePath) === TRUE) {
        $presentation = $zip->getFromName('ppt/presentation.xml');
        if ($presentation) {
            $output[] = "✓ Extracted ppt/presentation.xml";
            libxml_disable_entity_loader(false);
            try {
                $dom = new DOMDocument();
                $dom->loadXML($presentation, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);
                $output[] = "✓ XML parsed successfully (XXE may have been triggered!)";
            } catch (Exception $e) {
                $output[] = "Exception: " . $e->getMessage();
            }
        }
        $zip->close();
    }
    $output[] = "";
    
    return $output;
}

function renderODT($filePath, $uploadDir, $origName, $output) {
    $output[] = "=== RENDERING ODT/ODS/ODP ===";
    
    // Technique 1: LibreOffice
    $output[] = "--- Technique 1: LibreOffice convert to PDF (XXE/SSRF) ---";
    $pdfOut = $uploadDir . '/odt_' . uniqid() . '.pdf';
    $cmd = 'libreoffice --headless --convert-to pdf --outdir ' . escapeshellarg($uploadDir) . ' ' . escapeshellarg($filePath) . ' 2>&1';
    $output[] = "Command: " . $cmd;
    exec($cmd, $loOutput, $loRet);
    $output[] = "Exit code: " . $loRet;
    $output[] = "Output:";
    $output = array_merge($output, array_slice($loOutput, 0, 30));
    $output[] = "";
    
    // Technique 2: Extract and parse XML (XXE)
    $output[] = "--- Technique 2: Extract and parse XML (XXE) ---";
    $zip = new ZipArchive();
    if ($zip->open($filePath) === TRUE) {
        $content = $zip->getFromName('content.xml');
        if ($content) {
            $output[] = "✓ Extracted content.xml";
            libxml_disable_entity_loader(false);
            try {
                $dom = new DOMDocument();
                $dom->loadXML($content, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);
                $output[] = "✓ XML parsed successfully (XXE may have been triggered!)";
            } catch (Exception $e) {
                $output[] = "Exception: " . $e->getMessage();
            }
        }
        $zip->close();
    }
    $output[] = "";
    
    return $output;
}

function renderSVG($filePath, $uploadDir, $origName, $output) {
    $output[] = "=== RENDERING SVG ===";
    
    // Technique 1: ImageMagick (SSRF via xlink:href)
    $output[] = "--- Technique 1: ImageMagick convert (SSRF via xlink:href) ---";
    $pngOut = $uploadDir . '/svg_' . uniqid() . '.png';
    $cmd = 'convert ' . escapeshellarg($filePath) . ' ' . escapeshellarg($pngOut) . ' 2>&1';
    $output[] = "Command: " . $cmd;
    exec($cmd, $imgOutput, $imgRet);
    $output[] = "Exit code: " . $imgRet;
    $output[] = "Output:";
    $output = array_merge($output, array_slice($imgOutput, 0, 20));
    $output[] = "";
    
    // Technique 2: Parse as XML (XXE)
    $output[] = "--- Technique 2: Parse as XML (XXE) ---";
    $svgContent = file_get_contents($filePath);
    libxml_disable_entity_loader(false);
    try {
        $dom = new DOMDocument();
        $dom->loadXML($svgContent, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);
        $output[] = "✓ SVG parsed as XML successfully (XXE may have been triggered!)";
    } catch (Exception $e) {
        $output[] = "Exception: " . $e->getMessage();
    }
    $output[] = "";
    
    return $output;
}

function renderXML($filePath, $uploadDir, $origName, $output) {
    $output[] = "=== RENDERING XML ===";
    $output[] = "Parsing XML with vulnerable parser (XXE)...";
    
    $xmlContent = file_get_contents($filePath);
    libxml_disable_entity_loader(false);
    
    // Technique 1: SimpleXML
    $output[] = "--- Technique 1: SimpleXML (XXE) ---";
    libxml_use_internal_errors(true);
    try {
        $xml = simplexml_load_string($xmlContent, 'SimpleXMLElement', LIBXML_NOENT);
        if ($xml !== false) {
            $output[] = "✓ SimpleXML parsed successfully (XXE may have been triggered!)";
        }
    } catch (Exception $e) {
        $output[] = "Exception: " . $e->getMessage();
    }
    $output[] = "";
    
    // Technique 2: DOMDocument
    $output[] = "--- Technique 2: DOMDocument (XXE) ---";
    try {
        $dom = new DOMDocument();
        $dom->loadXML($xmlContent, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);
        $output[] = "✓ DOMDocument parsed successfully (XXE may have been triggered!)";
    } catch (Exception $e) {
        $output[] = "Exception: " . $e->getMessage();
    }
    $output[] = "";
    
    return $output;
}

function renderHTML($filePath, $uploadDir, $origName, $output) {
    $output[] = "=== RENDERING HTML ===";
    
    $htmlContent = file_get_contents($filePath);
    $output[] = "File content length: " . strlen($htmlContent) . " bytes";
    $output[] = "";
    
    // Technique 1: Extract URLs and test SSRF
    $output[] = "--- Technique 1: Extract and test URLs (SSRF) ---";
    preg_match_all('/https?:\/\/[^\s"\'<>]+/', $htmlContent, $urls);
    if (!empty($urls[0])) {
        $output[] = "Found URLs (testing SSRF):";
        foreach (array_unique(array_slice($urls[0], 0, 5)) as $url) {
            $output[] = "  Testing: " . $url;
            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 2);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);
            curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            $output[] = "    HTTP Code: " . $httpCode;
        }
    }
    $output[] = "";
    
    // Technique 2: Extract script tags (XSS/RCE)
    $output[] = "--- Technique 2: Extract script content (XSS/RCE) ---";
    preg_match_all('/<script[^>]*>(.*?)<\/script>/is', $htmlContent, $scripts);
    if (!empty($scripts[1])) {
        $output[] = "Found " . count($scripts[1]) . " script tag(s)";
        foreach (array_slice($scripts[1], 0, 3) as $idx => $script) {
            $output[] = "  Script " . ($idx + 1) . " (first 200 chars): " . substr(trim($script), 0, 200);
        }
    }
    $output[] = "";
    
    // Technique 3: Display content (XSS)
    $output[] = "--- Technique 3: Content preview (XSS will be rendered) ---";
    $output[] = "⚠ HTML content will be displayed below (XSS possible):";
    $output[] = "";
    $output[] = "=== HTML CONTENT START ===";
    $output[] = substr($htmlContent, 0, 1000);
    if (strlen($htmlContent) > 1000) {
        $output[] = "... (truncated)";
    }
    $output[] = "=== HTML CONTENT END ===";
    $output[] = "";
    
    // Store HTML for display
    global $htmlContentForDisplay;
    $htmlContentForDisplay = $htmlContent;
    
    return $output;
}

function renderImage($filePath, $uploadDir, $origName, $output, $ext) {
    $output[] = "=== RENDERING IMAGE ===";
    $output[] = "File type: " . strtoupper($ext);
    $output[] = "";
    
    $fileData = file_get_contents($filePath);
    $fileSize = strlen($fileData);
    
    if (in_array($ext, ['jpg', 'jpeg'])) {
        return renderJPEG($filePath, $uploadDir, $origName, $output, $fileData);
    } elseif ($ext === 'png') {
        return renderPNG($filePath, $uploadDir, $origName, $output, $fileData);
    } else {
        return renderImageGeneric($filePath, $uploadDir, $origName, $output, $ext);
    }
}

function renderJPEG($filePath, $uploadDir, $origName, $output, $fileData) {
    $output[] = "=== JPG/JPEG VULNERABILITIES ===";
    $output[] = "";
    
    $output[] = "--- Technique 1: ExifTool DjVu polyglotte (RCE - CVE-2021-22204) ---";
    $cmd1 = 'exiftool ' . escapeshellarg($filePath) . ' 2>&1';
    $output[] = "Command: " . $cmd1;
    exec($cmd1, $exifOutput, $exifRet);
    $output[] = "Exit code: " . $exifRet;
    $output[] = "Output (first 40 lines):";
    $output = array_merge($output, array_slice($exifOutput, 0, 40));
    $output[] = "";
    
    $output[] = "--- Technique 2: PHP unserialize EXIF Comment/Artist (RCE - Facebook 35k$ + Shopify 25k$) ---";
    if (function_exists('exif_read_data')) {
        $exifData = @exif_read_data($filePath);
        if ($exifData) {
            $output[] = "✓ EXIF data found";
            if (isset($exifData['COMMENT'])) {
                $output[] = "EXIF COMMENT: " . print_r($exifData['COMMENT'], true);
                foreach ((array)$exifData['COMMENT'] as $comment) {
                    if (preg_match('/^[Oa]:\d+:/', $comment)) {
                        $output[] = "⚠ Serialized data detected in COMMENT! Attempting unserialize...";
                        try {
                            @unserialize($comment);
                            $output[] = "✓ Unserialize executed (RCE may have been triggered!)";
                        } catch (Exception $e) {
                            $output[] = "Exception: " . $e->getMessage();
                        }
                    }
                }
            }
            if (isset($exifData['ARTIST'])) {
                $output[] = "EXIF ARTIST: " . $exifData['ARTIST'];
                if (preg_match('/^[Oa]:\d+:/', $exifData['ARTIST'])) {
                    $output[] = "⚠ Serialized data detected in ARTIST! Attempting unserialize...";
                    try {
                        @unserialize($exifData['ARTIST']);
                        $output[] = "✓ Unserialize executed (RCE may have been triggered!)";
                    } catch (Exception $e) {
                        $output[] = "Exception: " . $e->getMessage();
                    }
                }
            }
        }
    }
    $output[] = "";
    
    $output[] = "--- Technique 3: Java ysoserial EXIF/XMP (RCE - Adobe AEM 40k$) ---";
    if (preg_match('/<x:xmpmeta.*?<\/x:xmpmeta>/is', $fileData, $xmpMatches)) {
        $output[] = "✓ XMP metadata found in JPEG";
        $xmpContent = $xmpMatches[0];
        if (preg_match('/rdf:about="([^"]+)"/', $xmpContent, $urlMatches)) {
            $output[] = "Found URL in XMP: " . $urlMatches[1];
        }
    }
    $output[] = "";
    
    $output[] = "--- Technique 4: SSRF ICC profile URL (Cloudinary 10k$ + Imgix CDN) ---";
    if (preg_match('/ICC_PROFILE/i', $fileData)) {
        $output[] = "✓ ICC profile found";
        if (preg_match('/http[s]?:\/\/[^\s\x00]+/i', $fileData, $iccUrls)) {
            $output[] = "⚠ URL found in ICC profile: " . $iccUrls[0];
            $output[] = "Testing SSRF...";
            $ch = curl_init($iccUrls[0]);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 3);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            $output[] = "HTTP Code: " . $httpCode;
        }
    }
    $output[] = "";
    
    $output[] = "--- Technique 5: XXE XMP embedded APP1 (GitLab 12k$ + DAM systems) ---";
    if (preg_match('/\xFF\xE1.*?<x:xmpmeta.*?<\/x:xmpmeta>/is', $fileData, $app1Matches)) {
        $output[] = "✓ XMP in APP1 segment found";
        $xmpForParsing = preg_replace('/.*?(<x:xmpmeta.*?<\/x:xmpmeta>).*/is', '$1', $app1Matches[0]);
        libxml_disable_entity_loader(false);
        try {
            $dom = new DOMDocument();
            $dom->loadXML($xmpForParsing, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);
            $output[] = "✓ XMP parsed successfully (XXE may have been triggered!)";
        } catch (Exception $e) {
            $output[] = "Exception: " . $e->getMessage();
        }
    }
    $output[] = "";
    
    $output[] = "--- Technique 6: RCE PHP code in EXIF + LFI chain (BookFresh/Square 2023) ---";
    if (function_exists('exif_read_data')) {
        $exifData = @exif_read_data($filePath);
        if ($exifData && isset($exifData['COMPUTED']['UserComment'])) {
            $userComment = $exifData['COMPUTED']['UserComment'];
            if (preg_match('/\.\.\//', $userComment)) {
                $output[] = "⚠ Path traversal detected in UserComment: " . $userComment;
                $output[] = "⚠ LFI chain possible";
            }
            if (preg_match('/<\?php|<\?=|eval\(|system\(|exec\(/i', $userComment)) {
                $output[] = "⚠ PHP code detected in UserComment!";
            }
        }
    }
    $output[] = "";
    
    $output[] = "--- Technique 7: RCE libjpeg EXIF buffer overflow (Vercel workers 8k$ + CVE-2023-47475) ---";
    $output[] = "Processing with ImageMagick (may trigger buffer overflow)...";
    $pngOut = $uploadDir . '/jpeg_' . uniqid() . '.png';
    $cmd7 = 'convert ' . escapeshellarg($filePath) . ' ' . escapeshellarg($pngOut) . ' 2>&1';
    exec($cmd7, $imgOutput, $imgRet);
    $output[] = "Exit code: " . $imgRet;
    $output[] = "Output (first 20 lines):";
    $output = array_merge($output, array_slice($imgOutput, 0, 20));
    $output[] = "";
    
    $output[] = "--- Technique 8: SSRF EXIF GPS GeoURL (Intigriti bounties 2024) ---";
    if (function_exists('exif_read_data')) {
        $exifData = @exif_read_data($filePath);
        if ($exifData && isset($exifData['GPS'])) {
            $output[] = "✓ GPS data found";
            if (isset($exifData['GPS']['GPSLatitudeRef']) && isset($exifData['GPS']['GPSLongitudeRef'])) {
                $output[] = "GPS Coordinates detected";
                if (preg_match('/geo:.*?http[s]?:\/\//i', $fileData, $geoUrls)) {
                    $output[] = "⚠ GeoURL found: " . $geoUrls[0];
                }
            }
        }
    }
    $output[] = "";
    
    $output[] = "--- Technique 9: RCE ExifTool MakerNotes eval (CVE-2022-45020) ---";
    $cmd9 = 'exiftool -MakerNote ' . escapeshellarg($filePath) . ' 2>&1';
    $output[] = "Command: " . $cmd9;
    exec($cmd9, $makerOutput, $makerRet);
    $output[] = "Exit code: " . $makerRet;
    $output[] = "Output (first 30 lines):";
    $output = array_merge($output, array_slice($makerOutput, 0, 30));
    $output[] = "";
    
    return $output;
}

function renderPNG($filePath, $uploadDir, $origName, $output, $fileData) {
    $output[] = "=== PNG VULNERABILITIES ===";
    $output[] = "";
    
    $output[] = "--- Technique 1: RCE libpng chunk overflow tEXt (Vercel 8k$ + CVE-2023-47475) ---";
    if (preg_match('/tEXt(.*?)\x00(.*?)\x00/', $fileData, $textMatches)) {
        $output[] = "✓ tEXt chunk found";
        $textKeyword = $textMatches[1];
        $textValue = $textMatches[2];
        $output[] = "Keyword: " . $textKeyword;
        $output[] = "Value length: " . strlen($textValue);
        if (strlen($textValue) > 1000) {
            $output[] = "⚠ Large tEXt chunk detected (potential buffer overflow)";
        }
    }
    $output[] = "Processing with ImageMagick convert (may trigger overflow)...";
    $pngOut = $uploadDir . '/png_' . uniqid() . '.png';
    $cmd1 = 'convert ' . escapeshellarg($filePath) . ' ' . escapeshellarg($pngOut) . ' 2>&1';
    exec($cmd1, $imgOutput, $imgRet);
    $output[] = "Exit code: " . $imgRet;
    $output[] = "Output (first 20 lines):";
    $output = array_merge($output, array_slice($imgOutput, 0, 20));
    $output[] = "";
    
    $output[] = "--- Technique 2: SSRF iTXt chunk URL (Imgix 10k$ + ImageMagick CVE-2016-3718) ---";
    if (preg_match('/iTXt(.*?)\x00(.*?)\x00(.*?)\x00(.*?)\x00/', $fileData, $itxtMatches)) {
        $output[] = "✓ iTXt chunk found";
        $itxtKeyword = $itxtMatches[1];
        $itxtValue = isset($itxtMatches[4]) ? $itxtMatches[4] : '';
        $output[] = "Keyword: " . $itxtKeyword;
        if (preg_match('/http[s]?:\/\/[^\s\x00]+/', $itxtValue, $urlMatches)) {
            $output[] = "⚠ URL found in iTXt: " . $urlMatches[0];
            $output[] = "Testing SSRF...";
            $ch = curl_init($urlMatches[0]);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 3);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            $output[] = "HTTP Code: " . $httpCode;
        }
    }
    $output[] = "";
    
    $output[] = "--- Technique 3: XXE XML in tEXt chunk (Adobe 12k$ + PortSwigger PNG-XXE) ---";
    if (preg_match('/tEXt(.*?)\x00(.*?)\x00/', $fileData, $textMatches)) {
        $textValue = $textMatches[2];
        if (preg_match('/<\?xml|<[a-zA-Z]/', $textValue)) {
            $output[] = "⚠ XML detected in tEXt chunk!";
            libxml_disable_entity_loader(false);
            try {
                $dom = new DOMDocument();
                $dom->loadXML($textValue, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);
                $output[] = "✓ XML parsed successfully (XXE may have been triggered!)";
            } catch (Exception $e) {
                $output[] = "Exception: " . $e->getMessage();
            }
        }
    }
    $output[] = "";
    
    $output[] = "--- Technique 4: RCE PHP/Java unserialize in tEXt chunk (Facebook 25k$ + media SaaS) ---";
    if (preg_match('/tEXt(.*?)\x00(.*?)\x00/', $fileData, $textMatches)) {
        $textValue = $textMatches[2];
        if (preg_match('/^[Oa]:\d+:/', $textValue)) {
            $output[] = "⚠ Serialized data detected in tEXt chunk!";
            $output[] = "Attempting unserialize...";
            try {
                @unserialize($textValue);
                $output[] = "✓ Unserialize executed (RCE may have been triggered!)";
            } catch (Exception $e) {
                $output[] = "Exception: " . $e->getMessage();
            }
        }
    }
    $output[] = "";
    
    $output[] = "--- Technique 5: SSRF polyglotte PNG + ImageTragick MVG (WordPress plugins + bounties 5-10k$) ---";
    $mvgPayload = '';
    $mvgFound = false;
    if (preg_match('/ImageMagick\x00\x00([^\x00]+)/', $fileData, $matches)) {
        $mvgFound = true;
        $mvgPayload = $matches[1];
        $output[] = "✓ MVG payload found in iTXt chunk!";
        $output[] = "Extracting and testing MVG payload...";
        
        $mvgPath = $uploadDir . '/payload_' . uniqid() . '.mvg';
        file_put_contents($mvgPath, $mvgPayload);
        $output[] = "✓ MVG file written to: " . $mvgPath;
        
        $renderPath = $uploadDir . '/rendered_' . uniqid() . '.png';
        $cmd5 = 'convert "mvg:' . $mvgPath . '" ' . escapeshellarg($renderPath) . ' 2>&1';
        $output[] = "Command: " . $cmd5;
        exec($cmd5, $mvgOutput, $mvgRet);
        $output[] = "Exit code: " . $mvgRet;
        $output[] = "Output:";
        $output = array_merge($output, array_slice($mvgOutput, 0, 20));
    }
    $output[] = "";
    
    $output[] = "--- Technique 6: RCE Sharp/libvips TIFF-in-PNG overflow (Netlify/Vercel functions 2024-2025) ---";
    if (preg_match('/tEXt.*?TIFF/i', $fileData)) {
        $output[] = "⚠ TIFF data detected in PNG";
        $output[] = "Processing with ImageMagick (may trigger overflow)...";
        $tiffOut = $uploadDir . '/tiff_' . uniqid() . '.tiff';
        $cmd6 = 'convert ' . escapeshellarg($filePath) . ' ' . escapeshellarg($tiffOut) . ' 2>&1';
        exec($cmd6, $tiffOutput, $tiffRet);
        $output[] = "Exit code: " . $tiffRet;
        $output[] = "Output (first 20 lines):";
        $output = array_merge($output, array_slice($tiffOutput, 0, 20));
    }
    $output[] = "";
    
    $output[] = "--- Technique 7: XMP in PNG (XXE) ---";
    if (preg_match('/XML:com\.adobe\.xmp\x00\x00([^\x00]+)/', $fileData, $xmpMatches)) {
        $xmpPayload = $xmpMatches[1];
        $output[] = "✓ XMP payload found in iTXt chunk!";
        
        $xmpForParsing = '<?xml version="1.0"?>' . "\n" . $xmpPayload;
        libxml_disable_entity_loader(false);
        try {
            $dom = new DOMDocument();
            $dom->loadXML($xmpForParsing, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);
            $output[] = "✓ XMP parsed successfully (XXE may have been triggered!)";
        } catch (Exception $e) {
            $output[] = "Exception: " . $e->getMessage();
        }
    }
    $output[] = "";
    
    $output[] = "--- Technique 8: ImageMagick identify (may trigger chunk parsing vulnerabilities) ---";
    $cmd8 = 'identify -verbose ' . escapeshellarg($filePath) . ' 2>&1';
    $output[] = "Command: " . $cmd8;
    exec($cmd8, $identifyOutput, $identifyRet);
    $output[] = "Exit code: " . $identifyRet;
    $output[] = "Output (first 40 lines):";
    $output = array_merge($output, array_slice($identifyOutput, 0, 40));
    $output[] = "";
    
    $output[] = "--- Technique 9: ImageMagick mogrify (may trigger chunk processing) ---";
    $mogrifyOut = $uploadDir . '/mogrify_' . uniqid() . '.png';
    copy($filePath, $mogrifyOut);
    $cmd9 = 'mogrify -resize 100x100 ' . escapeshellarg($mogrifyOut) . ' 2>&1';
    $output[] = "Command: " . $cmd9;
    exec($cmd9, $mogrifyOutput, $mogrifyRet);
    $output[] = "Exit code: " . $mogrifyRet;
    $output[] = "Output (first 20 lines):";
    $output = array_merge($output, array_slice($mogrifyOutput, 0, 20));
    $output[] = "";
    
    $output[] = "--- Technique 10: ImageMagick composite (may trigger chunk parsing) ---";
    $compositeOut = $uploadDir . '/composite_' . uniqid() . '.png';
    $cmd10 = 'composite ' . escapeshellarg($filePath) . ' ' . escapeshellarg($filePath) . ' ' . escapeshellarg($compositeOut) . ' 2>&1';
    $output[] = "Command: " . $cmd10;
    exec($cmd10, $compositeOutput, $compositeRet);
    $output[] = "Exit code: " . $compositeRet;
    $output[] = "Output (first 20 lines):";
    $output = array_merge($output, array_slice($compositeOutput, 0, 20));
    $output[] = "";
    
    $output[] = "--- Technique 11: Extract all PNG chunks and parse (zTXt, sPLT, iCCP, etc.) ---";
    $chunks = extractPNGChunks($fileData);
    if (!empty($chunks)) {
        $output[] = "✓ Found " . count($chunks) . " chunks";
        foreach ($chunks as $chunkType => $chunkData) {
            $output[] = "Chunk type: " . $chunkType . " (length: " . strlen($chunkData) . " bytes)";
            
            if ($chunkType === 'zTXt') {
                $output[] = "  Processing zTXt (compressed text) chunk...";
                if (preg_match('/http[s]?:\/\/[^\s\x00]+/', $chunkData, $zurlMatches)) {
                    $output[] = "  ⚠ URL found in zTXt: " . $zurlMatches[0];
                }
                if (preg_match('/<\?xml|<[a-zA-Z]/', $chunkData)) {
                    $output[] = "  ⚠ XML detected in zTXt!";
                    libxml_disable_entity_loader(false);
                    try {
                        $dom = new DOMDocument();
                        $dom->loadXML($chunkData, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);
                        $output[] = "  ✓ XML parsed (XXE may have been triggered!)";
                    } catch (Exception $e) {
                        $output[] = "  Exception: " . $e->getMessage();
                    }
                }
            }
            
            if ($chunkType === 'sPLT') {
                $output[] = "  Processing sPLT (suggested palette) chunk...";
            }
            
            if ($chunkType === 'iCCP') {
                $output[] = "  Processing iCCP (ICC profile) chunk...";
                if (preg_match('/http[s]?:\/\/[^\s\x00]+/', $chunkData, $iccpUrls)) {
                    $output[] = "  ⚠ URL found in iCCP: " . $iccpUrls[0];
                    $output[] = "  Testing SSRF...";
                    $ch = curl_init($iccpUrls[0]);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                    curl_setopt($ch, CURLOPT_TIMEOUT, 3);
                    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
                    curl_exec($ch);
                    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                    curl_close($ch);
                    $output[] = "  HTTP Code: " . $httpCode;
                }
            }
            
            if (preg_match('/\.\.\//', $chunkData)) {
                $output[] = "  ⚠ Path traversal detected in chunk " . $chunkType;
            }
            
            if (preg_match('/^[Oa]:\d+:/', $chunkData)) {
                $output[] = "  ⚠ Serialized data detected in chunk " . $chunkType;
                try {
                    @unserialize($chunkData);
                    $output[] = "  ✓ Unserialize executed (RCE may have been triggered!)";
                } catch (Exception $e) {
                    $output[] = "  Exception: " . $e->getMessage();
                }
            }
        }
    }
    $output[] = "";
    
    $output[] = "--- Technique 12: PHP GD imagecreatefrompng (may trigger libpng overflow) ---";
    if (function_exists('imagecreatefrompng')) {
        $output[] = "Attempting to load PNG with PHP GD...";
        $img = @imagecreatefrompng($filePath);
        if ($img) {
            $output[] = "✓ PNG loaded successfully with GD (overflow may have been triggered!)";
            imagedestroy($img);
        } else {
            $output[] = "✗ Failed to load PNG with GD";
        }
    } else {
        $output[] = "PHP GD extension not available";
    }
    $output[] = "";
    
    $output[] = "--- Technique 13: ImageMagick convert to different formats (may trigger vulnerabilities) ---";
    $formats = ['jpg', 'gif', 'bmp', 'tiff', 'webp'];
    foreach ($formats as $format) {
        $formatOut = $uploadDir . '/png_to_' . $format . '_' . uniqid() . '.' . $format;
        $cmd13 = 'convert ' . escapeshellarg($filePath) . ' ' . escapeshellarg($formatOut) . ' 2>&1';
        exec($cmd13, $formatOutput, $formatRet);
        if ($formatRet === 0) {
            $output[] = "✓ Converted to " . strtoupper($format) . " successfully";
        }
    }
    $output[] = "";
    
    $output[] = "--- Technique 14: ImageMagick with various operations (resize, crop, etc.) ---";
    $opsOut = $uploadDir . '/ops_' . uniqid() . '.png';
    $cmd14 = 'convert ' . escapeshellarg($filePath) . ' -resize 50% -crop 100x100+10+10 ' . escapeshellarg($opsOut) . ' 2>&1';
    $output[] = "Command: " . $cmd14;
    exec($cmd14, $opsOutput, $opsRet);
    $output[] = "Exit code: " . $opsRet;
    $output[] = "Output (first 20 lines):";
    $output = array_merge($output, array_slice($opsOutput, 0, 20));
    $output[] = "";
    
    $output[] = "--- Technique 15: exiftool (XXE via XMP and other metadata) ---";
    $cmd15 = 'exiftool ' . escapeshellarg($filePath) . ' 2>&1';
    $output[] = "Command: " . $cmd15;
    exec($cmd15, $exifOutput, $exifRet);
    $output[] = "Exit code: " . $exifRet;
    $output[] = "Output (first 30 lines):";
    $output = array_merge($output, array_slice($exifOutput, 0, 30));
    $output[] = "";
    
    return $output;
}

function extractPNGChunks($fileData) {
    $chunks = [];
    $offset = 8;
    
    while ($offset < strlen($fileData) - 8) {
        if ($offset + 8 > strlen($fileData)) break;
        
        $length = unpack('N', substr($fileData, $offset, 4))[1];
        $chunkType = substr($fileData, $offset + 4, 4);
        
        if ($offset + 8 + $length + 4 > strlen($fileData)) break;
        
        $chunkData = substr($fileData, $offset + 8, $length);
        $crc = substr($fileData, $offset + 8 + $length, 4);
        
        if ($chunkType === 'IEND') break;
        
        if (!isset($chunks[$chunkType])) {
            $chunks[$chunkType] = '';
        }
        $chunks[$chunkType] .= $chunkData;
        
        $offset += 8 + $length + 4;
    }
    
    return $chunks;
}

function renderImageGeneric($filePath, $uploadDir, $origName, $output, $ext) {
    $output[] = "=== GENERIC IMAGE RENDERING ===";
    
    $pngOut = $uploadDir . '/img_' . uniqid() . '.png';
    $cmd = 'convert ' . escapeshellarg($filePath) . ' ' . escapeshellarg($pngOut) . ' 2>&1';
    $output[] = "Command: " . $cmd;
    exec($cmd, $imgOutput, $imgRet);
    $output[] = "Exit code: " . $imgRet;
    $output[] = "Output:";
    $output = array_merge($output, array_slice($imgOutput, 0, 20));
    $output[] = "";
    
    $cmd2 = 'exiftool ' . escapeshellarg($filePath) . ' 2>&1';
    $output[] = "Command: " . $cmd2;
    exec($cmd2, $exifOutput, $exifRet);
    $output[] = "Exit code: " . $exifRet;
    $output[] = "Output (first 30 lines):";
    $output = array_merge($output, array_slice($exifOutput, 0, 30));
    $output[] = "";
    
    return $output;
}

function renderWebM($filePath, $uploadDir, $origName, $output) {
    $output[] = "=== WEBM VULNERABILITIES ===";
    $output[] = "";
    
    $fileData = file_get_contents($filePath);
    
    $output[] = "--- Technique 1: RCE VP8 frame buffer overflow (Netflix bounty 2024 + CVE-2023-4863 libwebp chain) ---";
    $output[] = "Processing with FFmpeg (may trigger buffer overflow)...";
    $mp4Out = $uploadDir . '/webm_' . uniqid() . '.mp4';
    $cmd1 = 'ffmpeg -i ' . escapeshellarg($filePath) . ' -c copy ' . escapeshellarg($mp4Out) . ' 2>&1';
    $output[] = "Command: " . $cmd1;
    exec($cmd1, $ffmpegOutput, $ffmpegRet);
    $output[] = "Exit code: " . $ffmpegRet;
    $output[] = "Output (first 40 lines):";
    $output = array_merge($output, array_slice($ffmpegOutput, 0, 40));
    $output[] = "";
    
    $output[] = "--- Technique 2: SSRF EBML metadata URL (Neex/HackerOne 12k$ + CVE-2021-38171) ---";
    if (preg_match('/http[s]?:\/\/[^\s\x00]+/', $fileData, $ebmlUrls)) {
        $output[] = "⚠ URL found in EBML metadata: " . $ebmlUrls[0];
        $output[] = "Testing SSRF...";
        $ch = curl_init($ebmlUrls[0]);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 3);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        $output[] = "HTTP Code: " . $httpCode;
    }
    $output[] = "";
    
    $output[] = "--- Technique 3: XXE XML timed text embed (YouTube-like SaaS 10k$ + CVE-2024-1010) ---";
    if (preg_match('/<\?xml.*?<\/tt>/is', $fileData, $xmlMatches)) {
        $output[] = "✓ XML timed text found in WebM";
        $xmlContent = $xmlMatches[0];
        libxml_disable_entity_loader(false);
        try {
            $dom = new DOMDocument();
            $dom->loadXML($xmlContent, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);
            $output[] = "✓ XML parsed successfully (XXE may have been triggered!)";
        } catch (Exception $e) {
            $output[] = "Exception: " . $e->getMessage();
        }
    }
    $output[] = "";
    
    $output[] = "--- Technique 4: SSRF m3u8 playlist embed polyglotte (Neex report 2021-2024 + CVE-2017-9693) ---";
    if (preg_match('/#EXTINF.*?http[s]?:\/\/[^\s\n]+/i', $fileData, $m3u8Matches)) {
        $output[] = "⚠ m3u8 playlist URL found: " . $m3u8Matches[0];
        if (preg_match('/http[s]?:\/\/[^\s\n]+/', $m3u8Matches[0], $playlistUrl)) {
            $output[] = "Testing SSRF with playlist URL...";
            $ch = curl_init($playlistUrl[0]);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 3);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            $output[] = "HTTP Code: " . $httpCode;
        }
    }
    $output[] = "";
    
    $output[] = "--- Technique 5: RCE FFmpeg avformat_open_input overflow (streaming platforms 2023-2025) ---";
    $output[] = "Processing with FFmpeg avformat_open_input (may trigger overflow)...";
    $cmd5 = 'ffprobe -v error -show_format -show_streams ' . escapeshellarg($filePath) . ' 2>&1';
    $output[] = "Command: " . $cmd5;
    exec($cmd5, $ffprobeOutput, $ffprobeRet);
    $output[] = "Exit code: " . $ffprobeRet;
    $output[] = "Output (first 40 lines):";
    $output = array_merge($output, array_slice($ffprobeOutput, 0, 40));
    $output[] = "";
    
    $output[] = "--- Technique 6: Extract metadata with exiftool ---";
    $cmd6 = 'exiftool ' . escapeshellarg($filePath) . ' 2>&1';
    $output[] = "Command: " . $cmd6;
    exec($cmd6, $exifOutput, $exifRet);
    $output[] = "Exit code: " . $exifRet;
    $output[] = "Output (first 30 lines):";
    $output = array_merge($output, array_slice($exifOutput, 0, 30));
    $output[] = "";
    
    return $output;
}

function renderArchive($filePath, $uploadDir, $origName, $output) {
    $output[] = "=== RENDERING ARCHIVE (ZIP/JAR/EPUB) ===";
    
    // Technique 1: Extract (Path Traversal, XXE, RCE)
    $output[] = "--- Technique 1: Extract archive (Path Traversal, XXE, RCE) ---";
    $extractDir = $uploadDir . '/extract_' . uniqid();
    mkdir($extractDir, 0777, true);
    
    $zip = new ZipArchive();
    if ($zip->open($filePath) === TRUE) {
        $output[] = "✓ Archive opened";
        $output[] = "Extracting files (Path Traversal possible)...";
        
        // Extract all files (vulnerable to path traversal)
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $filename = $zip->getNameIndex($i);
            $output[] = "  Extracting: " . $filename;
            
            // Vulnerable extraction (no path validation)
            $extractPath = $extractDir . '/' . $filename;
            $dir = dirname($extractPath);
            if (!is_dir($dir)) {
                mkdir($dir, 0777, true);
            }
            file_put_contents($extractPath, $zip->getFromIndex($i));
        }
        $zip->close();
        $output[] = "✓ Extraction complete";
        $output[] = "";
        
        // Technique 2: Parse XML files in archive (XXE)
        $output[] = "--- Technique 2: Parse XML files in archive (XXE) ---";
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($extractDir));
        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'xml') {
                $output[] = "Found XML: " . $file->getPathname();
                $xmlContent = file_get_contents($file->getPathname());
                libxml_disable_entity_loader(false);
                try {
                    $dom = new DOMDocument();
                    $dom->loadXML($xmlContent, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);
                    $output[] = "  ✓ XML parsed (XXE may have been triggered!)";
                } catch (Exception $e) {
                    $output[] = "  Exception: " . $e->getMessage();
                }
            }
        }
        $output[] = "";
        
        // Technique 3: Execute PHP files (RCE)
        $output[] = "--- Technique 3: Execute PHP files if found (RCE) ---";
        $phpIterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($extractDir));
        foreach ($phpIterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $output[] = "Found PHP file: " . $file->getPathname();
                $output[] = "⚠ PHP execution disabled for security, but file would be executed in vulnerable setup";
                $output[] = "  File content (first 200 chars): " . substr(file_get_contents($file->getPathname()), 0, 200);
            }
        }
        $output[] = "";
    } else {
        $output[] = "✗ Failed to open archive";
    }
    
    return $output;
}

function renderText($filePath, $uploadDir, $origName, $output) {
    $output[] = "=== RENDERING TEXT FILE ===";
    
    // Technique 1: Read and display (XSS)
    $output[] = "--- Technique 1: Read content (XSS possible) ---";
    $content = file_get_contents($filePath);
    $output[] = "File content length: " . strlen($content) . " bytes";
    $output[] = "⚠ Content will be displayed (XSS possible)";
    $output[] = "";
    
    // Technique 2: Command injection (if content is executed)
    $output[] = "--- Technique 2: Check for command injection patterns ---";
    if (preg_match('/[|;&`$()]/', $content)) {
        $output[] = "⚠ File contains characters that could trigger command injection";
    }
    $output[] = "";
    
    return $output;
}

function renderGeneric($filePath, $uploadDir, $origName, $output) {
    $output[] = "=== GENERIC RENDERING ===";
    $output[] = "Trying to identify file type and render...";
    
    // Try file command
    $output[] = "--- File type detection ---";
    $cmd = 'file ' . escapeshellarg($filePath) . ' 2>&1';
    exec($cmd, $fileOutput, $fileRet);
    $output[] = "Output:";
    $output = array_merge($output, $fileOutput);
    $output[] = "";
    
    return $output;
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Vuln Render Lab – All File Types</title>
    <style>
        body { font-family: sans-serif; margin: 2rem; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .box { border: 1px solid #ddd; padding: 1.5rem; border-radius: 6px; margin-bottom: 1rem; }
        .message { margin-top: 1rem; padding: 1rem; background: #f9f9f9; border-radius: 4px; border-left: 4px solid #007bff; }
        input[type=file] { margin-top: 0.5rem; padding: 0.5rem; width: 100%; }
        button { margin-top: 1rem; padding: 0.75rem 1.5rem; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; }
        button:hover { background: #0056b3; }
        code { background: #eee; padding: 0.1rem 0.3rem; border-radius: 3px; font-family: monospace; }
        pre { background: #1e1e1e; color: #d4d4d4; padding: 1rem; border-radius: 4px; overflow-x: auto; font-size: 0.9rem; line-height: 1.5; }
        h1 { color: #333; }
        h2 { color: #555; margin-top: 2rem; }
        .supported { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-top: 1rem; }
        .supported-item { padding: 0.5rem; background: #f0f0f0; border-radius: 4px; }
    </style>
</head>
<body>
<div class="container">
    <h1>Vuln Render Lab – All File Types</h1>
    <div class="box">
        <p>
            This lab is <strong>intentionally vulnerable</strong> and renders various file types server-side
            to trigger vulnerabilities: <strong>RCE</strong>, <strong>SSRF</strong>, <strong>XXE</strong>, <strong>XSS</strong>, 
            <strong>Path Traversal</strong>, <strong>NTLM Leak</strong>, etc.
        </p>
        <h2>Supported File Types</h2>
        <div class="supported">
            <div class="supported-item"><strong>PDF</strong> - Ghostscript, pdftoppm, exiftool</div>
            <div class="supported-item"><strong>DOCX/XLSX/PPTX</strong> - LibreOffice, XML parsing</div>
            <div class="supported-item"><strong>ODT/ODS/ODP</strong> - LibreOffice, XML parsing</div>
            <div class="supported-item"><strong>SVG</strong> - ImageMagick, XML parsing</div>
            <div class="supported-item"><strong>XML</strong> - PHP XML parsers</div>
            <div class="supported-item"><strong>HTML</strong> - Direct rendering</div>
            <div class="supported-item"><strong>PNG/JPG/GIF</strong> - ImageMagick, exiftool</div>
            <div class="supported-item"><strong>ZIP/JAR/EPUB</strong> - Extraction, XML parsing</div>
            <div class="supported-item"><strong>TXT/CSV/RTF/MD</strong> - Direct rendering</div>
        </div>
        <form method="post" enctype="multipart/form-data">
            <label>
                <strong>Upload file:</strong>
                <input type="file" name="file" accept="*/*">
            </label>
            <br>
            <button type="submit">Upload &amp; Render</button>
        </form>
        <?php if ($message): ?>
            <div class="message">
                <?php echo $message; ?>
            </div>
        <?php endif; ?>
    </div>
</div>
</body>
</html>

