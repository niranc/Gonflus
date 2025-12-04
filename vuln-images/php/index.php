<?php
// Intentionally vulnerable PHP upload + ImageMagick render

error_reporting(E_ALL);
ini_set('display_errors', 1);

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
        $message = 'Upload error';
    } else {
        $uploadDir  = __DIR__ . '/uploads';
        if (!is_dir($uploadDir)) {
            mkdir($uploadDir, 0777, true);
        }

        $tmpName    = $_FILES['file']['tmp_name'];
        $origName   = basename($_FILES['file']['name']);
        $targetPath = $uploadDir . '/' . $origName;

        if (!move_uploaded_file($tmpName, $targetPath)) {
            $message = 'Failed to move uploaded file';
        } else {
            // INTENTIONALLY UNSAFE - Multiple attack vectors to trigger ImageTragick RCE:
            $allOutput = [];
            $allOutput[] = "=== UPLOAD SUCCESS ===";
            $allOutput[] = "File saved to: " . $targetPath;
            $allOutput[] = "File size: " . filesize($targetPath) . " bytes";
            $allOutput[] = "";
            
            // Method 1: Extract iTXt chunks (ImageMagick MVG, XMP XXE/SSRF, etc.)
            $allOutput[] = "=== STEP 1: Extract payloads from PNG iTXt chunks ===";
            $pngData = file_get_contents($targetPath);
            $allOutput[] = "PNG file read: " . strlen($pngData) . " bytes";
            
            $mvgPayload = '';
            $mvgFound = false;
            $xmpPayload = '';
            $xmpFound = false;
            
            // Look for ImageMagick MVG payload
            if (preg_match('/ImageMagick\x00\x00([^\x00]+)/', $pngData, $matches)) {
                $mvgPayload = $matches[1];
                $mvgFound = true;
                $allOutput[] = "✓ MVG payload found in iTXt chunk (ImageMagick keyword)!";
                $allOutput[] = "Payload length: " . strlen($mvgPayload) . " bytes";
                $allOutput[] = "Payload preview (first 200 chars): " . substr($mvgPayload, 0, 200);
                
                $mvgPath = $uploadDir . '/payload_' . uniqid() . '.mvg';
                if (file_put_contents($mvgPath, $mvgPayload) !== false) {
                    $allOutput[] = "✓ MVG file written to: " . $mvgPath;
                    $allOutput[] = "";
                    
                    // Force MVG interpretation - THIS IS THE VULNERABLE PATH
                    $allOutput[] = "=== STEP 2: Execute convert with MVG protocol (mvg:file.mvg) ===";
                    $renderPath = $uploadDir . '/rendered_' . $origName . '.png';
                    
                    // Check if payload uses url() which triggers delegates
                    $usesUrl = (strpos($mvgPayload, 'url(') !== false || strpos($mvgPayload, 'url (') !== false);
                    if ($usesUrl) {
                        $allOutput[] = "⚠ Payload contains url() - this should trigger delegates!";
                    }
                    
                    // Try with explicit size if viewbox is missing
                    $hasViewbox = (strpos($mvgPayload, 'viewbox') !== false);
                    if (!$hasViewbox && !$usesUrl) {
                        // Add viewbox if missing (required for MVG)
                        $mvgWithViewbox = "push graphic-context\nviewbox 0 0 640 480\n" . $mvgPayload . "\npop graphic-context";
                        $mvgPathWithViewbox = $uploadDir . '/payload_viewbox_' . uniqid() . '.mvg';
                        file_put_contents($mvgPathWithViewbox, $mvgWithViewbox);
                        $allOutput[] = "Added viewbox to MVG (required for proper parsing)";
                        $mvgPath = $mvgPathWithViewbox;
                    }
                    
                    $cmd = 'convert "mvg:' . $mvgPath . '" ' . escapeshellarg($renderPath) . ' 2>&1';
                    $allOutput[] = "Command: " . $cmd;
                    $output = [];
                    $ret = 0;
                    exec($cmd, $output, $ret);
                    $allOutput[] = "Exit code: " . $ret;
                    $allOutput[] = "Output:";
                    $allOutput = array_merge($allOutput, $output);
                    if ($ret === 0) {
                        $allOutput[] = "✓ SUCCESS: File converted (delegate/RCE may have executed!)";
                    } else {
                        $allOutput[] = "⚠ Convert returned non-zero exit code (but delegate may still have executed!)";
                    }
                    $allOutput[] = "";
                    
                    // Also try direct MVG file
                    $allOutput[] = "=== STEP 3: Execute convert with direct MVG file ===";
                    $mvgInline = $uploadDir . '/inline_' . uniqid() . '.mvg';
                    if (!$hasViewbox && !$usesUrl) {
                        file_put_contents($mvgInline, $mvgWithViewbox);
                    } else {
                        file_put_contents($mvgInline, $mvgPayload);
                    }
                    $allOutput[] = "MVG file written to: " . $mvgInline;
                    $cmd2 = 'convert "' . $mvgInline . '" ' . escapeshellarg($uploadDir . '/rendered2_' . $origName . '.png') . ' 2>&1';
                    $allOutput[] = "Command: " . $cmd2;
                    $output2 = [];
                    $ret2 = 0;
                    exec($cmd2, $output2, $ret2);
                    $allOutput[] = "Exit code: " . $ret2;
                    $allOutput[] = "Output:";
                    $allOutput = array_merge($allOutput, $output2);
                    if ($ret2 === 0) {
                        $allOutput[] = "✓ SUCCESS: File converted (delegate/RCE may have executed!)";
                    } else {
                        $allOutput[] = "⚠ Convert returned non-zero exit code (but delegate may still have executed!)";
                    }
                    $allOutput[] = "";
                    
                    // If payload uses url(), also try to extract and test the URL directly
                    if ($usesUrl && preg_match('/url\(([^)]+)\)/', $mvgPayload, $urlMatches)) {
                        $urlFromMvg = trim($urlMatches[1], '"\'');
                        $allOutput[] = "=== STEP 3b: Test extracted URL from url() delegate ===";
                        $allOutput[] = "Extracted URL: " . $urlFromMvg;
                        
                        // Try https: protocol
                        $renderPathUrl = $uploadDir . '/rendered_url_' . $origName . '.png';
                        $cmdUrl = 'convert "https:' . $urlFromMvg . '" ' . escapeshellarg($renderPathUrl) . ' 2>&1';
                        $allOutput[] = "Command: " . $cmdUrl;
                        $outputUrl = [];
                        $retUrl = 0;
                        exec($cmdUrl, $outputUrl, $retUrl);
                        $allOutput[] = "Exit code: " . $retUrl;
                        $allOutput[] = "Output:";
                        $allOutput = array_merge($allOutput, $outputUrl);
                        $allOutput[] = "";
                        
                        // Try http: protocol
                        $httpUrl = str_replace('https://', 'http://', $urlFromMvg);
                        $cmdUrl2 = 'convert "http:' . $httpUrl . '" ' . escapeshellarg($uploadDir . '/rendered_url2_' . $origName . '.png') . ' 2>&1';
                        $allOutput[] = "Command: " . $cmdUrl2;
                        $outputUrl2 = [];
                        $retUrl2 = 0;
                        exec($cmdUrl2, $outputUrl2, $retUrl2);
                        $allOutput[] = "Exit code: " . $retUrl2;
                        $allOutput[] = "Output:";
                        $allOutput = array_merge($allOutput, $outputUrl2);
                        $allOutput[] = "";
                    }
                } else {
                    $allOutput[] = "✗ FAILED: Could not write MVG file to " . $mvgPath;
                    $allOutput[] = "";
                }
            }
            
            // Look for XMP XXE/SSRF payload
            if (preg_match('/XML:com\.adobe\.xmp\x00\x00([^\x00]+)/', $pngData, $xmpMatches)) {
                $xmpPayload = $xmpMatches[1];
                $xmpFound = true;
                $allOutput[] = "✓ XMP payload found in iTXt chunk (XML:com.adobe.xmp keyword)!";
                $allOutput[] = "Payload length: " . strlen($xmpPayload) . " bytes";
                $allOutput[] = "Payload preview (first 200 chars): " . substr($xmpPayload, 0, 200);
                
                // Test XMP XXE - Multiple techniques
                $allOutput[] = "";
                $allOutput[] = "=== STEP 1b: Test XMP XXE payload (multiple techniques) ===";
                $xmpPath = $uploadDir . '/xmp_' . uniqid() . '.xml';
                file_put_contents($xmpPath, $xmpPayload);
                $allOutput[] = "✓ XMP file written to: " . $xmpPath;
                $allOutput[] = "";
                
                // Technique 1: convert with -format "%[xmp:*]"
                $allOutput[] = "--- Technique 1: convert -format \"%[xmp:*]\" ---";
                $cmdXmp1 = 'convert ' . escapeshellarg($targetPath) . ' -format "%[xmp:*]" ' . escapeshellarg($uploadDir . '/xmp_output1_' . $origName . '.txt') . ' 2>&1';
                $allOutput[] = "Command: " . $cmdXmp1;
                $outputXmp1 = [];
                $retXmp1 = 0;
                exec($cmdXmp1, $outputXmp1, $retXmp1);
                $allOutput[] = "Exit code: " . $retXmp1;
                $allOutput[] = "Output:";
                $allOutput = array_merge($allOutput, $outputXmp1);
                $allOutput[] = "";
                
                // Technique 2: identify -verbose (should parse XMP)
                $allOutput[] = "--- Technique 2: identify -verbose (full XMP parsing) ---";
                $cmdXmp2 = 'identify -verbose ' . escapeshellarg($targetPath) . ' 2>&1';
                $allOutput[] = "Command: " . $cmdXmp2;
                $outputXmp2 = [];
                $retXmp2 = 0;
                exec($cmdXmp2, $outputXmp2, $retXmp2);
                $allOutput[] = "Exit code: " . $retXmp2;
                $allOutput[] = "Output (first 50 lines):";
                $allOutput = array_merge($allOutput, array_slice($outputXmp2, 0, 50));
                $allOutput[] = "";
                
                // Technique 3: convert with -set xmp:* (may trigger parsing)
                $allOutput[] = "--- Technique 3: convert -set xmp:* (force XMP processing) ---";
                $cmdXmp3 = 'convert ' . escapeshellarg($targetPath) . ' -set xmp:test "test" ' . escapeshellarg($uploadDir . '/xmp_output3_' . $origName . '.png') . ' 2>&1';
                $allOutput[] = "Command: " . $cmdXmp3;
                $outputXmp3 = [];
                $retXmp3 = 0;
                exec($cmdXmp3, $outputXmp3, $retXmp3);
                $allOutput[] = "Exit code: " . $retXmp3;
                $allOutput[] = "Output:";
                $allOutput = array_merge($allOutput, $outputXmp3);
                $allOutput[] = "";
                
                // Technique 4: convert to SVG (may parse XMP during conversion)
                $allOutput[] = "--- Technique 4: convert to SVG (XMP may be parsed) ---";
                $cmdXmp4 = 'convert ' . escapeshellarg($targetPath) . ' ' . escapeshellarg($uploadDir . '/xmp_output4_' . $origName . '.svg') . ' 2>&1';
                $allOutput[] = "Command: " . $cmdXmp4;
                $outputXmp4 = [];
                $retXmp4 = 0;
                exec($cmdXmp4, $outputXmp4, $retXmp4);
                $allOutput[] = "Exit code: " . $retXmp4;
                $allOutput[] = "Output:";
                $allOutput = array_merge($allOutput, $outputXmp4);
                $allOutput[] = "";
                
                // Technique 5: convert to PDF (may parse XMP)
                $allOutput[] = "--- Technique 5: convert to PDF (XMP may be parsed) ---";
                $cmdXmp5 = 'convert ' . escapeshellarg($targetPath) . ' ' . escapeshellarg($uploadDir . '/xmp_output5_' . $origName . '.pdf') . ' 2>&1';
                $allOutput[] = "Command: " . $cmdXmp5;
                $outputXmp5 = [];
                $retXmp5 = 0;
                exec($cmdXmp5, $outputXmp5, $retXmp5);
                $allOutput[] = "Exit code: " . $retXmp5;
                $allOutput[] = "Output:";
                $allOutput = array_merge($allOutput, $outputXmp5);
                $allOutput[] = "";
                
                // Technique 6: Extract XMP as separate file and process
                $allOutput[] = "--- Technique 6: Extract XMP chunk and process separately ---";
                $xmpExtracted = $uploadDir . '/xmp_extracted_' . uniqid() . '.xml';
                // Wrap XMP payload in proper XMP structure
                $xmpWrapped = '<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>' . "\n" . $xmpPayload . "\n" . '<?xpacket end="w"?>';
                file_put_contents($xmpExtracted, $xmpWrapped);
                $allOutput[] = "✓ Wrapped XMP file written to: " . $xmpExtracted;
                $cmdXmp6 = 'convert ' . escapeshellarg($xmpExtracted) . ' ' . escapeshellarg($uploadDir . '/xmp_output6_' . $origName . '.png') . ' 2>&1';
                $allOutput[] = "Command: " . $cmdXmp6;
                $outputXmp6 = [];
                $retXmp6 = 0;
                exec($cmdXmp6, $outputXmp6, $retXmp6);
                $allOutput[] = "Exit code: " . $retXmp6;
                $allOutput[] = "Output:";
                $allOutput = array_merge($allOutput, $outputXmp6);
                $allOutput[] = "";
                
                // Technique 7: Use mogrify (may process XMP differently)
                $allOutput[] = "--- Technique 7: mogrify (alternative processor) ---";
                $targetPathCopy = $uploadDir . '/copy_' . $origName;
                copy($targetPath, $targetPathCopy);
                $cmdXmp7 = 'mogrify -format png ' . escapeshellarg($targetPathCopy) . ' 2>&1';
                $allOutput[] = "Command: " . $cmdXmp7;
                $outputXmp7 = [];
                $retXmp7 = 0;
                exec($cmdXmp7, $outputXmp7, $retXmp7);
                $allOutput[] = "Exit code: " . $retXmp7;
                $allOutput[] = "Output:";
                $allOutput = array_merge($allOutput, $outputXmp7);
                $allOutput[] = "";
                
                // Technique 8: convert with -strip (may parse XMP before stripping)
                $allOutput[] = "--- Technique 8: convert -strip (parse XMP before stripping) ---";
                $cmdXmp8 = 'convert ' . escapeshellarg($targetPath) . ' -strip ' . escapeshellarg($uploadDir . '/xmp_output8_' . $origName . '.png') . ' 2>&1';
                $allOutput[] = "Command: " . $cmdXmp8;
                $outputXmp8 = [];
                $retXmp8 = 0;
                exec($cmdXmp8, $outputXmp8, $retXmp8);
                $allOutput[] = "Exit code: " . $retXmp8;
                $allOutput[] = "Output:";
                $allOutput = array_merge($allOutput, $outputXmp8);
                $allOutput[] = "";
                
                // Technique 9: convert with -profile (may trigger XMP parsing)
                $allOutput[] = "--- Technique 9: convert -profile (XMP profile processing) ---";
                $cmdXmp9 = 'convert ' . escapeshellarg($targetPath) . ' -profile sRGB.icc ' . escapeshellarg($uploadDir . '/xmp_output9_' . $origName . '.png') . ' 2>&1';
                $allOutput[] = "Command: " . $cmdXmp9;
                $outputXmp9 = [];
                $retXmp9 = 0;
                exec($cmdXmp9, $outputXmp9, $retXmp9);
                $allOutput[] = "Exit code: " . $retXmp9;
                $allOutput[] = "Output:";
                $allOutput = array_merge($allOutput, $outputXmp9);
                $allOutput[] = "";
                
                // Technique 10: convert with -comment (may read XMP)
                $allOutput[] = "--- Technique 10: convert -comment (may read XMP metadata) ---";
                $cmdXmp10 = 'convert ' . escapeshellarg($targetPath) . ' -comment "%[xmp:*]" ' . escapeshellarg($uploadDir . '/xmp_output10_' . $origName . '.png') . ' 2>&1';
                $allOutput[] = "Command: " . $cmdXmp10;
                $outputXmp10 = [];
                $retXmp10 = 0;
                exec($cmdXmp10, $outputXmp10, $retXmp10);
                $allOutput[] = "Exit code: " . $retXmp10;
                $allOutput[] = "Output:";
                $allOutput = array_merge($allOutput, $outputXmp10);
                $allOutput[] = "";
                
                // Technique 11: Try exiftool (if available) - exiftool actually parses XMP as XML
                $allOutput[] = "--- Technique 11: exiftool (if available - actually parses XMP as XML) ---";
                $exiftoolPath = trim(shell_exec('which exiftool 2>/dev/null'));
                if (!empty($exiftoolPath)) {
                    $allOutput[] = "✓ exiftool found at: " . $exiftoolPath;
                    $cmdXmp11 = 'exiftool ' . escapeshellarg($targetPath) . ' 2>&1';
                    $allOutput[] = "Command: " . $cmdXmp11;
                    $outputXmp11 = [];
                    $retXmp11 = 0;
                    exec($cmdXmp11, $outputXmp11, $retXmp11);
                    $allOutput[] = "Exit code: " . $retXmp11;
                    $allOutput[] = "Output (first 30 lines):";
                    $allOutput = array_merge($allOutput, array_slice($outputXmp11, 0, 30));
                    $allOutput[] = "";
                    
                    // Also try exiftool with -XMP:all
                    $cmdXmp11b = 'exiftool -XMP:all ' . escapeshellarg($targetPath) . ' 2>&1';
                    $allOutput[] = "Command: " . $cmdXmp11b;
                    $outputXmp11b = [];
                    $retXmp11b = 0;
                    exec($cmdXmp11b, $outputXmp11b, $retXmp11b);
                    $allOutput[] = "Exit code: " . $retXmp11b;
                    $allOutput[] = "Output:";
                    $allOutput = array_merge($allOutput, $outputXmp11b);
                    $allOutput[] = "";
                } else {
                    $allOutput[] = "⚠ exiftool not found (exiftool actually parses XMP as XML, which is needed for XXE)";
                    $allOutput[] = "  ImageMagick does NOT parse XMP content as XML, so XXE via XMP won't work with ImageMagick alone";
                    $allOutput[] = "";
                }
                
                // Technique 12: Parse XMP with PHP XML parser (VULNERABLE TO XXE!)
                $allOutput[] = "--- Technique 12: PHP XML Parser (VULNERABLE TO XXE!) ---";
                $allOutput[] = "⚠ This uses PHP's native XML parser which IS vulnerable to XXE";
                $allOutput[] = "  Parsing XMP payload with PHP SimpleXML/DOMDocument...";
                $allOutput[] = "";
                
                // Wrap XMP in proper XML structure for parsing
                $xmpForParsing = '<?xml version="1.0"?>' . "\n" . $xmpPayload;
                
                // Test with SimpleXML (vulnerable to XXE if libxml_disable_entity_loader is not called)
                $allOutput[] = "Test 12a: SimpleXML (libxml_disable_entity_loader disabled = VULNERABLE)";
                libxml_disable_entity_loader(false); // Enable external entity loading (VULNERABLE!)
                libxml_use_internal_errors(true);
                try {
                    $xml = simplexml_load_string($xmpForParsing, 'SimpleXMLElement', LIBXML_NOENT);
                    if ($xml !== false) {
                        $allOutput[] = "✓ SimpleXML parsed successfully (XXE may have been triggered!)";
                        $allOutput[] = "XML content: " . $xml->asXML();
                    } else {
                        $allOutput[] = "✗ SimpleXML parsing failed";
                        $errors = libxml_get_errors();
                        foreach ($errors as $error) {
                            $allOutput[] = "  Error: " . trim($error->message);
                        }
                    }
                } catch (Exception $e) {
                    $allOutput[] = "Exception: " . $e->getMessage();
                }
                $allOutput[] = "";
                
                // Test with DOMDocument (vulnerable to XXE)
                $allOutput[] = "Test 12b: DOMDocument (LIBXML_NOENT = VULNERABLE)";
                libxml_use_internal_errors(true);
                try {
                    $dom = new DOMDocument();
                    $dom->loadXML($xmpForParsing, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);
                    $allOutput[] = "✓ DOMDocument parsed successfully (XXE may have been triggered!)";
                    $allOutput[] = "XML content: " . $dom->saveXML();
                } catch (Exception $e) {
                    $allOutput[] = "Exception: " . $e->getMessage();
                }
                $allOutput[] = "";
                
                // Test with XMLReader (vulnerable to XXE)
                $allOutput[] = "Test 12c: XMLReader (LIBXML_NOENT = VULNERABLE)";
                try {
                    $reader = new XMLReader();
                    $reader->open('data://text/plain;base64,' . base64_encode($xmpForParsing), null, LIBXML_NOENT | LIBXML_DTDLOAD);
                    $allOutput[] = "✓ XMLReader opened (XXE may have been triggered during parsing!)";
                    while ($reader->read()) {
                        // Read through the document to trigger parsing
                    }
                    $reader->close();
                } catch (Exception $e) {
                    $allOutput[] = "Exception: " . $e->getMessage();
                }
                $allOutput[] = "";
                
                // Important note about XXE with ImageMagick
                $allOutput[] = "=== IMPORTANT NOTE ABOUT XXE VIA XMP ===";
                $allOutput[] = "⚠ ImageMagick does NOT parse XMP metadata as XML with a vulnerable XML parser";
                $allOutput[] = "  - ImageMagick reads XMP metadata but doesn't parse it as XML";
                $allOutput[] = "  - XXE requires an XML parser that processes DOCTYPE and ENTITY declarations";
                $allOutput[] = "  - For XXE to work, you need tools like exiftool, libexif, or PHP XML parsers";
                $allOutput[] = "  - ImageMagick is vulnerable to RCE via delegates (ImageTragick), not XXE via XMP";
                $allOutput[] = "  - The XMP payloads WILL trigger XXE with PHP XML parsers (SimpleXML, DOMDocument, XMLReader)";
                $allOutput[] = "";
            }
            
            if (!$mvgFound && !$xmpFound) {
                $allOutput[] = "✗ FAILED: No 'ImageMagick' or 'XML:com.adobe.xmp' iTXt chunk found in PNG";
                $allOutput[] = "Searching for patterns: ImageMagick\\x00\\x00 or XML:com.adobe.xmp\\x00\\x00";
                $allOutput[] = "PNG contains iTXt chunks: " . (strpos($pngData, 'iTXt') !== false ? 'YES' : 'NO');
                if (strpos($pngData, 'ImageMagick') !== false) {
                    $allOutput[] = "Note: 'ImageMagick' string found but not in expected format";
                }
                if (strpos($pngData, 'XML:com.adobe.xmp') !== false) {
                    $allOutput[] = "Note: 'XML:com.adobe.xmp' string found but not in expected format";
                }
                $allOutput[] = "";
            }
            
            // Method 2: Extract and test as SVG (for delegate-based payloads)
            $allOutput[] = "=== STEP 4: Extract and test as SVG (delegate-based payload) ===";
            if ($mvgFound && (strpos($mvgPayload, '<svg') !== false || strpos($mvgPayload, 'xlink:href') !== false)) {
                $allOutput[] = "Payload appears to be SVG (contains <svg> or xlink:href)";
                $svgPath = $uploadDir . '/payload_' . uniqid() . '.svg';
                file_put_contents($svgPath, $mvgPayload);
                $allOutput[] = "✓ SVG file written to: " . $svgPath;
                
                // Test 1: Convert SVG directly (should trigger delegate for xlink:href)
                $allOutput[] = "";
                $allOutput[] = "--- Test 4a: Convert SVG file (should trigger delegate for xlink:href) ---";
                $renderPathSvg = $uploadDir . '/rendered_svg_' . $origName . '.png';
                $cmdSvg = 'convert ' . escapeshellarg($svgPath) . ' ' . escapeshellarg($renderPathSvg) . ' 2>&1';
                $allOutput[] = "Command: " . $cmdSvg;
                $outputSvg = [];
                $retSvg = 0;
                exec($cmdSvg, $outputSvg, $retSvg);
                $allOutput[] = "Exit code: " . $retSvg;
                $allOutput[] = "Output:";
                $allOutput = array_merge($allOutput, $outputSvg);
                if ($retSvg === 0) {
                    $allOutput[] = "✓ SUCCESS: SVG converted (delegate may have been triggered!)";
                } else {
                    $allOutput[] = "✗ FAILED: Convert returned non-zero exit code";
                }
                $allOutput[] = "";
                
                // Test 2: Use SVG protocol
                $allOutput[] = "--- Test 4b: Convert with SVG protocol (svg:file.svg) ---";
                $renderPathSvg2 = $uploadDir . '/rendered_svg2_' . $origName . '.png';
                $cmdSvg2 = 'convert "svg:' . $svgPath . '" ' . escapeshellarg($renderPathSvg2) . ' 2>&1';
                $allOutput[] = "Command: " . $cmdSvg2;
                $outputSvg2 = [];
                $retSvg2 = 0;
                exec($cmdSvg2, $outputSvg2, $retSvg2);
                $allOutput[] = "Exit code: " . $retSvg2;
                $allOutput[] = "Output:";
                $allOutput = array_merge($allOutput, $outputSvg2);
                $allOutput[] = "";
                
                // Test 3: Extract URL from xlink:href and test delegate directly
                if (preg_match('/xlink:href=["\']([^"\']+)["\']/', $mvgPayload, $urlMatches)) {
                    $delegateUrl = $urlMatches[1];
                    $allOutput[] = "--- Test 4c: Test delegate directly with extracted URL ---";
                    $allOutput[] = "Extracted URL from xlink:href: " . $delegateUrl;
                    
                    // Try https: protocol (should trigger delegate)
                    $renderPathDelegate = $uploadDir . '/rendered_delegate_' . $origName . '.png';
                    $cmdDelegate = 'convert "https:' . $delegateUrl . '" ' . escapeshellarg($renderPathDelegate) . ' 2>&1';
                    $allOutput[] = "Command: " . $cmdDelegate;
                    $outputDelegate = [];
                    $retDelegate = 0;
                    exec($cmdDelegate, $outputDelegate, $retDelegate);
                    $allOutput[] = "Exit code: " . $retDelegate;
                    $allOutput[] = "Output:";
                    $allOutput = array_merge($allOutput, $outputDelegate);
                    $allOutput[] = "";
                    
                    // Try http: protocol
                    $httpUrl = str_replace('https://', 'http://', $delegateUrl);
                    $cmdDelegate2 = 'convert "http:' . $httpUrl . '" ' . escapeshellarg($uploadDir . '/rendered_delegate2_' . $origName . '.png') . ' 2>&1';
                    $allOutput[] = "Command: " . $cmdDelegate2;
                    $outputDelegate2 = [];
                    $retDelegate2 = 0;
                    exec($cmdDelegate2, $outputDelegate2, $retDelegate2);
                    $allOutput[] = "Exit code: " . $retDelegate2;
                    $allOutput[] = "Output:";
                    $allOutput = array_merge($allOutput, $outputDelegate2);
                    $allOutput[] = "";
                }
            } else {
                $allOutput[] = "Payload is not SVG format (no <svg> or xlink:href found)";
                $allOutput[] = "";
            }
            
            // Method 3: Use identify with vulnerable format string
            $allOutput[] = "=== STEP 5: Try identify command (may trigger delegates) ===";
            $cmd3 = 'identify -format "%[filename]" ' . escapeshellarg($targetPath) . ' 2>&1';
            $allOutput[] = "Command: " . $cmd3;
            $output3 = [];
            $ret3 = 0;
            exec($cmd3, $output3, $ret3);
            $allOutput[] = "Exit code: " . $ret3;
            $allOutput[] = "Output:";
            $allOutput = array_merge($allOutput, $output3);
            $allOutput[] = "";
            
            // Method 4: Standard convert (may trigger on some formats)
            $allOutput[] = "=== STEP 6: Standard convert (baseline test) ===";
            $renderPath3 = $uploadDir . '/rendered3_' . $origName . '.png';
            $cmd4 = 'convert ' . escapeshellarg($targetPath) . ' ' . escapeshellarg($renderPath3) . ' 2>&1';
            $allOutput[] = "Command: " . $cmd4;
            $output4 = [];
            $ret4 = 0;
            exec($cmd4, $output4, $ret4);
            $allOutput[] = "Exit code: " . $ret4;
            $allOutput[] = "Output:";
            $allOutput = array_merge($allOutput, $output4);
            $allOutput[] = "";
            
            // Diagnostic info
            $allOutput[] = "=== DIAGNOSTIC INFO ===";
            $allOutput[] = "ImageMagick version:";
            exec('convert -version 2>&1', $versionOutput, $versionRet);
            $allOutput = array_merge($allOutput, $versionOutput);
            $allOutput[] = "";
            $allOutput[] = "Policy.xml locations checked:";
            $policyPaths = ['/usr/local/etc/ImageMagick-6/policy.xml', '/etc/ImageMagick-6/policy.xml', '/etc/ImageMagick/policy.xml'];
            foreach ($policyPaths as $policyPath) {
                $allOutput[] = "  " . $policyPath . ": " . (file_exists($policyPath) ? "EXISTS (should be removed!)" : "NOT FOUND (good)");
            }
            $allOutput[] = "";
            $allOutput[] = "=== SUMMARY ===";
            if ($mvgFound) {
                $allOutput[] = "✓ MVG payload extracted successfully";
                $allOutput[] = "⚠ If RCE didn't trigger, check:";
                $allOutput[] = "  1. ImageMagick version (should be 6.9.3-10 or older)";
                $allOutput[] = "  2. Policy.xml files (should be removed)";
                $allOutput[] = "  3. Delegates configuration (should allow dangerous protocols)";
            } else {
                $allOutput[] = "✗ No MVG payload found in PNG iTXt chunk";
                $allOutput[] = "  The PNG may not contain the expected ImageTragick payload structure";
            }

            $message = "Saved as: {$targetPath}<br><pre>" .
                htmlspecialchars(implode("\n", $allOutput), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') .
                '</pre>';
        }
    }
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Vuln Image Lab – PHP + ImageMagick</title>
    <style>
        body { font-family: sans-serif; margin: 2rem; }
        .container { max-width: 640px; margin: 0 auto; }
        .box { border: 1px solid #ccc; padding: 1rem 1.5rem; border-radius: 6px; }
        .message { margin-top: 1rem; padding: 0.75rem; background: #f5f5f5; border-radius: 4px; }
        input[type=file] { margin-top: 0.5rem; }
        button { margin-top: 1rem; padding: 0.5rem 1rem; }
        code { background: #eee; padding: 0.1rem 0.3rem; border-radius: 3px; }
    </style>
</head>
<body>
<div class="container">
    <h1>Vuln Image Lab – PHP + ImageMagick</h1>
    <div class="box">
        <p>
            This demo is intentionally vulnerable: it uploads an image
            (<code>.png</code>, <code>.jpg</code>, <code>.jpeg</code>) and calls
            <code>convert</code> (ImageMagick) on it server‑side.
        </p>
        <form method="post" enctype="multipart/form-data">
            <label>
                Choose image:
                <input type="file" name="file" accept=".png,.jpg,.jpeg,image/png,image/jpeg">
            </label>
            <br>
            <button type="submit">Upload &amp; render with ImageMagick</button>
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


