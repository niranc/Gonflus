# Detailed WEBM Techniques

## OOB Read/Write (Out-of-Bounds)
1. **Chunk size overflow** - EBML chunk with invalid size - libvpx, libwebm, Chrome, Firefox - CVE-2023-5217, CVE-2023-4863
2. **VP8 frame overflow** - Malformed VP8 frame data - libvpx parsers - CVE-2018-1000116
3. **Matroska segment overflow** - Invalid segment size in Matroska container - libwebm, FFmpeg - CVE-2019-11470

## Heap Buffer Overflow
1. **Superframe VP9 malformed** - Invalid VP9 superframe structure - libvpx - CVE-2023-5217 (exploited in-the-wild)
2. **Corrupted Huffman table** - Corrupted WebP Huffman table in WEBM - libwebp - CVE-2023-4863 (BLASTPASS Pegasus)
3. **Invalid chunk size** - Invalid chunk size causing heap overflow - All WEBM parsers - Multiple CVEs

## Use-After-Free
1. **Double-free** - Double-free in libvpx/libwebm - libvpx, Chrome - CVE-2020-6418, CVE-2024-38365
2. **Premature free** - Premature free in VP8/VP9 decoder - libvpx, Firefox - CVE-2020-6418

## Integer Overflow / Underflow
1. **Width overflow** - Width value > 2³² causing integer overflow - All WEBM parsers - CVE-2023-44488
2. **Height overflow** - Height value > 2³² causing integer overflow - All WEBM parsers - CVE-2023-44488
3. **Frame size overflow** - Frame size > 2³² leading to OOB - libvpx, libwebm - CVE-2017-0641
4. **Timestamp overflow** - Timestamp > 2⁶⁴ causing integer overflow - Matroska parsers - CVE-2023-44488

## RCE (Remote Code Execution)
1. **CVE-2023-5217 (libvpx)** - Heap buffer overflow in VP8/VP9 decoder - Chrome, Firefox, Telegram - Zero-click possible
2. **CVE-2023-4863 (libwebp)** - Heap buffer overflow in WebP decoder - Chrome, Firefox, iOS - BLASTPASS Pegasus exploit
3. **BLASTPASS exploit chain** - Combination of heap overflow + UAF - iOS, Chrome - Zero-click RCE

## DoS / Crash
1. **Invalid chunk** - Malformed EBML chunk causing immediate segfault - All parsers - Very easy to trigger
2. **Malformed EBML header** - Invalid EBML header structure - All parsers - Immediate crash
3. **Corrupted header** - Corrupted Matroska/WEBM header - FFmpeg, libwebm - Crash on parse
4. **Segfault trigger** - Specific byte pattern causing segfault - libvpx, Chrome - CVE-2018-1000116

## Information Leak
1. **OOB read** - Out-of-bounds read leaking heap addresses - libvpx, Chrome - CVE-2018-1000116
2. **Heap leak** - Heap memory leak via malformed chunk - All parsers - Information disclosure

**Note**: WEBM is based on the binary EBML/Matroska format. Vulnerabilities are mainly related to binary parsing (heap overflow, OOB, UAF) and not classic web vulnerabilities (XXE, SSRF, XSS). Exploits are often used in-the-wild (zero-click RCE).

