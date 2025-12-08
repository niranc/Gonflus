# Detailed MP4 Techniques

## RCE (Remote Code Execution)
1. **CVE-2019-2107 (Android MediaCodec)** - RCE via H.264 tiles overflow - Android MediaCodec, WhatsApp - Exploited in-the-wild (WhatsApp 2019)
2. **CVE-2023-20069 (FFmpeg)** - Heap buffer overflow in MP4 parser - FFmpeg, GStreamer - RCE via OOB chain
3. **CVE-2024-30194 (Integer overflow → RCE)** - Integer overflow leading to RCE - FFmpeg, MediaCodec - Zero-click possible

## OOB Read/Write (Out-of-Bounds)
1. **moov atom size overflow** - Invalid moov atom size causing OOB - FFmpeg, MediaCodec, GStreamer - CVE-2024-47537, CVE-2018-13302
2. **stsd/trak overflow** - Malformed stsd/trak atoms causing OOB read/write - All MP4 parsers - CVE-2023-20069
3. **mov_read_dref OOB** - OOB read in mov_read_dref function - FFmpeg - CVE-2018-13302

## Heap Buffer Overflow
1. **stsd/trak overflow** - Invalid stsd/trak atom size causing heap overflow - FFmpeg, MediaCodec - CVE-2024-30194
2. **H.264 tiles overflow** - Malformed H.264 tiles in MP4 - Android MediaCodec - CVE-2019-2107
3. **Atom size invalid** - Invalid atom size causing heap overflow - All MP4 parsers - Multiple CVEs

## Use-After-Free (UAF)
1. **Double-free in mov.c** - Double-free in MP4 mov parser - FFmpeg - CVE-2024-30194
2. **Premature free** - Premature memory free in MP4 decoder - MediaCodec, FFmpeg - HackerOne reports

## Integer Overflow / Underflow
1. **Atom size overflow** - Atom size > 2³² causing integer overflow - All MP4 parsers - CVE-2024-30194, CVE-2018-13302
2. **Width/height overflow** - Width/height values > 2³² - All MP4 parsers - CVE-2024-30194
3. **Allocation negative** - Integer overflow leading to negative allocation - FFmpeg - CVE-2024-30194

## DoS / Crash
1. **Invalid atom** - Malformed atom causing immediate segfault - All parsers - Very easy to trigger
2. **Malformed ftyp** - Invalid ftyp atom structure - All parsers - Immediate crash
3. **Corrupted moov** - Corrupted moov atom header - FFmpeg, MediaCodec - Crash on parse
4. **Segfault trigger** - Specific byte pattern causing segfault - All parsers - CVE-2019-11931 (WhatsApp)

## Information Leak
1. **OOB read** - Out-of-bounds read leaking heap addresses - FFmpeg, MediaCodec - CVE-2018-13302
2. **Heap leak** - Heap memory leak via malformed atom - All parsers - Information disclosure
3. **Memory disclosure** - Memory disclosure via corrupted atoms - NGINX MP4 module - CVE-2022-41742

## SSRF (Server-Side Request Forgery) - Indirect
1. **Thumbnailer metadata** - MP4 metadata with remote URL fetched by thumbnailer - XFCE Tumbler, thumbnailers - CVE-2022-31094 (GPAC)
2. **XFCE Tumbler** - XFCE Tumbler fetching cover art from remote URL - XFCE Tumbler - GitHub issues

## XSS (Cross-Site Scripting) - Indirect
1. **Video embed** - Embedding MP4 with script in metadata - Video.js, browsers - CVE-2021-23414
2. **Track src bypass** - Track src with javascript: protocol - Video.js - CVE-2021-23414

**Note**: MP4 uses binary format based on "atoms" (boxes). Vulnerabilities are mainly in binary parsing (heap overflow, OOB, UAF, integer overflow) leading to RCE. Exploits are often used in-the-wild (WhatsApp 2019, BLASTPASS). Indirect SSRF and XSS are possible through thumbnailers or web parsers, but not directly in pure MP4 format.

