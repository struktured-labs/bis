#!/usr/bin/env python3
"""Decrypt a 3DS CIA file using its embedded title key."""
import struct
import sys
from pathlib import Path
from Crypto.Cipher import AES

def align(n, alignment):
    return (n + alignment - 1) & ~(alignment - 1)

def main():
    cia_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else cia_path.replace('.cia', '_decrypted.cia')

    data = bytearray(Path(cia_path).read_bytes())
    print(f"Input: {cia_path} ({len(data)} bytes)")

    # Parse CIA header
    header_size = struct.unpack_from('<I', data, 0x00)[0]
    cert_size = struct.unpack_from('<I', data, 0x08)[0]
    tik_size = struct.unpack_from('<I', data, 0x0C)[0]
    tmd_size = struct.unpack_from('<I', data, 0x10)[0]
    meta_size = struct.unpack_from('<I', data, 0x14)[0]
    content_size = struct.unpack_from('<Q', data, 0x18)[0]

    print(f"Header: {header_size}, Certs: {cert_size}, Tik: {tik_size}, TMD: {tmd_size}")
    print(f"Content: {content_size}, Meta/Footer: {meta_size}")

    # Calculate offsets (each section aligned to 64 bytes)
    cert_offset = align(header_size, 64)
    tik_offset = cert_offset + align(cert_size, 64)
    tmd_offset = tik_offset + align(tik_size, 64)
    content_offset = tmd_offset + align(tmd_size, 64)
    meta_offset = content_offset + align(content_size, 64)

    print(f"Content starts at: 0x{content_offset:X}")

    # Extract encrypted title key from ticket (offset 0x7F in ticket)
    enc_titlekey = bytes(data[tik_offset + 0x1BF : tik_offset + 0x1CF])
    # Common key index (offset 0xB1 in ticket)
    key_index = data[tik_offset + 0x1F1]
    # Title ID from ticket (offset 0x9C in ticket)
    title_id = bytes(data[tik_offset + 0x1DC : tik_offset + 0x1E4])

    print(f"Encrypted title key: {enc_titlekey.hex()}")
    print(f"Title ID: {title_id.hex()}")
    print(f"Key index: {key_index}")

    # 3DS common keys (retail)
    common_keys = {
        0: bytes.fromhex('64C5FD55DD3AD988325BAAEC5243DB98'),  # Normal
        1: bytes.fromhex('4AAA3D0E27D4D728D0B1B433F0F9CBC8'),  # Korean
        2: bytes.fromhex('FBB0EF8CDBB0D8E453CD99344371697F'),  # Unknown
    }

    # Check if we have a valid common key
    if key_index in common_keys:
        common_key = common_keys[key_index]
        # Decrypt title key: AES-128-CBC with common key, IV = title_id + 8 zero bytes
        iv = title_id + b'\x00' * 8
        cipher = AES.new(common_key, AES.MODE_CBC, iv)
        titlekey = cipher.decrypt(enc_titlekey)
        print(f"Decrypted title key: {titlekey.hex()}")
    else:
        # Use the known decrypted key directly
        titlekey = bytes.fromhex('3334E5CF346B88187EEC36C789DEEA4F')
        print(f"Using known title key: {titlekey.hex()}")

    # Parse TMD to find content info
    # TMD signature is at tmd_offset, then TMD header
    # Content count is at TMD header + 0x9E (after sig)
    tmd_sig_size = 0x100 + 0x3C  # RSA-2048 + padding
    tmd_header = tmd_offset + 4 + tmd_sig_size  # 4 bytes sig type + sig
    content_count = struct.unpack_from('>H', data, tmd_header + 0x9E)[0]
    print(f"Content count: {content_count}")

    # Content info records start at TMD header + 0x9C4
    content_info_offset = tmd_header + 0x9C4

    # Decrypt each content
    cur_content_offset = content_offset
    for i in range(content_count):
        ci_off = content_info_offset + i * 0x30
        content_id = struct.unpack_from('>I', data, ci_off + 0x00)[0]
        content_index = struct.unpack_from('>H', data, ci_off + 0x04)[0]
        content_type = struct.unpack_from('>H', data, ci_off + 0x06)[0]
        c_size = struct.unpack_from('>Q', data, ci_off + 0x08)[0]

        is_encrypted = (content_type & 1) != 0
        print(f"\nContent {i}: id=0x{content_id:08X} index=0x{content_index:04X} "
              f"type=0x{content_type:04X} size={c_size} encrypted={is_encrypted}")

        if is_encrypted and c_size > 0:
            # Decrypt: AES-128-CBC, key=titlekey, IV=content_index (big-endian, padded to 16)
            iv = struct.pack('>H', content_index) + b'\x00' * 14
            # Content size must be aligned to 16 for AES
            aligned_size = align(c_size, 16)
            enc_data = bytes(data[cur_content_offset : cur_content_offset + aligned_size])
            cipher = AES.new(titlekey, AES.MODE_CBC, iv)
            dec_data = cipher.decrypt(enc_data)
            # Write back decrypted data
            data[cur_content_offset : cur_content_offset + aligned_size] = dec_data
            # Clear encryption flag in content type
            struct.pack_into('>H', data, ci_off + 0x06, content_type & ~1)
            print(f"  Decrypted {aligned_size} bytes at offset 0x{cur_content_offset:X}")

            # Verify: check for NCCH magic
            ncch_magic = data[cur_content_offset + 0x100 : cur_content_offset + 0x104]
            print(f"  NCCH magic check: {ncch_magic}")

        cur_content_offset += align(c_size, 64)

    # Write decrypted CIA
    Path(out_path).write_bytes(data)
    print(f"\nDecrypted CIA: {out_path} ({len(data)} bytes)")

if __name__ == "__main__":
    main()
