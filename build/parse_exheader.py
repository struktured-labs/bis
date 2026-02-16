#!/usr/bin/env python3
import struct

with open('build/extracted_clean/exheader.bin', 'rb') as f:
    data = f.read()

# Code segment info at offset 0x10 in SCI
text_addr = struct.unpack_from('<I', data, 0x10)[0]
text_pages = struct.unpack_from('<I', data, 0x14)[0]
text_size = struct.unpack_from('<I', data, 0x18)[0]

rodata_addr = struct.unpack_from('<I', data, 0x20)[0]
rodata_pages = struct.unpack_from('<I', data, 0x24)[0]
rodata_size = struct.unpack_from('<I', data, 0x28)[0]

data_addr = struct.unpack_from('<I', data, 0x30)[0]
data_pages = struct.unpack_from('<I', data, 0x34)[0]
data_size = struct.unpack_from('<I', data, 0x38)[0]

bss_size = struct.unpack_from('<I', data, 0x3C)[0]

print(f'Text: addr=0x{text_addr:08X} pages={text_pages} size=0x{text_size:X} ({text_size} bytes)')
print(f'Rodata: addr=0x{rodata_addr:08X} pages={rodata_pages} size=0x{rodata_size:X}')
print(f'Data: addr=0x{data_addr:08X} pages={data_pages} size=0x{data_size:X}')
print(f'BSS: size=0x{bss_size:X}')
print()
print(f'code.bin contains TEXT+RODATA+DATA concatenated')
print(f'Text loaded at: 0x{text_addr:08X} (size 0x{text_size:X})')
print(f'Rodata loaded at: 0x{rodata_addr:08X} (size 0x{rodata_size:X})')
print(f'Data loaded at: 0x{data_addr:08X} (size 0x{data_size:X})')
print()
print(f'To find file offset for virtual addr X:')
print(f'  If X in [0x{text_addr:08X}, 0x{text_addr+text_size:08X}): offset = X - 0x{text_addr:08X}')
print(f'  If X in [0x{rodata_addr:08X}, 0x{rodata_addr+rodata_size:08X}): offset = 0x{text_size:X} + (X - 0x{rodata_addr:08X})')
print(f'  If X in [0x{data_addr:08X}, 0x{data_addr+data_size:08X}): offset = 0x{text_size+rodata_size:X} + (X - 0x{data_addr:08X})')

# Verify code.bin size
import os
code_size = os.path.getsize('build/v3_extract/exefs_dir/code.bin')
expected = text_size + rodata_size + data_size
print(f'\ncode.bin actual size: {code_size} (0x{code_size:X})')
print(f'Expected (text+rodata+data): {expected} (0x{expected:X})')
print(f'text_size used for offset: 0x{text_size:X} = {text_size}')
