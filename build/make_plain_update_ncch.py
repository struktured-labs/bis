import struct,sys
src,dst,U=sys.argv[1],sys.argv[2],sys.argv[3]
d=bytearray(open(src,'rb').read())
mu=0x200
eo,es=struct.unpack('<II',d[0x1A0:0x1A8]); ro,rs=struct.unpack('<II',d[0x1B0:0x1B8])
exh=open(U+'/exheader_v22.bin','rb').read(); exe=open(U+'/exefs_raw.bin','rb').read(); rom=open(U+'/romfs.bin','rb').read()
print('exh',exh[:8],'exefs',hex(eo*mu),es*mu,len(exe),exe[:8],'romfs',hex(ro*mu),rs*mu,len(rom),rom[:4])
assert len(exh)==0x800 and len(exe)==es*mu and len(rom)==rs*mu
d[0x200:0xA00]=exh; d[eo*mu:eo*mu+len(exe)]=exe; d[ro*mu:ro*mu+len(rom)]=rom
d[0x18F]|=0x04; d[0x18B]=0
open(dst,'wb').write(d)
