#!/usr/bin/env python3
import argparse, os, struct, tempfile

def u16(b,o): return struct.unpack_from('<H',b,o)[0]
def u32(b,o): return struct.unpack_from('<I',b,o)[0]

def recover(data):
    headers=[]
    for off in range(0, len(data)-68):
        if data[off:off+5] == b'\x13\x03CIS' and data[off+8:off+14] == b'FTL100':
            h=data[off:off+68]
            headers.append((off,h))
    if not headers: raise ValueError('No FTL100 erase-unit headers found')
    h0=headers[0][1]
    block_shift=h0[22]; erase_shift=h0[23]; first=u16(h0,24); num=u16(h0,26); fmt=u32(h0,28); bamoff=u32(h0,48)
    block_size=1<<block_shift; erase_size=1<<erase_shift; data_units=num-h0[15]
    # Keep valid data EUNs. This BMW image numbers LogicalEUNs using absolute EUN numbers,
    # so normalize against FirstPhysicalEUN.
    units={}
    transfers=[]
    for off,h in headers:
        if u32(h,28)!=fmt or u16(h,26)!=num: continue
        lun=u16(h,20)
        if lun==0xffff: transfers.append(off); continue
        nlun=lun-first if first <= lun < first+data_units else lun
        if 0 <= nlun < data_units:
            # In case duplicates exist, retain the header with the greater erase count.
            ec=u32(h,16)
            if nlun not in units or ec > units[nlun][1]: units[nlun]=(off,ec)
    blocks_per_unit=erase_size//block_size
    vmap={}
    for lun,(base,ec) in units.items():
        for j in range(blocks_per_unit):
            bo=base+bamoff+j*4
            if bo+4>len(data): break
            ent=u32(data,bo)
            typ=ent & 0x7f
            if typ==0x40: # BLOCK_DATA
                sector=ent >> block_shift
                phys=base+j*block_size
                if phys+block_size<=len(data): vmap[sector]=phys
    out=bytearray(fmt)
    for sector,phys in vmap.items():
        dst=sector*block_size
        if dst+block_size<=len(out): out[dst:dst+block_size]=data[phys:phys+block_size]
    return bytes(out), headers, units, transfers, vmap

def preprocess(path):
    """Reconstruct FTL100 into a temporary logical image for qnxprobe."""
    with open(path, "rb") as fh:
        data = fh.read()
    out, headers, units, transfers, vmap = recover(data)
    fd, out_path = tempfile.mkstemp(prefix="qnxprobe_ftl100_", suffix=".img")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(out)
    except Exception:
        try: os.close(fd)
        except OSError: pass
        try: os.remove(out_path)
        except OSError: pass
        raise
    return out_path, {
        "headers": len(headers), "data_units": len(units),
        "transfer_units": len(transfers), "recovered_sectors": len(vmap),
        "logical_bytes": len(out),
    }

def main():
    ap=argparse.ArgumentParser(description='Recover an M-Systems FTL100 logical block image from a raw NOR dump')
    ap.add_argument('input'); ap.add_argument('output', nargs='?', default='recovered_ftl.img')
    a=ap.parse_args(); data=open(a.input,'rb').read(); out,hs,units,trans,vmap=recover(data); open(a.output,'wb').write(out)
    print(f'FTL100 headers: {len(hs)}; data units: {len(units)}; transfer units: {len(trans)}')
    print(f'Recovered sectors: {len(vmap)}; logical image: {len(out)} bytes -> {a.output}')
    if out[510:512]==b'\x55\xaa': print('Sector 0 has valid 0x55AA signature')
    for i in range(4):
        e=out[446+i*16:462+i*16]
        if len(e)==16 and e[4]: print(f'Partition {i+1}: type=0x{e[4]:02X}, start={u32(e,8)}, sectors={u32(e,12)}')
if __name__=='__main__': main()