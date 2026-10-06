#!/usr/bin/env python3
"""Qualcomm Kommbox NAND preprocessor used by qnxprobe.

Validated geometry:
  physical page 4352 bytes -> logical page 4096 bytes
  first seven 532-byte codewords:
      372 data + 1 FF stuff + 144 data + 13 BCH parity + 2 FF pad
  final 628-byte region:
      372 data + 1 FF stuff + 112 data + 143 spare bytes

BCH: m=13, t=8, primitive polynomial 0x201B, systematic MSB-first.
Only a codeword that decodes to <=8 errors AND verifies after correction is
changed. Uncorrectable words are copied unchanged and counted.
"""
from pathlib import Path
import os, tempfile

RAW_PAGE=4352
LOGICAL_PAGE=4096
CW=532
DATA_BYTES=516
ECC_BYTES=13
M=13
T=8
PRIM=0x201B
N=(1<<M)-1

# Degree-104 BCH generator for m=13/t=8. The stored 13 parity bytes are
# the systematic polynomial remainder, MSB first. A 256-entry byte table
# makes the overwhelmingly common "ECC already matches" path cheap.
GEN=0x115f914e07b0c138741c5c4fb23
GEN_DEG=104
GEN_MASK=(1<<GEN_DEG)-1
_PARITY_TABLE=[]
for _b in range(256):
    _r=_b << (GEN_DEG-8)
    for _ in range(8):
        _r = ((_r << 1) ^ GEN) if (_r & (1 << (GEN_DEG-1))) else (_r << 1)
        _r &= GEN_MASK
    _PARITY_TABLE.append(_r)

def _parity(payload):
    """Return the 13 stored BCH parity bytes for a 516-byte payload."""
    r=0
    for b in payload:
        top=(r >> (GEN_DEG-8)) & 0xff
        r=((r << 8) & GEN_MASK) ^ _PARITY_TABLE[top ^ b]
    for _ in range(ECC_BYTES):
        top=(r >> (GEN_DEG-8)) & 0xff
        r=((r << 8) & GEN_MASK) ^ _PARITY_TABLE[top]
    return r.to_bytes(ECC_BYTES,"big")

# GF(2^13) tables
_EXP=[0]*(2*N)
_LOG=[-1]*(1<<M)
x=1
for i in range(N):
    _EXP[i]=x; _LOG[x]=i
    x <<= 1
    if x & (1<<M): x ^= PRIM
for i in range(N,2*N): _EXP[i]=_EXP[i-N]

def _mul(a,b):
    return 0 if not a or not b else _EXP[(_LOG[a]+_LOG[b])%N]

def _syndromes(code):
    """S1..S16 for an MSB-first shortened BCH codeword."""
    syn=[]
    bits=len(code)*8
    for j in range(1,2*T+1):
        s=0
        # Horner evaluation at alpha**j; first bit is highest coefficient.
        a=_EXP[j%N]
        for byte in code:
            for k in range(7,-1,-1):
                s=_mul(s,a) ^ ((byte>>k)&1)
        syn.append(s)
    return syn

def _berlekamp_massey(s):
    C=[0]*(2*T+1); B=[0]*(2*T+1)
    C[0]=B[0]=1
    L=0; m=1; b=1
    for n in range(2*T):
        d=s[n]
        for i in range(1,L+1):
            if C[i] and s[n-i]: d ^= _mul(C[i],s[n-i])
        if d==0:
            m+=1; continue
        coef=_EXP[(_LOG[d]-_LOG[b])%N]
        old=C[:]
        for j in range(0,2*T+1-m):
            if B[j]: C[j+m] ^= _mul(coef,B[j])
        if 2*L <= n:
            L=n+1-L; B=old; b=d; m=1
        else:
            m+=1
    return C,L

def _correct_codeword(payload,ecc):
    code=bytearray(payload+ecc)
    syn=_syndromes(code)
    if not any(syn): return bytes(payload),0,"clean"
    loc,L=_berlekamp_massey(syn)
    if L<1 or L>T: return bytes(payload),0,"uncorrectable"
    positions=[]
    # Position p is counted from the rightmost (constant) bit.
    for p in range(len(code)*8):
        z=_EXP[(N-(p%N))%N]  # alpha**(-p)
        v=0; power=1
        for i in range(L+1):
            if loc[i]: v ^= _mul(loc[i],power)
            power=_mul(power,z)
        if v==0: positions.append(p)
    if len(positions)!=L: return bytes(payload),0,"uncorrectable"
    for p in positions:
        left=len(code)*8-1-p
        bi=left//8; bit=7-(left%8)
        code[bi] ^= 1<<bit
    if any(_syndromes(code)): return bytes(payload),0,"uncorrectable"
    return bytes(code[:DATA_BYTES]),len(positions),"corrected"

def process_page(page):
    if len(page)!=RAW_PAGE: raise ValueError("page must be 4352 bytes")
    out=bytearray(); corrected=0; bad=0; clean=0
    for i in range(7):
        b=i*CW
        payload=page[b:b+372]+page[b+373:b+517]
        ecc=page[b+517:b+530]
        pad=page[b+530:b+532]
        # Erased/unprogrammed codewords need no BCH work.
        if payload==b"\xff"*DATA_BYTES and ecc==b"\xff"*ECC_BYTES:
            fixed=payload; clean+=1
        elif _parity(payload)==ecc:
            # Fast path: clean codeword; skip syndrome/BM/Chien completely.
            fixed=payload; clean+=1
        else:
            fixed,n,status=_correct_codeword(payload,ecc)
            corrected += n
            if status=="uncorrectable": bad+=1
            else: clean+= status=="clean"
        out += fixed
    # Last region: remove the stuff byte at absolute 4096 and trailing spare.
    out += page[7*CW:4096]       # 372 bytes
    out += page[4097:4209]       # 112 bytes
    assert len(out)==LOGICAL_PAGE
    return bytes(out),corrected,bad,clean

def preprocess(src,dst=None,progress=None):
    src=Path(src)
    if dst is None:
        fd,name=tempfile.mkstemp(prefix="qnxprobe_kommbox_",suffix=".bin")
        os.close(fd); dst=Path(name)
    else: dst=Path(dst)
    size=src.stat().st_size
    pages=size//RAW_PAGE
    if size%RAW_PAGE:
        raise ValueError(f"Qualcomm-Kombox image size {size} is not divisible by {RAW_PAGE}")
    total_corr=total_bad=0
    with src.open("rb") as fi, dst.open("wb") as fo:
        for i in range(pages):
            page=fi.read(RAW_PAGE)
            data,corr,bad,_=process_page(page)
            fo.write(data); total_corr+=corr; total_bad+=bad
            if progress and (i%1024==0 or i+1==pages):
                progress(i+1,pages,total_corr,total_bad)
    return str(dst),{"pages":pages,"corrected_bits":total_corr,"uncorrectable_codewords":total_bad}
