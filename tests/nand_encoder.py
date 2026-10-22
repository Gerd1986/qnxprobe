"""Independent test encoder from Gerd1986/sleuthkit tests/flash_preprocess_regression.py."""
def gf_mul(a, b):
    out = 0
    while b:
        if b & 1:
            out ^= a
        b >>= 1
        a <<= 1
        if a & 8192:
            a ^= 0x201b
    return out


def generator():
    exponents = [1]
    for _ in range(8190):
        exponents.append(gf_mul(exponents[-1], 2))
    roots = set()
    for first in range(1, 17):
        i = first
        while i not in roots:
            roots.add(i)
            i = (i*2) % 8191
    polynomial = [1]
    for root in sorted(roots):
        out = [0]*(len(polynomial)+1)
        for i, coefficient in enumerate(polynomial):
            out[i] ^= gf_mul(coefficient, exponents[root])
            out[i+1] ^= coefficient
        polynomial = out
    assert len(polynomial) == 105 and set(polynomial) <= {0, 1}
    return sum(c << i for i, c in enumerate(polynomial))


def encode(payload, polynomial):
    remainder = int.from_bytes(payload, 'big') << 104
    while remainder.bit_length() > 104:
        remainder ^= polynomial << (remainder.bit_length()-105)
    return remainder.to_bytes(13, 'big')


def pack_page(data, polynomial):
    assert len(data) == 4096
    page = bytearray(b'\xff'*4352)
    for i in range(7):
        base = 532*i
        payload = data[516*i:516*(i+1)]
        page[base:base+372] = payload[:372]
        page[base+373:base+517] = payload[372:]
        page[base+517:base+530] = b'\xff'*13 if payload == b'\xff'*516 else encode(payload, polynomial)
    page[3724:4096] = data[3612:3984]
    page[4097:4209] = data[3984:]
    return bytes(page)


