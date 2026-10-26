"""AES manual sesuai FIPS-197."""

# 1. Aritmetika GF(2^8)

def gmul(a, b):
    """Perkalian di GF(2^8) modulo x^8 + x^4 + x^3 + x + 1."""
    p = 0
    while b:
        if b & 1:
            p ^= a
        a <<= 1
        if a & 0x100:
            # reduksi modulo 0x11B
            a ^= 0x11B
        b >>= 1
    return p


def ginv(a):
    """Invers perkalian di GF(2^8), ginv(0) = 0."""
    # a^255 = 1, jadi a^254 = a^-1
    r = 1
    for _ in range(254):
        r = gmul(r, a)
    return r


# 2. S-Box

def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_sbox():
    """Bangun S-Box dan inversnya dari ginv + affine transform."""
    sbox, inv = [0] * 256, [0] * 256
    for a in range(256):
        b = ginv(a)
        # affine transform FIPS-197 5.1.1
        s = b ^ _rotl8(b, 1) ^ _rotl8(b, 2) ^ _rotl8(b, 3) ^ _rotl8(b, 4) ^ 0x63
        sbox[a] = s
        inv[s] = a
    return sbox, inv


SBOX, INV_SBOX = _build_sbox()


# 3. Key Expansion

def key_expansion(key):
    """Ekspansi key 16/24/32 byte menjadi Nr+1 round key 16 byte."""
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rc = 1
    for i in range(nk, 4 * (nr + 1)):
        t = w[i - 1]
        if i % nk == 0:
            # RotWord, SubWord, XOR Rcon
            t = [SBOX[x] for x in t[1:] + t[:1]]
            t[0] ^= rc
            rc = gmul(rc, 2)
        elif nk > 6 and i % nk == 4:
            # SubWord tambahan khusus AES-256
            t = [SBOX[x] for x in t]
        w.append([x ^ y for x, y in zip(w[i - nk], t)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(nr + 1)]


# 4. Transformasi Ronde
# state: list 16 byte column-major, s[r + 4c]

MIX, INV_MIX = (2, 3, 1, 1), (14, 11, 13, 9)


def _sub_bytes(s, box):
    return [box[x] for x in s]


def _shift_rows(s, d):
    # baris r digeser siklik sejauh r, d=1 ke kiri, d=-1 ke kanan
    return [s[r + 4 * ((c + d * r) % 4)] for c in range(4) for r in range(4)]


def _mix_columns(s, m):
    out = []
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        for r in range(4):
            # baris r matriks sirkulan m dikali kolom a
            x = 0
            for j in range(4):
                x ^= gmul(a[(r + j) % 4], m[j])
            out.append(x)
    return out


def _add_round_key(s, k):
    return [x ^ y for x, y in zip(s, k)]


def encrypt_block(block: bytes, rk: list) -> bytes:
    """Enkripsi satu blok 16 byte dengan round key dari key_expansion."""
    nr = len(rk) - 1
    s = _add_round_key(list(block), rk[0])
    for i in range(1, nr):
        s = _sub_bytes(s, SBOX)
        s = _shift_rows(s, 1)
        s = _mix_columns(s, MIX)
        s = _add_round_key(s, rk[i])
    # ronde terakhir tanpa MixColumns
    s = _sub_bytes(s, SBOX)
    s = _shift_rows(s, 1)
    s = _add_round_key(s, rk[nr])
    return bytes(s)


def decrypt_block(block: bytes, rk: list) -> bytes:
    """Dekripsi satu blok 16 byte (inverse cipher FIPS-197 5.3)."""
    nr = len(rk) - 1
    s = _add_round_key(list(block), rk[nr])
    for i in range(nr - 1, 0, -1):
        s = _shift_rows(s, -1)
        s = _sub_bytes(s, INV_SBOX)
        s = _add_round_key(s, rk[i])
        s = _mix_columns(s, INV_MIX)
    s = _shift_rows(s, -1)
    s = _sub_bytes(s, INV_SBOX)
    s = _add_round_key(s, rk[0])
    return bytes(s)
