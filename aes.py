"""AES manual sesuai FIPS-197."""

import secrets

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


# 5. Padding dan Mode

def _pad(data):
    # PKCS#7
    n = 16 - len(data) % 16
    return data + bytes([n]) * n


def _unpad(data):
    n = data[-1] if data else 0
    if not 1 <= n <= 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("Padding tidak valid (key salah / ciphertext rusak?)")
    return data[:-n]


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_bytes(key: bytes, data: bytes, mode="CBC") -> bytes:
    """Enkripsi data dengan padding PKCS#7, mode ECB atau CBC (IV di depan)."""
    rk = key_expansion(key)
    data = _pad(data)
    blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
    if mode == "ECB":
        return b"".join(encrypt_block(b, rk) for b in blocks)
    if mode == "CBC":
        prev = out = secrets.token_bytes(16)
        for b in blocks:
            prev = encrypt_block(_xor(b, prev), rk)
            out += prev
        return out
    raise ValueError("Mode harus ECB atau CBC")


def decrypt_bytes(key: bytes, data: bytes, mode="CBC") -> bytes:
    """Kebalikan encrypt_bytes, padding dibuang."""
    if not data or len(data) % 16:
        raise ValueError("Panjang ciphertext harus kelipatan 16 byte")
    rk = key_expansion(key)
    blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
    if mode == "ECB":
        out = b"".join(decrypt_block(b, rk) for b in blocks)
    elif mode == "CBC":
        out = b"".join(_xor(decrypt_block(c, rk), prev)
                       for prev, c in zip(blocks, blocks[1:]))
    else:
        raise ValueError("Mode harus ECB atau CBC")
    return _unpad(out)


# 6. API Publik

def _ascii(s, what):
    try:
        return s.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError(f"{what} harus ASCII") from None


def validate_key(key_str: str) -> bytes:
    """Ubah key ASCII ke bytes, panjang harus 16/24/32 karakter."""
    key = _ascii(key_str, "Key")
    if len(key) not in (16, 24, 32):
        raise ValueError(f"Panjang key {len(key)}, harus 16/24/32 karakter")
    return key


def key_variant(key_str: str) -> str:
    """Nama varian AES sesuai panjang key."""
    return f"AES-{len(validate_key(key_str)) * 8}"


def encrypt_text(key_str: str, plaintext: str, mode="CBC") -> str:
    """Enkripsi teks ASCII, hasil hex (CBC: 16 byte pertama = IV)."""
    data = _ascii(plaintext, "Plaintext")
    return encrypt_bytes(validate_key(key_str), data, mode).hex()


def decrypt_hex(key_str: str, hex_str: str, mode="CBC") -> str:
    """Dekripsi ciphertext hex menjadi teks ASCII."""
    try:
        data = bytes.fromhex(hex_str)
    except ValueError:
        raise ValueError("Ciphertext bukan hex yang valid") from None
    pt = decrypt_bytes(validate_key(key_str), data, mode)
    try:
        return pt.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("Hasil dekripsi bukan ASCII (key salah?)") from None


def selftest(verbose=True) -> bool:
    """Uji test vector FIPS-197 Appendix C dan round-trip ECB/CBC."""
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    vec = ((16, "69c4e0d86a7b0430d8cdb78070b4c55a"),
           (24, "dda97ca4864cdfe06eaf70a0ec0d7191"),
           (32, "8ea2b7ca516745bfeafc49904b496089"))
    ok = True
    for n, ct in vec:
        rk = key_expansion(bytes(range(n)))
        c = encrypt_block(pt, rk)
        good = c.hex() == ct and decrypt_block(c, rk) == pt
        ok = ok and good
        if verbose:
            print(f"  AES-{n * 8} FIPS-197 C : {'OK' if good else 'GAGAL'}")
    k, msg = "kunci-rahasia-16", "Ks|A|B|12345"
    for mode in ("ECB", "CBC"):
        good = decrypt_hex(k, encrypt_text(k, msg, mode), mode) == msg
        ok = ok and good
        if verbose:
            print(f"  Round-trip {mode}      : {'OK' if good else 'GAGAL'}")
    return ok


# 7. CLI

def main():
    key, mode = None, "CBC"
    print("Perintah: key <key>, mode <ECB|CBC>, enc <teks>, dec <hex>, test, quit")
    while True:
        try:
            line = input("aes> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        cmd, _, arg = line.partition(" ")
        try:
            if cmd == "key":
                print(f"  Key diset ({key_variant(arg)})")
                key = arg
            elif cmd == "mode":
                if arg.upper() not in ("ECB", "CBC"):
                    raise ValueError("Mode harus ECB atau CBC")
                mode = arg.upper()
                print(f"  Mode: {mode}")
            elif cmd in ("enc", "dec") and key is None:
                raise ValueError("Key belum diset, pakai: key <key>")
            elif cmd == "enc":
                print(f"  Plaintext (ASCII): {arg}")
                print(f"  Ciphertext (HEX) : {encrypt_text(key, arg, mode)}")
            elif cmd == "dec":
                print(f"  Ciphertext (HEX) : {arg}")
                print(f"  Plaintext (ASCII): {decrypt_hex(key, arg, mode)}")
            elif cmd == "test":
                print("  Semua lulus" if selftest() else "  [!] Ada yang gagal")
            elif cmd == "quit":
                break
            elif cmd:
                print("  [!] Perintah tidak dikenal")
        except ValueError as e:
            print(f"  [!] {e}")


if __name__ == "__main__":
    main()
