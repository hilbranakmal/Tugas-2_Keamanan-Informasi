"""KDC versi demo: test case serangan dan pengaturan session key."""

import argparse
import secrets

from aes import validate_key, key_variant
from net import log
from kdc import PROMPT, HELP, check_request, build_reply, new_session_key, start_server, command

# 1. Test Case

CASES = {
    "normal": "balasan KDC benar",
    "replay": "kirim ulang balasan lama untuk pasangan IDA-IDB yang sama",
    "n1": "N1 di dalam E(Ka,..) diganti",
    "idb": "IDB di dalam E(Ka,..) diganti",
    "ka": "E(Ka,..) dienkripsi dengan key yang salah",
    "ticket": "tiket E(Kb,..) dienkripsi dengan key yang salah",
}

opt = {"ks": None, "kslen": 16, "case": "normal", "last": {}}


def demo_handler(keys, msg):
    """Handler KDC sesuai test case aktif, dipasang ke start_server."""
    id_a, id_b, n1 = check_request(keys, msg)
    case, pair = opt["case"], (id_a, id_b)
    if case != "normal":
        log("KDC", f"    Test case '{case}': {CASES[case]}", PROMPT)
    if case == "replay" and pair in opt["last"]:
        return opt["last"][pair]
    ks = opt["ks"] or new_session_key(opt["kslen"])
    # isi atau key sengaja dirusak supaya peer menolak
    rn1 = str(secrets.randbelow(10 ** 9)) if case == "n1" else n1
    ridb = "Eve" if case == "idb" else id_b
    ka = new_session_key() if case == "ka" else keys[id_a]
    kb = new_session_key() if case == "ticket" else keys[id_b]
    rep = build_reply(ka, kb, ks, id_a, ridb, rn1)
    if case in ("normal", "replay"):
        opt["last"][pair] = rep, ks
    return rep, ks


# 2. Perintah Demo

def set_ks(arg):
    """Atur session key: tetap (ks <KEY>) atau acak (ks acak [16|24|32])."""
    a, _, n = arg.partition(" ")
    if a == "acak":
        n = n or "16"
        if n not in ("16", "24", "32"):
            raise ValueError("Panjang Ks harus 16/24/32")
        opt["ks"], opt["kslen"] = None, int(n)
        print(f"  Ks acak {n} karakter (AES-{int(n) * 8})")
    else:
        validate_key(arg)
        if "|" in arg:
            raise ValueError("Ks tidak boleh mengandung '|'")
        opt["ks"] = arg
        print(f"  Ks tetap '{arg}' ({key_variant(arg)})")


def set_case(arg):
    """Pilih test case, tanpa argumen tampilkan daftar."""
    if not arg:
        for n, d in CASES.items():
            print(f"  {'*' if n == opt['case'] else ' '} {n:<7} {d}")
    elif arg not in CASES:
        raise ValueError("Test case tidak dikenal, ketik: case")
    else:
        opt["case"] = arg
        print(f"  Test case -> {arg} ({CASES[arg]})")


# 3. CLI

HELP_DEMO = HELP + """

Perintah demo:
  ks <KEY>               pakai session key tetap untuk request berikutnya
  ks acak [16|24|32]     session key acak (default 16 = AES-128)
  case [nama]            pilih test case, tanpa nama = tampilkan daftar"""


def main():
    ap = argparse.ArgumentParser(description="KDC versi demo dengan test case")
    ap.add_argument("--bind", default="0.0.0.0", help="IP listen (default 0.0.0.0)")
    ap.add_argument("--port", type=int, default=5000, help="Port listen (default 5000)")
    args = ap.parse_args()

    keys = {}
    try:
        srv = start_server(keys, args.bind, args.port, demo_handler)
    except OSError as e:
        print(f"[!] Tidak bisa listen di {args.bind}:{args.port}: {e}")
        return
    print(HELP_DEMO)
    while True:
        try:
            line = input(PROMPT).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        cmd, _, arg = line.partition(" ")
        try:
            if cmd == "quit":
                break
            elif cmd == "help":
                print(HELP_DEMO)
            elif cmd == "ks":
                set_ks(arg)
            elif cmd == "case":
                set_case(arg)
            elif cmd and not command(keys, cmd, arg):
                print("  [!] Perintah tidak dikenal, ketik help")
        except ValueError as e:
            print(f"  [!] {e}")
    srv.close()


if __name__ == "__main__":
    main()
