"""KDC skenario Stallings, menangani langkah 1-2 distribusi session key."""

import argparse
import secrets
import string
import threading

from aes import encrypt_text, validate_key, key_variant, selftest
from net import log, send_msg, recv_msg, make_listener

# 1. Logika Protokol

KS_CHARS = string.ascii_letters + string.digits
PROMPT = "KDC> "


def register(keys, ident, key):
    """Daftarkan master key milik satu ID ke tabel KDC."""
    if not ident or "|" in ident:
        raise ValueError("ID tidak boleh kosong atau mengandung '|'")
    validate_key(key)
    keys[ident] = key


def new_session_key(n=16):
    """Session key ASCII acak, tanpa '|' supaya aman dipisah di peer."""
    return "".join(secrets.choice(KS_CHARS) for _ in range(n))


def handle_request(keys, msg):
    """Proses KDC_REQUEST (langkah 1), kembalikan (balasan langkah 2, ks)."""
    if msg.get("type") != "KDC_REQUEST":
        raise ValueError("Bukan KDC_REQUEST")
    id_a, id_b, n1 = msg.get("id_a"), msg.get("id_b"), str(msg.get("n1", ""))
    for i in (id_a, id_b):
        if i not in keys:
            raise ValueError(f"ID '{i}' tidak terdaftar di KDC")
    if id_a == id_b:
        raise ValueError("IDA dan IDB tidak boleh sama")
    if not n1 or "|" in n1:
        raise ValueError("N1 tidak valid")
    ks = new_session_key()
    rep = {
        "step": 2,
        "type": "KDC_RESPONSE",
        "enc_for_a": encrypt_text(keys[id_a], f"{ks}|{id_a}|{id_b}|{n1}"),
        "ticket_for_b": encrypt_text(keys[id_b], f"{ks}|{id_a}"),
    }
    return rep, ks


# 2. Server

def serve_one(keys, conn, addr):
    """Layani satu koneksi: terima langkah 1, balas langkah 2."""
    try:
        conn.settimeout(10)
        msg = recv_msg(conn)
        if not msg:
            return
        log("KDC", f"(1) Dari {addr[0]}: IDA={msg.get('id_a')}, IDB={msg.get('id_b')}, "
                   f"N1={msg.get('n1')}", PROMPT)
        try:
            rep, ks = handle_request(keys, msg)
        except ValueError as e:
            send_msg(conn, {"type": "ERROR", "reason": str(e)})
            log("KDC", f"    Ditolak: {e}", PROMPT)
            return
        send_msg(conn, rep)
        log("KDC", f"(2) Ks='{ks}' dikirim ke {msg['id_a']}\n"
                   f"      E(Ka,..) = {rep['enc_for_a']}\n"
                   f"      E(Kb,..) = {rep['ticket_for_b']}", PROMPT)
    except (OSError, ValueError) as e:
        log("KDC", f"Error koneksi {addr[0]}: {e}", PROMPT)
    finally:
        conn.close()


def _accept_loop(keys, srv):
    while True:
        try:
            conn, addr = srv.accept()
        except OSError:
            break
        threading.Thread(target=serve_one, args=(keys, conn, addr), daemon=True).start()


def start_server(keys, host, port):
    """Buka listener KDC, terima koneksi di thread terpisah."""
    srv = make_listener(host, port)
    threading.Thread(target=_accept_loop, args=(keys, srv), daemon=True).start()
    log("KDC", f"Listening di {host}:{port}", PROMPT)
    return srv


# 3. CLI

HELP = """Perintah:
  add <ID> <KEY>   daftarkan / ganti master key milik ID
  del <ID>         hapus ID dari KDC
  list             tampilkan tabel master key
  test             selftest AES
  quit             keluar"""


def main():
    ap = argparse.ArgumentParser(description="Key Distribution Center")
    ap.add_argument("--bind", default="0.0.0.0", help="IP listen (default 0.0.0.0)")
    ap.add_argument("--port", type=int, default=5000, help="Port listen (default 5000)")
    args = ap.parse_args()

    keys = {}
    try:
        srv = start_server(keys, args.bind, args.port)
    except OSError as e:
        print(f"[!] Tidak bisa listen di {args.bind}:{args.port}: {e}")
        return
    print(HELP)
    while True:
        try:
            line = input(PROMPT).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        cmd, _, arg = line.partition(" ")
        try:
            if cmd == "add":
                ident, _, key = arg.partition(" ")
                register(keys, ident, key)
                print(f"  {ident} terdaftar ({key_variant(key)})")
            elif cmd == "del":
                if keys.pop(arg, None) is None:
                    raise ValueError(f"ID '{arg}' tidak terdaftar")
                print(f"  {arg} dihapus")
            elif cmd == "list":
                for i, k in keys.items():
                    print(f"  {i:<10} {k}  ({key_variant(k)})")
                if not keys:
                    print("  Belum ada ID terdaftar")
            elif cmd == "test":
                print("  Semua lulus" if selftest() else "  [!] Ada yang gagal")
            elif cmd == "help":
                print(HELP)
            elif cmd == "quit":
                break
            elif cmd:
                print("  [!] Perintah tidak dikenal, ketik help")
        except ValueError as e:
            print(f"  [!] {e}")
    srv.close()


if __name__ == "__main__":
    main()
