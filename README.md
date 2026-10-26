# Key Distribution Scenario (KDC) + AES Manual

Implementasi skenario distribusi session key dengan Key Distribution Center
(Stallings) dan AES yang ditulis manual sesuai FIPS-197, tanpa library
kriptografi. Hanya memakai stdlib Python.

## Isi Program

| File | Isi |
|---|---|
| `aes.py` | AES-128/192/256 manual, mode ECB dan CBC, padding PKCS#7, CLI kecil untuk mencoba enkripsi |
| `kdc.py` | KDC: menyimpan master key tiap entitas, membuat session key, menjawab langkah 1-2 |
| `test.py` | KDC versi demo: sama dengan `kdc.py`, ditambah test case yang sengaja merusak balasan KDC |
| `net.py` | Utilitas jaringan: kirim/terima pesan JSON lewat TCP, log |
| `peer.py` | Program Alice dan Bob: meminta session key, langkah 3-5, lalu chat terenkripsi AES |

## Konsep Dasar

Setiap entitas (Alice, Bob, ...) punya satu **master key** yang hanya
diketahui dirinya sendiri dan KDC. Alice dan Bob tidak punya key bersama.
Kalau ingin berkomunikasi, Alice meminta KDC membuatkan **session key (Ks)**
baru, lalu Ks dikirim ke Alice dan Bob dalam keadaan terenkripsi dengan
master key masing-masing. Ks tidak pernah lewat jaringan dalam bentuk terbuka.

Notasi: `Ka` = master key Alice, `Kb` = master key Bob, `E(K, x)` = enkripsi
AES-CBC dari `x` dengan key `K`, `N1` dan `N2` = nonce (angka acak sekali pakai).

## Alur Protokol

```
(1) Alice -> KDC   : IDA, IDB, N1
(2) KDC   -> Alice : E(Ka, Ks|IDA|IDB|N1)  dan  E(Kb, Ks|IDA)
(3) Alice -> Bob   : E(Kb, Ks|IDA)                       (tiket)
(4) Bob   -> Alice : E(Ks, N2)
(5) Alice -> Bob   : E(Ks, f(N2))    dengan f(N2) = N2 + 1
```

1. Alice memberi tahu KDC: "saya Alice, ingin bicara dengan Bob", plus
   nonce N1 yang baru dibuat.
2. KDC membuat Ks acak dan mengirim dua bagian:
   - Bagian untuk Alice, dienkripsi dengan Ka. Isinya Ks, IDA, IDB, dan N1.
     Alice mengecek IDB (Ks ini memang untuk Bob) dan N1 (balasan ini
     jawaban untuk request barusan, bukan rekaman lama).
   - Tiket untuk Bob, dienkripsi dengan Kb. Alice tidak bisa membacanya,
     hanya meneruskan.
3. Alice meneruskan tiket ke Bob. Bob membukanya dengan Kb dan mendapat Ks
   serta tahu lawan bicaranya Alice.
4. Bob mengirim nonce N2 terenkripsi Ks untuk menguji apakah Alice benar
   memegang Ks.
5. Alice membalas N2 + 1. Kalau cocok, sesi dibuka dan keduanya bisa chat
   dengan pesan terenkripsi Ks.

Bagian program: `kdc.py` menangani langkah 1-2, `peer.py` menangani langkah
1-5 dari sisi Alice dan 3-5 dari sisi Bob.

Format pesan di jaringan: 4 byte panjang + JSON. Ciphertext dalam HEX, dan
pada mode CBC 16 byte pertama ciphertext adalah IV.

## Cara Kerja AES (`aes.py`)

1. **GF(2^8)**: `gmul` mengalikan dua byte sebagai polinomial modulo
   0x11B, `ginv` mencari invers (a^254).
2. **S-Box**: dibangun dari invers GF(2^8) lalu affine transform, bukan
   tabel hardcode.
3. **Key expansion**: key 16/24/32 byte diperluas jadi 11/13/15 round key.
4. **Enkripsi blok**: SubBytes, ShiftRows, MixColumns, AddRoundKey,
   10/12/14 ronde. Dekripsi menjalankan kebalikannya.
5. **Mode**: ECB (tiap blok sendiri-sendiri) dan CBC (tiap blok di-XOR
   dengan ciphertext sebelumnya, IV acak). Padding PKCS#7.

Key dan plaintext berupa teks ASCII. Panjang key menentukan varian:
16 karakter = AES-128, 24 = AES-192, 32 = AES-256.

## Menjalankan Program

Butuh Python 3. Contoh di bawah untuk satu laptop dengan tiga terminal.
Untuk beberapa laptop, lihat [Menjalankan di 2 / 3 Laptop](#menjalankan-di-2--3-laptop).

```
# Terminal 1: KDC
python3 kdc.py
KDC> add Alice kunci-alice-1234
KDC> add Bob kunci-bob-1234567890abcd

# Terminal 2: Bob
python3 peer.py --id Bob --kdc 127.0.0.1:5000 --port 6001
Master key Bob ...: kunci-bob-1234567890abcd

# Terminal 3: Alice
python3 peer.py --id Alice --kdc 127.0.0.1:5000 --port 6002
Master key Alice ...: kunci-alice-1234
Alice> /connect Bob 127.0.0.1:6001
Alice->Bob[CBC]> Halo Bob
```

Master key yang diketik di peer harus sama dengan yang didaftarkan di KDC.
Kalau Alice dan Bob di laptop yang sama, `--port` harus berbeda.

### Menjalankan di 2 / 3 Laptop

KDC dan peer listen di `0.0.0.0` secara default, jadi bisa menerima koneksi
dari laptop lain tanpa opsi tambahan. Yang perlu diatur hanya alamat
tujuan: `--kdc` menunjuk ke laptop KDC, dan `/connect` menunjuk ke laptop
Bob. KDC tidak pernah menghubungi Bob (tiket diteruskan oleh Alice), jadi
cukup Alice yang bisa menjangkau KDC dan Bob.

**Persiapan**

1. Semua laptop terhubung ke jaringan yang sama (WiFi / hotspot yang sama).
2. Cari IP tiap laptop:
   - Linux: `hostname -I` atau `ip a`
   - Windows: `ipconfig` (lihat "IPv4 Address")
   - macOS: `ipconfig getifaddr en0`
3. Buka port di firewall: 5000 (KDC) di laptop KDC, 6001 (Bob) di laptop
   Bob. Di Windows, klik "Allow access" saat muncul peringatan Windows
   Defender ketika program pertama kali dijalankan. Di Linux dengan ufw:
   `sudo ufw allow 5000/tcp` atau `sudo ufw allow 6001/tcp`.
4. Uji koneksi dengan `ping <IP laptop lain>` dari laptop Alice.

Contoh di bawah memakai IP misal. Ganti dengan IP yang didapat di langkah 2.

**3 laptop**: KDC, Bob, dan Alice masing-masing di laptop sendiri.

| Laptop | Peran | IP (contoh) |
|---|---|---|
| A | KDC | 192.168.1.10 |
| B | Bob | 192.168.1.11 |
| C | Alice | 192.168.1.12 |

```
# Laptop A: KDC
python3 kdc.py
KDC> add Alice kunci-alice-1234
KDC> add Bob kunci-bob-1234567890abcd

# Laptop B: Bob
python3 peer.py --id Bob --kdc 192.168.1.10:5000 --port 6001
Master key Bob ...: kunci-bob-1234567890abcd

# Laptop C: Alice
python3 peer.py --id Alice --kdc 192.168.1.10:5000 --port 6001
Master key Alice ...: kunci-alice-1234
Alice> /connect Bob 192.168.1.11:6001
Alice->Bob[CBC]> Halo Bob
```

**2 laptop**: KDC dan Bob di satu laptop (dua terminal), Alice di laptop lain.

| Laptop | Peran | IP (contoh) |
|---|---|---|
| A | KDC + Bob | 192.168.1.10 |
| B | Alice | 192.168.1.12 |

```
# Laptop A, terminal 1: KDC
python3 kdc.py
KDC> add Alice kunci-alice-1234
KDC> add Bob kunci-bob-1234567890abcd

# Laptop A, terminal 2: Bob (KDC ada di laptop yang sama)
python3 peer.py --id Bob --kdc 127.0.0.1:5000 --port 6001
Master key Bob ...: kunci-bob-1234567890abcd

# Laptop B: Alice
python3 peer.py --id Alice --kdc 192.168.1.10:5000 --port 6001
Master key Alice ...: kunci-alice-1234
Alice> /connect Bob 192.168.1.10:6001
Alice->Bob[CBC]> Halo Bob
```

Catatan:
- Alice dan Bob di laptop berbeda, jadi `--port` boleh sama.
- Kalau IP KDC salah ketik, tidak perlu restart: ketik `/kdc <IP>:5000` di
  peer. Cek pengaturan yang aktif dengan `/status`.
- Kalau muncul `Connection refused` atau timeout: pastikan program tujuan
  sudah berjalan, IP dan port benar, dan firewall tidak memblokir.
- Untuk demo `test.py` di beberapa laptop, jalankan `python3 test.py` di
  laptop KDC menggantikan `kdc.py`, dan pada langkah demo ganti
  `127.0.0.1:6001` dengan IP laptop Bob.

## Test Case Demo (`test.py`)

### Cara kerjanya

Di program yang benar, KDC selalu mengirim balasan yang valid. Untuk
membuktikan bahwa peer bisa mendeteksi balasan palsu atau rusak, `test.py`
menjalankan KDC yang **bisa disuruh berbuat curang**, seolah-olah ada
penyerang di tengah jalan.

`test.py` tidak punya logika KDC sendiri. Ia memakai fungsi dari `kdc.py`
(validasi request, penyusunan balasan, server) lalu hanya mengganti satu
bagian balasan sesuai test case yang aktif. Yang menentukan test lulus atau
tidak adalah **reaksi Alice atau Bob** di `peer.py`: serangan dianggap
berhasil ditangkal kalau peer menolak dan menampilkan pesan error.

Test case bisa diganti kapan saja dari prompt KDC, tanpa menjalankan ulang
program. Setiap `/connect` dari Alice memakai test case yang sedang aktif.

### Langkah demo

Jalankan seperti di bagian **Menjalankan Program**, tetapi Terminal 1 memakai
`python3 test.py` sebagai pengganti `python3 kdc.py`. Lalu untuk tiap baris
tabel di bawah:

1. Di Terminal 1 (prompt `KDC> `), ketik teks dari kolom "Perintah di KDC".
2. Di Terminal 3 (Alice) ketik `/connect Bob 127.0.0.1:6001`.
3. Lihat hasilnya. Kalau sesi terbuka, ketik `/disconnect` sebelum lanjut.

Contoh untuk baris `case n1`:

```
# Terminal 1 (test.py)
KDC> case n1
  Test case -> n1 (N1 di dalam E(Ka,..) diganti)

# Terminal 3 (Alice)
Alice> /connect Bob 127.0.0.1:6001
  [!] Balasan KDC tidak cocok dengan request (IDA/IDB/N1) — kemungkinan replay
```

| Perintah di KDC | Yang dilakukan KDC | Hasil yang benar | Kenapa ditolak |
|---|---|---|---|
| `case normal` | balasan benar | sesi terbuka | - |
| `case replay` | `/connect` kedua dikirimi balasan lama | Alice: "kemungkinan replay" | N1 di balasan lama berbeda dengan N1 baru Alice |
| `case n1` | N1 di bagian Alice diganti | Alice: "tidak cocok (IDA/IDB/N1)" | N1 tidak cocok |
| `case idb` | IDB di bagian Alice diganti "Eve" | Alice: "tidak cocok (IDA/IDB/N1)" | Ks ternyata bukan untuk Bob |
| `case ka` | bagian Alice dienkripsi key acak | Alice: "Gagal dekripsi balasan KDC" | hanya Ka yang bisa membuka |
| `case ticket` | tiket Bob dienkripsi key acak | Alice: "Ditolak peer: Tiket tidak bisa didekripsi" | hanya Kb yang bisa membuka |
| `ks acak 32` | Ks 32 karakter | sesi terbuka, AES-256 | - |
| `ks <KEY 16/24/32>` | Ks tetap sesuai input | sesi terbuka dengan Ks itu | - |
| `add Bob <key lain>` | master key Bob di KDC berbeda | tiket ditolak Bob | Bob membuka tiket dengan key lamanya |
| `del Bob` | Bob dihapus dari KDC | Alice: "ID 'Bob' tidak terdaftar" | KDC tidak kenal Bob |

Catatan:
- `case replay` butuh dua kali `/connect`. Yang pertama dilayani normal dan
  balasannya disimpan KDC, yang kedua dikirimi balasan simpanan itu.
- Setelah `add Bob <key lain>`, ketik `/key <key lain>` di Bob supaya
  `/connect` berhasil lagi. Ini menunjukkan master key bisa diganti tanpa
  restart.
- Ketik `case` tanpa argumen untuk melihat daftar dan test case yang aktif
  (bertanda `*`). Kembalikan ke `case normal` dan `ks acak` setelah selesai.

### Test di sisi peer

Saat sesi terbuka, fitur dari `peer.py`:
- `/mode ecb` lalu kirim `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`: dua blok
  ciphertext sama (ECB membocorkan pola). Ulangi dengan `/mode cbc`: semua
  blok berbeda.
- `/sk kunci-salah-1234` di Alice lalu kirim pesan: Bob gagal dekripsi.
- `/status`: tampilkan key, sesi, dan mode yang aktif.

### Selftest AES

```
python3 aes.py
aes> test
```

Mengecek AES terhadap test vector FIPS-197 Appendix C (AES-128/192/256) dan
enkripsi-dekripsi ECB/CBC. Perintah `test` juga tersedia di `kdc.py` dan
`test.py`. Hasil yang benar: lima baris `OK` lalu "Semua lulus".
