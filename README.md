# Domain Checker CLI

Program CLI sederhana dalam bahasa Go untuk mengecek status SSL, masa berlaku domain, DNS pointing, dan status Cloudflare dari sebuah domain.

## Fitur
1. **SSL Check**: Mengecek apakah sertifikat SSL masih aktif atau sudah expired, serta menampilkan tanggal kadaluarsanya.
2. **Domain Expiry Check**: Mengecek apakah nama domain masih aktif atau sudah expired berdasarkan data WHOIS/registrar (bukan status website atau DNS).
3. **NS Lookup**: Menampilkan Nameserver (NS) yang menangani domain tersebut.
4. **DNS Pointing**: Menampilkan IP address yang diarahkan oleh domain (A/AAAA Records).
5. **Cloudflare Detection**: Mendeteksi apakah domain menggunakan proxy Cloudflare (Orange Cloud) berdasarkan range IP dan header response.
6. **Origin Verification**: Memastikan domain yang menggunakan Cloudflare benar-benar mengarah ke IP server asli kita dengan melakukan direct request menggunakan Host header spoofing.

> Catatan: domain expired berarti pendaftaran nama domain sudah berakhir di registrar/registry. Ini berbeda dengan SSL expired, yang mengacu pada sertifikat HTTPS website.

## Cara Penggunaan

### Prasyarat
- Go (Golang) versi 1.21 ke atas.

### Cara Install Go di Ubuntu 24.04
Jika perintah `go` belum ditemukan, instal menggunakan perintah berikut:
```bash
sudo apt update
sudo apt install golang-go
```
Atau jika ingin versi terbaru (rekomendasi):
```bash
# Menggunakan PPA untuk versi terbaru
sudo add-apt-repository ppa:longsleep/golang-backports
sudo apt update
sudo apt install golang-go
```

Verifikasi instalasi dengan:
```bash
go version
```

### 1) Cek domain biasa
```bash
go run . -domain example.com
```
Fungsi: menampilkan status SSL, domain expiry, NS, DNS pointing, dan deteksi Cloudflare.

### 2) Cek domain dengan origin IP untuk verifikasi server asli
```bash
go run . -domain domainkita.com -origin 123.123.123.123
```
Fungsi: selain cek umum, program akan mengecek apakah IP yang Anda masukkan memang benar menjadi origin server untuk domain tersebut.

### 3) Build menjadi binary
```bash
go build -o checkdomain main.go
./checkdomain -domain example.com
```

### 4) Contoh domain yang sering dipakai
```bash
go run . -domain google.com
go run . -domain batannyuh.desa.id
go run . -domain yourdomain.com -origin 1.2.3.4
```

### Penjelasan parameter
- `-domain`: nama domain yang akan dicek
- `-origin`: IP server asal (origin) yang ingin diverifikasi untuk domain tertentu

## Output yang ditampilkan
Saat dijalankan, program akan menampilkan hasil seperti:
- SSL status (active/expired)
- Tanggal expired domain (jika data WHOIS tersedia)
- NS Lookup
- A/AAAA records
- Cloudflare detection
- optional origin verification jika `-origin` dipakai

## Penjelasan Fitur

### 1) Cek SSL masih aktif atau expired
Tool akan mencoba koneksi ke port 443 dan membaca sertifikat TLS dari domain. Jika sertifikat sudah lewat tanggal `NotAfter`, hasilnya akan tampil `EXPIRED` dan menunjukkan tanggal kadaluarsanya.

### 2) Cek domain expired atau masih aktif
Tool akan melakukan query ke WHOIS server domain untuk membaca tanggal expiry/renewal. Jika data bisa dibaca, program akan menampilkan status `Active` atau `EXPIRED` dan sisa hari sampai masa berakhirnya domain. Ini membantu mengetahui apakah nama domain berstatus expired di registrar.

### 3) NS Lookup
Tool akan melakukan query DNS untuk menampilkan daftar Nameserver (NS) yang bertanggung jawab atas domain tersebut. Ini berguna untuk mengecek apakah domain ada di provider DNS yang benar.

## Contoh Output
```
🔍 Checking domain: example.com
----------------------------------------
🔒 SSL Status: ✅ Active (kadaluarsa 2026-12-25)
   📝 Subject: example.com
   🏢 Issuer:  SSL Corporation
   ⏳ Sisa:    85 hari
📅 Domain Expiry: ✅ Active (berlaku sampai 2027-08-13)
   ⏳ Sisa:    316 hari
🧭 NS Lookup:
   - ns1.example.com.
   - ns2.example.com.
🌐 DNS Pointing:
   - 104.20.23.154                            (Cloudflare IP)
   - 172.66.147.243                           (Cloudflare IP)
☁️  Cloudflare: 🟠 Proxied (Orange Cloud Active)
----------------------------------------
```
