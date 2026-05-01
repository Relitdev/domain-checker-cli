# Domain Checker CLI

Program CLI sederhana dalam bahasa Go untuk mengecek status SSL, DNS pointing, dan status Cloudflare dari sebuah domain.

## Fitur
1. **SSL Check**: Mengecek apakah sertifikat SSL aktif atau sudah expired, serta menampilkan tanggal kadaluarsanya.
2. **DNS Pointing**: Menampilkan IP address yang diarahkan oleh domain (A/AAAA Records).
3. **Cloudflare Detection**: Mendeteksi apakah domain menggunakan proxy Cloudflare (Orange Cloud) berdasarkan range IP dan header response.
4. **Origin Verification**: Memastikan domain yang menggunakan Cloudflare benar-benar mengarah ke IP server asli kita dengan melakukan direct request menggunakan Host header spoofing.

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

# Untuk cek domain dan verifikasi IP server asli (Origin)
go run main.go -domain domainkita.com -origin 123.123.123.123
```

### Cara Compile (Build)
Jika ingin membuat file executable (binary):

```bash
go build -o checkdomain main.go
./checkdomain -domain example.com
```

## Contoh Output
```
🔍 Checking domain: myawesomeapp.com
----------------------------------------
🔒 SSL Status: ✅ Active (Expires in 85 days, on 2026-07-20)
🌐 DNS Pointing: 104.21.9.155, 172.67.140.230
☁️  Cloudflare: 🟠 Proxied (Orange Cloud Active)
🎯 Origin Verification: ✅ Success! Origin server at 1.2.3.4 responds to myawesomeapp.com
   (Status: Traffic is flowing through Cloudflare and pointing to this origin)
----------------------------------------
```
