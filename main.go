package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// Cloudflare IP ranges (IPv4 & IPv6)
var cloudflareIPRanges = []string{
	// IPv4
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	// IPv6
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

func isCloudflareIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range cloudflareIPRanges {
		_, subnet, _ := net.ParseCIDR(cidr)
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

func main() {
	flag.Usage = func() {
		fmt.Printf("🚀 Domain Checker CLI - Hubungi kami di opendesa.id jika ada kendala\n\n")
		fmt.Printf("PENGGUNAAN:\n")
		fmt.Printf("  checkdomain -domain <domain> [opsi lainnya]\n\n")
		fmt.Printf("OPSI:\n")
		fmt.Print("  -domain string\n")
		fmt.Print("    \tNama Domain yang ingin dicek (contoh: google.com atau web.desa.id)\n")
		fmt.Print("  -origin string\n")
		fmt.Print("    \tAlamat IP server asli (Origin IP) untuk verifikasi pointing dan SSL asli\n")
		fmt.Printf("\nCONTOH:\n")
		fmt.Printf("  checkdomain -domain google.com\n")
		fmt.Printf("  checkdomain -domain opendesa.id -origin 103.154.142.172\n\n")
		fmt.Printf("FITUR:\n")
		fmt.Printf("  ✅ Cek status dan masa berlaku SSL (HTTPs)\n")
		fmt.Printf("  📅 Cek masa berlaku domain (expired atau masih aktif) via WHOIS\n")
		fmt.Printf("  🧭 Cek NS (Nameserver) untuk domain\n")
		fmt.Printf("  🌐 Cek IP Pointing (A/AAAA Records) dengan label Cloudflare\n")
		fmt.Printf("  ☁️  Deteksi status Proxy Cloudflare (Orange Cloud)\n")
		fmt.Printf("  🎯 Verifikasi Origin IP (memastikan pointing Cloudflare benar ke server Anda)\n")
	}

	domain := flag.String("domain", "", "Domain to check")
	expectedOrigin := flag.String("origin", "", "Expected origin IP")
	flag.Parse()

	if *domain == "" {
		flag.Usage()
		os.Exit(0)
	}

	fmt.Printf("\n🔍 Checking domain: %s\n", *domain)
	fmt.Println(strings.Repeat("-", 40))

	// 1. SSL Check
	checkSSL(*domain)

	// 2. Domain Expiry Check
	checkDomainExpiry(*domain)

	// 3. NS Lookup
	checkNS(*domain)

	// 4. DNS Pointing Check
	ips := checkDNS(*domain)

	// 5. Cloudflare Check
	isCF := checkCloudflare(*domain, ips)

	// 6. Origin Verification
	if *expectedOrigin != "" {
		verifyOrigin(*domain, *expectedOrigin, isCF)
	} else if isCF {
		fmt.Println("💡 Penjelasan: Domain ini di-proxy oleh Cloudflare.")
		fmt.Println("   Untuk memastikan pointing benar, jalankan dengan -origin <IP_SERVER_ANDA>")
	}

	fmt.Println(strings.Repeat("-", 40))
}

func normalizeDomain(domain string) string {
	trimmed := strings.TrimSpace(domain)
	trimmed = strings.TrimPrefix(trimmed, "http://")
	trimmed = strings.TrimPrefix(trimmed, "https://")
	trimmed = strings.TrimSuffix(trimmed, "/")
	trimmed = strings.Trim(trimmed, "/")
	trimmed = strings.TrimSpace(trimmed)
	return strings.ToLower(trimmed)
}

func checkSSL(domain string) {
	domain = normalizeDomain(domain)
	fmt.Print("🔒 SSL Status: ")
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", domain+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		fmt.Printf("❌ Tidak bisa konek ke HTTPS: %v\n", err)
		return
	}
	defer conn.Close()

	if len(conn.ConnectionState().PeerCertificates) == 0 {
		fmt.Println("❌ Tidak ada sertifikat TLS yang dikembalikan")
		return
	}

	cert := conn.ConnectionState().PeerCertificates[0]
	expiry := cert.NotAfter
	now := time.Now()

	if now.After(expiry) {
		fmt.Printf("❌ EXPIRED (kadaluarsa pada %s)\n", expiry.Format("2006-01-02"))
		fmt.Printf("   🔴 STATUS: domain sudah tidak memiliki sertifikat SSL yang aktif\n")
		return
	}

	fmt.Printf("✅ Active (kadaluarsa %s)\n", expiry.Format("2006-01-02"))
	fmt.Printf("   📝 Subject: %s\n", cert.Subject.CommonName)
	if len(cert.Issuer.Organization) > 0 {
		fmt.Printf("   🏢 Issuer:  %s\n", cert.Issuer.Organization[0])
	} else if cert.Issuer.CommonName != "" {
		fmt.Printf("   🏢 Issuer:  %s\n", cert.Issuer.CommonName)
	}

	daysRemaining := int(time.Until(expiry).Hours() / 24)
	fmt.Printf("   ⏳ Sisa:    %d hari\n", daysRemaining)
}

func checkDomainExpiry(domain string) {
	domain = normalizeDomain(domain)
	fmt.Print("📅 Domain Expiry: ")

	expiry, err := lookupDomainExpiry(domain)
	if err != nil {
		fmt.Printf("⚠️  %v\n", err)
		return
	}

	if expiry.IsZero() {
		fmt.Println("⚠️  Tidak ada data expiry yang bisa dideteksi dari WHOIS")
		return
	}

	now := time.Now()
	if now.After(expiry) {
		fmt.Printf("❌ EXPIRED (expired pada %s)\n", expiry.Format("2006-01-02"))
		return
	}

	daysRemaining := int(time.Until(expiry).Hours() / 24)
	fmt.Printf("✅ Active (berlaku sampai %s)\n", expiry.Format("2006-01-02"))
	fmt.Printf("   ⏳ Sisa:    %d hari\n", daysRemaining)
}

func lookupDomainExpiry(domain string) (time.Time, error) {
	whoisServer := whoisServerForDomain(domain)
	if whoisServer == "" {
		return time.Time{}, fmt.Errorf("server WHOIS untuk domain %s tidak ditemukan", domain)
	}

	conn, err := net.DialTimeout("tcp", whoisServer+":43", 5*time.Second)
	if err != nil {
		return time.Time{}, fmt.Errorf("gagal menghubungi WHOIS %s: %w", whoisServer, err)
	}
	defer conn.Close()

	if _, err = fmt.Fprintf(conn, domain+"\r\n"); err != nil {
		return time.Time{}, fmt.Errorf("gagal mengirim query ke WHOIS: %w", err)
	}

	response, err := io.ReadAll(conn)
	if err != nil {
		return time.Time{}, fmt.Errorf("gagal membaca respon WHOIS: %w", err)
	}

	text := string(response)
	if strings.Contains(strings.ToLower(text), "no match") || strings.Contains(strings.ToLower(text), "not found") || strings.Contains(strings.ToLower(text), "not registered") {
		return time.Time{}, fmt.Errorf("domain belum terdaftar atau tidak ditemukan di WHOIS")
	}

	expiry, ok := parseWhoisExpiry(text)
	if !ok {
		return time.Time{}, fmt.Errorf("domain ditemukan, tetapi tanggal expiry tidak bisa dibaca dari WHOIS")
	}

	return expiry, nil
}

func whoisServerForDomain(domain string) string {
	lower := strings.ToLower(domain)
	servers := []struct {
		suffix string
		server string
	}{
		{".co.id", "whois.co.id"},
		{".go.id", "whois.kemenag.go.id"},
		{".ac.id", "whois.ac.id"},
		{".id", "whois.pandi.or.id"},
		{".com", "whois.verisign-grs.com"},
		{".net", "whois.verisign-grs.com"},
		{".org", "whois.publicinterestregistry.org"},
		{".info", "whois.afilias.net"},
		{".io", "whois.nic.io"},
		{".me", "whois.nic.me"},
		{".biz", "whois.nic.biz"},
		{".my", "whois.mynic.my"},
		{".xyz", "whois.nic.xyz"},
	}

	for _, candidate := range servers {
		if strings.HasSuffix(lower, candidate.suffix) {
			return candidate.server
		}
	}

	return "whois.iana.org"
}

func parseWhoisExpiry(text string) (time.Time, bool) {
	patterns := []string{
		`(?i)(?:Registry Expiry Date|Domain Expiration Date|Expiration Date|Expiry Date|Expires On|Registrar Registration Expiration Date)\s*[:=]\s*([^\r\n]+)`,
		`(?i)(?:paid-till|renewal date|renewal-date|expires)\s*[:=]\s*([^\r\n]+)`,
		`(?i)(?:Registry Expiry|Domain Expiration|Expiration)\s*[:=]\s*([^\r\n]+)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(text)
		if len(matches) < 2 {
			continue
		}
		value := strings.TrimSpace(matches[1])
		if value == "" {
			continue
		}
		value = strings.Trim(value, "\"'")
		if ts, ok := parseDateValue(value); ok {
			return ts, true
		}
	}

	return time.Time{}, false
}

func parseDateValue(raw string) (time.Time, bool) {
	cleaned := strings.TrimSpace(strings.TrimSuffix(raw, "."))
	cleaned = strings.TrimSuffix(cleaned, " UTC")
	cleaned = strings.TrimSuffix(cleaned, " GMT")
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"2006/01/02",
		"2006.01.02",
	}

	for _, layout := range formats {
		if ts, err := time.Parse(layout, cleaned); err == nil {
			return ts.UTC(), true
		}
	}

	return time.Time{}, false
}

func checkNS(domain string) {
	domain = normalizeDomain(domain)
	fmt.Print("🧭 NS Lookup: ")
	ns, err := net.LookupNS(domain)
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		return
	}

	if len(ns) == 0 {
		fmt.Println("❌ Tidak ada Nameserver yang ditemukan")
		return
	}

	fmt.Println()
	for _, record := range ns {
		fmt.Printf("   - %s\n", record.Host)
	}
}

func checkDNS(domain string) []string {
	fmt.Print("🌐 DNS Pointing: \n")
	ips, err := net.LookupIP(domain)
	if err != nil {
		fmt.Printf("   ❌ Failed to lookup IP: %v\n", err)
		return nil
	}

	var ipStrings []string
	for _, ip := range ips {
		ipStr := ip.String()
		label := "(Direct/Server IP)"
		if isCloudflareIP(ipStr) {
			label = "(Cloudflare IP)"
		}
		fmt.Printf("   - %-40s %s\n", ipStr, label)
		ipStrings = append(ipStrings, ipStr)
	}
	return ipStrings
}

func checkCloudflare(domain string, ips []string) bool {
	fmt.Print("☁️  Cloudflare: ")
	
	// Method 1: Check IP ranges
	isProxiedByIP := false
	for _, ip := range ips {
		if isCloudflareIP(ip) {
			isProxiedByIP = true
			break
		}
	}

	// Method 2: Check Headers
	isProxiedByHeader := false
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + domain)
	if err == nil {
		defer resp.Body.Close()
		if resp.Header.Get("CF-RAY") != "" || strings.ToLower(resp.Header.Get("Server")) == "cloudflare" {
			isProxiedByHeader = true
		}
	}

	if isProxiedByIP || isProxiedByHeader {
		fmt.Println("🟠 Proxied (Orange Cloud Active)")
		return true
	}

	fmt.Println("⚪ Not Proxied")
	return false
}

func verifyOrigin(domain, originIP string, isProxied bool) {
	fmt.Printf("🎯 Origin Verification [%s]: \n", originIP)

	// 1. Check HTTP Connection
	fmt.Print("   🌐 HTTP Status: ")
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, originIP+":80")
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	
	req, _ := http.NewRequest("GET", "http://"+domain, nil)
	resp, err := client.Do(req)
	
	httpOk := false
	if err != nil {
		fmt.Printf("❌ HTTP failed: %v\n", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			fmt.Printf("✅ %d OK (Sesuai)\n", resp.StatusCode)
			httpOk = true
		} else {
			fmt.Printf("⚠️  %d (Merespons tapi status error)\n", resp.StatusCode)
		}
	}

	// 2. Check Origin SSL (on port 443)
	fmt.Print("   🔒 Origin SSL:  ")
	conf := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true,
	}
	
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", originIP+":443", conf)
	if err != nil {
		fmt.Printf("❌ Gagal connect ke port 443: %v\n", err)
		printVerdict(false, false, isProxied)
		return
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]
	expiry := cert.NotAfter
	
	// Check if domain matches certificate subject or SANs
	dnsMatch := false
	if cert.Subject.CommonName == domain || strings.Contains(cert.Subject.CommonName, "*."+strings.SplitN(domain, ".", 2)[1]) {
		dnsMatch = true
	}
	for _, names := range cert.DNSNames {
		if names == domain || (strings.HasPrefix(names, "*.") && strings.HasSuffix(domain, names[2:])) {
			dnsMatch = true
			break
		}
	}

	if dnsMatch {
		fmt.Printf("✅ Match (Expires %s)\n", expiry.Format("2006-01-02"))
	} else {
		fmt.Printf("❌ MISMATCH (Sertifikat untuk: %s)\n", cert.Subject.CommonName)
	}

	fmt.Printf("      📝 Subject: %s\n", cert.Subject.CommonName)
	if len(cert.Issuer.Organization) > 0 {
		fmt.Printf("      🏢 Issuer:  %s\n", cert.Issuer.Organization[0])
	} else {
		fmt.Printf("      🏢 Issuer:  %s\n", cert.Issuer.CommonName)
	}
	
	printVerdict(httpOk, dnsMatch, isProxied)
}

func printVerdict(httpOk, sslMatch bool, isProxied bool) {
	fmt.Print("\n   🚩 KESIMPULAN: ")
	if httpOk && sslMatch {
		fmt.Println("🌟 INTEGRASI SEMPURNA! Ini adalah Origin yang benar.")
	} else if sslMatch {
		fmt.Println("🌗 SETENGAH COCOK. SSL benar tapi HTTP error (mungkin firewall/config server).")
	} else {
		fmt.Println("🚫 BUKAN ORIGIN. IP ini tidak melayani domain Anda dengan benar.")
	}

	if isProxied && (httpOk || sslMatch) {
		fmt.Println("      (Trafik publik disembunyikan Cloudflare, tapi di dalam pointing sudah benar)")
	}
}
