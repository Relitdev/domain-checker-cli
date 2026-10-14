package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
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
		fmt.Printf("🚀 Domain Checker CLI\n\n")
		fmt.Printf("PENGGUNAAN:\n")
		fmt.Printf("  checkdomain -domain <domain> [opsi lainnya]\n\n")
		fmt.Printf("OPSI:\n")
		fmt.Print("  -domain string\n")
		fmt.Print("    \tNama Domain yang ingin dicek (contoh: google.com atau web.desa.id)\n")
		fmt.Print("  -origin string\n")
		fmt.Print("    \tAlamat IP server asli (Origin IP) untuk verifikasi pointing dan SSL asli\n")
		fmt.Print("  -url string\n")
		fmt.Print("    \tURL khusus untuk cek uptime (hanya URL ini yang dicek, config diabaikan)\n")
		fmt.Print("  -config string\n")
		fmt.Print("    \tPath file YAML berisi daftar URL uptime (opsional, hanya dibaca jika diisi)\n")
		fmt.Printf("\nCONTOH:\n")
		fmt.Printf("  checkdomain -domain google.com\n")
		fmt.Printf("  checkdomain -domain example.id -origin 103.154.142.172\n")
		fmt.Printf("  checkdomain -domain example.com -url https://example.com/login\n")
		fmt.Printf("  checkdomain -domain example.com -config config/config.yml\n\n")
		fmt.Printf("FITUR:\n")
		fmt.Printf("  ✅ Cek status dan masa berlaku SSL (HTTPS) + SAN\n")
		fmt.Printf("  🔗 Verifikasi trust chain browser (AUTHORITY/COMMON_NAME/DATE_INVALID)\n")
		fmt.Printf("  📅 Cek masa berlaku domain (expired atau masih aktif) via WHOIS\n")
		fmt.Printf("  🧭 Cek NS (Nameserver) untuk domain\n")
		fmt.Printf("  🩺 Cek uptime cepat dan status HTTP (200/3xx/4xx/5xx)\n")
		fmt.Printf("  🌐 Cek IP Pointing (A/AAAA Records) dengan label Cloudflare\n")
		fmt.Printf("  ☁️  Deteksi status Proxy Cloudflare (Orange Cloud)\n")
		fmt.Printf("  🎯 Verifikasi Origin IP (memastikan pointing Cloudflare benar ke server Anda)\n")
	}

	domain := flag.String("domain", "", "Domain to check")
	customURL := flag.String("url", "", "Custom URL for quick uptime test")
	configPath := flag.String("config", "", "Path to optional uptime config YAML (hanya dibaca jika diisi)")
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

	// 3. Uptime / quick status check
	checkUptime(*domain, *customURL, *configPath)

	// 4. NS Lookup
	checkNS(*domain)

	// 5. DNS Pointing Check
	ips := checkDNS(*domain)

	// 6. Cloudflare Check
	isCF := checkCloudflare(*domain, ips)

	// 7. Origin Verification
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
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", domain+":443", &tls.Config{InsecureSkipVerify: true, ServerName: domain})
	if err != nil {
		fmt.Printf("❌ Tidak bisa konek ke HTTPS: %v\n", err)
		return
	}
	defer conn.Close()

	if len(conn.ConnectionState().PeerCertificates) == 0 {
		fmt.Println("❌ Tidak ada sertifikat TLS yang dikembalikan")
		return
	}

	certs := conn.ConnectionState().PeerCertificates
	cert := certs[0]
	expiry := cert.NotAfter
	now := time.Now()

	if now.After(expiry) {
		fmt.Printf("❌ EXPIRED (kadaluarsa pada %s)\n", expiry.Format("2006-01-02"))
		fmt.Printf("   🔴 STATUS: domain sudah tidak memiliki sertifikat SSL yang aktif\n")
		fmt.Printf("   🌐 Browser: net::ERR_CERT_DATE_INVALID\n")
		return
	}

	fmt.Printf("✅ Active (kadaluarsa %s)\n", expiry.Format("2006-01-02"))
	fmt.Printf("   📝 Subject: %s\n", cert.Subject.CommonName)
	if len(cert.DNSNames) > 0 {
		fmt.Printf("   🔖 SAN:     %s\n", strings.Join(cert.DNSNames, ", "))
	}
	if len(cert.Issuer.Organization) > 0 {
		fmt.Printf("   🏢 Issuer:  %s\n", cert.Issuer.Organization[0])
	} else if cert.Issuer.CommonName != "" {
		fmt.Printf("   🏢 Issuer:  %s\n", cert.Issuer.CommonName)
	}

	daysRemaining := int(time.Until(expiry).Hours() / 24)
	fmt.Printf("   ⏳ Sisa:    %d hari\n", daysRemaining)

	checkTrustChain(domain, cert, certs)
}

func isSelfSigned(cert *x509.Certificate) bool {
	if cert.Subject.String() == cert.Issuer.String() {
		return true
	}
	return cert.CheckSignatureFrom(cert) == nil
}

func checkTrustChain(domain string, leaf *x509.Certificate, chain []*x509.Certificate) {
	fmt.Print("   🔗 Chain:   ")
	if isSelfSigned(leaf) {
		fmt.Println("❌ TIDAK DIPERCAYA BROWSER (net::ERR_CERT_AUTHORITY_INVALID)")
		fmt.Printf("      Penyebab: self-signed (Subject == Issuer: %s)\n", leaf.Subject.CommonName)
		fmt.Println("      Solusi: pasang sertifikat dari CA publik (misal Let's Encrypt) di server/IP tujuan")
		return
	}

	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	opts := x509.VerifyOptions{
		DNSName:       domain,
		Intermediates: intermediates,
	}

	if _, err := leaf.Verify(opts); err != nil {
		var unknownErr x509.UnknownAuthorityError
		var hostnameErr x509.HostnameError
		var invalidErr x509.CertificateInvalidError
		switch {
		case errors.As(err, &unknownErr):
			fmt.Println("❌ TIDAK DIPERCAYA BROWSER (net::ERR_CERT_AUTHORITY_INVALID)")
			fmt.Printf("      Penyebab: %v\n", err)
		case errors.As(err, &hostnameErr):
			fmt.Println("❌ TIDAK DIPERCAYA BROWSER (net::ERR_CERT_COMMON_NAME_INVALID)")
			fmt.Printf("      Penyebab: hostname tidak cocok: %v\n", err)
		case errors.As(err, &invalidErr) && invalidErr.Reason == x509.Expired:
			fmt.Println("❌ TIDAK DIPERCAYA BROWSER (net::ERR_CERT_DATE_INVALID)")
			fmt.Printf("      Penyebab: %v\n", err)
		default:
			fmt.Printf("❌ TIDAK DIPERCAYA BROWSER (%v)\n", err)
		}
		fmt.Println("      Solusi: cek chain/intermediate, pastikan fullchain terpasang dan CN/SAN mencakup domain ini")
		return
	}

	fmt.Println("✅ Dipercaya (rantai valid ke root CA sistem)")
}

func checkDomainExpiry(domain string) {
	domain = normalizeDomain(domain)
	fmt.Print("📅 Domain Expiry: ")

	target := registrableDomain(domain)
	if target != domain {
		fmt.Printf("\n   ℹ️  %s adalah subdomain, cek WHOIS ke parent %s\n   ", domain, target)
	}

	expiry, err := lookupDomainExpiry(target)
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

// registrableDomain mengembalikan domain yang terdaftar di WHOIS (eTLD+1
// versi ringan tanpa dependensi eksternal). Contoh: sabintulung.desa.id -> desa.id,
// sub.example.co.id -> example.co.id, deep.sub.example.com -> example.com.
func registrableDomain(domain string) string {
	lower := strings.ToLower(strings.TrimSpace(domain))
	labels := strings.Split(lower, ".")
	if len(labels) <= 2 {
		return lower
	}

	// Second-level .id yang registrasinya di tingkat 3 (contoh: example.co.id).
	secondLevelID := map[string]bool{
		"co.id": true, "go.id": true, "ac.id": true, "or.id": true,
		"sch.id": true, "mil.id": true, "web.id": true, "my.id": true,
		"biz.id": true, "net.id": true, "ponpes.id": true,
	}
	suffix2 := strings.Join(labels[len(labels)-2:], ".")
	if secondLevelID[suffix2] {
		if len(labels) >= 3 {
			return strings.Join(labels[len(labels)-3:], ".")
		}
		return lower
	}

	return strings.Join(labels[len(labels)-2:], ".")
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

func checkUptime(domain, customURL, configPath string) {
	urls := loadUptimeTargets(domain, customURL, configPath)
	if len(urls) == 0 {
		fmt.Println("🩺 Uptime Check: ❌ Tidak ada URL yang bisa diperiksa")
		return
	}

	fmt.Println("🩺 Uptime Check:")
	for _, target := range urls {
		fmt.Printf("   - %s -> ", target)
		statusCode, err := quickHTTPStatus(target)
		if err != nil {
			fmt.Printf("❌ %v\n", err)
			continue
		}

		switch {
		case statusCode >= 200 && statusCode < 300:
			fmt.Printf("✅ %d OK\n", statusCode)
		case statusCode >= 300 && statusCode < 400:
			fmt.Printf("↩️  %d Redirect\n", statusCode)
		case statusCode >= 400 && statusCode < 500:
			fmt.Printf("⚠️  %d Client Error\n", statusCode)
		case statusCode >= 500:
			fmt.Printf("🚨 %d Server Error\n", statusCode)
		default:
			fmt.Printf("ℹ️  %d\n", statusCode)
		}
	}
}

func loadUptimeTargets(domain, customURL, configPath string) []string {
	if customURL != "" {
		return []string{normalizeURL(customURL)}
	}

	var urls []string
	if configPath != "" {
		if data, err := os.ReadFile(configPath); err == nil {
			for _, match := range regexp.MustCompile(`(?m)^\s*[-:]?\s*(?:url|endpoint|site|target)\s*[:=]\s*(https?://\S+)`).FindAllStringSubmatch(string(data), -1) {
				if len(match) > 1 {
					urls = append(urls, normalizeURL(match[1]))
				}
			}
			for _, match := range regexp.MustCompile(`(?m)^\s*-\s*(https?://\S+)`).FindAllStringSubmatch(string(data), -1) {
				if len(match) > 1 {
					urls = append(urls, normalizeURL(match[1]))
				}
			}
		}
	}

	if len(urls) == 0 {
		urls = append(urls, normalizeURL("https://"+normalizeDomain(domain)))
	}

	return uniqueStrings(urls)
}

func normalizeURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	trimmed = strings.Trim(trimmed, "\"'")
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		return trimmed
	}
	return "https://" + trimmed
}

func uniqueStrings(items []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		result = append(result, item)
	}
	return result
}

func quickHTTPStatus(target string) (int, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
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
