package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
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
		fmt.Print("    	Nama Domain yang ingin dicek (contoh: google.com atau web.desa.id)\n")
		fmt.Print("  -origin string\n")
		fmt.Print("    	Alamat IP server asli (Origin IP) untuk verifikasi pointing dan SSL asli\n")
		fmt.Printf("\nCONTOH:\n")
		fmt.Printf("  checkdomain -domain google.com\n")
		fmt.Printf("  checkdomain -domain opendesa.id -origin 103.154.142.172\n\n")
		fmt.Printf("FITUR:\n")
		fmt.Printf("  ✅ Cek status dan masa berlaku SSL (HTTPs)\n")
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

	// 2. DNS Pointing Check
	ips := checkDNS(*domain)

	// 3. Cloudflare Check
	isCF := checkCloudflare(*domain, ips)

	// 4. Origin Verification
	if *expectedOrigin != "" {
		verifyOrigin(*domain, *expectedOrigin, isCF)
	} else if isCF {
		fmt.Println("💡 Penjelasan: Domain ini di-proxy oleh Cloudflare.")
		fmt.Println("   Untuk memastikan pointing benar, jalankan dengan -origin <IP_SERVER_ANDA>")
	}

	fmt.Println(strings.Repeat("-", 40))
}

func checkSSL(domain string) {
	fmt.Print("🔒 SSL Status: ")
	// Use port 443 for SSL check
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", domain+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		fmt.Printf("❌ Failed to connect: %v\n", err)
		return
	}
	defer conn.Close()

	if len(conn.ConnectionState().PeerCertificates) == 0 {
		fmt.Println("❌ No certificates found")
		return
	}

	cert := conn.ConnectionState().PeerCertificates[0]
	expiry := cert.NotAfter
	now := time.Now()

	fmt.Printf("✅ Active (Expires on %s)\n", expiry.Format("2006-01-02"))
	fmt.Printf("   📝 Subject: %s\n", cert.Subject.CommonName)
	fmt.Printf("   🏢 Issuer:  %s\n", cert.Issuer.Organization[0])

	if now.After(expiry) {
		fmt.Printf("   🔴 STATUS:  EXPIRED (since %s)\n", expiry.Format("2006-01-02"))
	} else {
		daysRemaining := int(expiry.Sub(now).Hours() / 24)
		fmt.Printf("   ⏳ Sisa:    %d hari\n", daysRemaining)
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
	
	if err != nil {
		fmt.Printf("❌ HTTP failed: %v\n", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 500 {
			fmt.Printf("✅ HTTP OK (Origin is replying)\n")
		} else {
			fmt.Printf("⚠️  HTTP Status %d\n", resp.StatusCode)
		}
	}

	// 2. Check Origin SSL (on port 443)
	fmt.Print("   🔒 Origin SSL: ")
	conf := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true,
	}
	
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", originIP+":443", conf)
	if err != nil {
		fmt.Printf("❌ Failed to connect: %v\n", err)
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
		fmt.Printf("✅ Active (Expires on %s)\n", expiry.Format("2006-01-02"))
	} else {
		fmt.Printf("⚠️  MISMATCH (Expires on %s)\n", expiry.Format("2006-01-02"))
		fmt.Printf("      ⚠️  Warning: Domain tidak cocok dengan sertifikat di IP ini!\n")
	}

	fmt.Printf("      📝 Subject: %s\n", cert.Subject.CommonName)
	if len(cert.Issuer.Organization) > 0 {
		fmt.Printf("      🏢 Issuer:  %s\n", cert.Issuer.Organization[0])
	} else {
		fmt.Printf("      🏢 Issuer:  %s\n", cert.Issuer.CommonName)
	}
	
	if isProxied {
		fmt.Println("   💡 Info: SSL yang anda lihat di atas adalah SSL asli di server Anda (Origin).")
		fmt.Println("      Sedangkan SSL di hasil awal adalah SSL milik Cloudflare (Edge).")
	}
}
