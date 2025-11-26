package ports

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// PortResult holds detailed info about a scanned port.
type PortResult struct {
	Port       int      `json:"port"`
	Open       bool     `json:"open"`
	Service    string   `json:"service,omitempty"`
	Banner     string   `json:"banner,omitempty"`
	Protocol   string   `json:"protocol,omitempty"`    // "tcp", "http", "tls", "ssh", ...
	TLSVersion string   `json:"tls_version,omitempty"` // human readable
	TLSCipher  string   `json:"tls_cipher,omitempty"`
	Error      string   `json:"error,omitempty"`
	ExtraLines []string `json:"extra_lines,omitempty"`
}

// -----------------------------------------------------------------------------
// Configuration / defaults
// -----------------------------------------------------------------------------

// commonPorts is the default list scanned by ScanPorts / ScanPortsDetailed.
// It contains a compact set of common and important service ports.
// Adjust or replace this list when you want top-1000 or full-range scanning.
var commonPorts = []int{
	21, 22, 23, 25, 53, 67, 68, 69,
	80, 88, 110, 111, 119, 123, 135, 139,
	143, 161, 179, 194, 389, 443, 445, 465,
	514, 587, 631, 636, 873, 993, 995, 1080,
	1433, 1521, 1723, 1883, 2049, 3306, 3389,
	4443, 5060, 5432, 5900, 6379, 8000, 8080,
	8443, 9000, 9001, 2222, 992, 9922, 2525,
	27017, 5000, 5001, 5984, 7001, 7002, 8008, 8081,
	8181, 9200, 9300, 11211, 27018, 50070, 50075,
	5985, 5986, 4500, 500, 3000, 3001, 4200, 4201,
	6060, 54321, 33060, 11212, 2323, 49152, 49153,
	5901, 5902, 6378, 3307, 5983, 8888, 9090, 9443,
	10000, 18080,
}

// DefaultScanCount returns the number of ports scanned by default.
func DefaultScanCount() int {
	return len(commonPorts)
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

// ScanPorts scans the default commonPorts for the given target using the provided timeout per connect.
// It prints a human-readable line for each open port and returns a sorted slice of open port numbers.
func ScanPorts(target string, timeout time.Duration) ([]int, error) {
	results, err := ScanPortsDetailed(target, timeout, commonPorts)
	if err != nil {
		return nil, err
	}

	open := []int{}
	for _, r := range results {
		if r.Open {
			open = append(open, r.Port)
			service := r.Service
			if service == "" {
				service = "unknown"
			}
			banner := r.Banner
			if banner == "" {
				if r.Protocol == "tls" && r.TLSVersion != "" {
					banner = fmt.Sprintf("%s / %s", r.TLSVersion, r.TLSCipher)
				}
			}
			if banner == "" {
				banner = "(no banner)"
			}
			fmt.Printf("[Port %d] open | Service: %s | Banner: %s\n", r.Port, service, strings.TrimSpace(banner))
		}
	}
	sort.Ints(open)
	return open, nil
}

// ScanPortsDetailed scans the provided ports slice on target and returns detailed results.
func ScanPortsDetailed(target string, timeout time.Duration, portsToScan []int) ([]PortResult, error) {
	host := normalizeTargetHost(target)
	if host == "" {
		return nil, fmt.Errorf("empty target")
	}

	const concurrency = 200
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	outCh := make(chan PortResult, len(portsToScan))

	for _, p := range portsToScan {
		p := p
		sem <- struct{}{}
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			outCh <- probePort(host, port, timeout)
		}(p)
	}

	wg.Wait()
	close(outCh)

	results := make([]PortResult, 0, len(portsToScan))
	for r := range outCh {
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
	return results, nil
}

// -----------------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------------

// normalizeTargetHost strips scheme if present and returns host/ip only.
func normalizeTargetHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		if u, err := url.Parse(raw); err == nil {
			h := u.Hostname()
			if h != "" {
				return h
			}
		}
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return host
	}
	return raw
}

// wellKnownService returns a heuristic name for common ports.
func wellKnownService(port int) string {
	switch port {
	case 20, 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "dns"
	case 67, 68:
		return "dhcp"
	case 69:
		return "tftp"
	case 80:
		return "http"
	case 110:
		return "pop3"
	case 119:
		return "nntp"
	case 123:
		return "ntp"
	case 143:
		return "imap"
	case 161:
		return "snmp"
	case 179:
		return "bgp"
	case 194:
		return "irc"
	case 389:
		return "ldap"
	case 443:
		return "https"
	case 445:
		return "microsoft-ds"
	case 465, 587:
		return "smtp"
	case 636:
		return "ldaps"
	case 993:
		return "imaps"
	case 995:
		return "pop3s"
	case 1433:
		return "mssql"
	case 1521:
		return "oracle"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	case 5900:
		return "vnc"
	case 6379:
		return "redis"
	case 8000, 8080:
		return "http-alt"
	case 8443:
		return "https-alt"
	case 5432:
		return "postgres"
	default:
		return ""
	}
}

// probePort attempts to connect to host:port and perform banner grabbing / protocol detection.
func probePort(host string, port int, timeout time.Duration) PortResult {
	res := PortResult{Port: port, Service: wellKnownService(port)}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		res.Open = false
		res.Error = err.Error()
		return res
	}
	res.Open = true
	// ensure connection closed at the end
	defer conn.Close()

	// short timeouts for banner reads
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)

	// service-specific probing (grouped cases, no duplicates)
	switch port {
	case 80, 8000, 8080, 8081, 8008:
		// HTTP plain: send HEAD to get status line + headers quickly
		req := fmt.Sprintf("HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: ReconNio/1.0\r\nConnection: close\r\n\r\n", host)
		_, _ = conn.Write([]byte(req))
		status, _ := reader.ReadString('\n')
		res.Protocol = "http"
		res.Banner = strings.TrimSpace(status)
		collectHTTPHeaders(reader, &res)
	case 443, 8443:
		// TLS handshake for version/cipher + optional banner peek
		_ = conn.Close()
		tinfo, banner, err := doTLSHandshake(host, port, timeout)
		if err != nil {
			res.Error = err.Error()
			return res
		}
		res.Protocol = "tls"
		res.TLSVersion = tinfo.Version
		res.TLSCipher = tinfo.Cipher
		res.Banner = banner
	case 22:
		// SSH sends banner immediately
		line, _ := reader.ReadString('\n')
		res.Protocol = "ssh"
		res.Banner = strings.TrimSpace(line)
	case 21:
		// FTP banner
		line, _ := reader.ReadString('\n')
		res.Protocol = "ftp"
		res.Banner = strings.TrimSpace(line)
	case 25:
		// SMTP banner
		line, _ := reader.ReadString('\n')
		res.Protocol = "smtp"
		res.Banner = strings.TrimSpace(line)
	case 110, 995:
		line, _ := reader.ReadString('\n')
		res.Protocol = "pop3"
		res.Banner = strings.TrimSpace(line)
	case 143, 993:
		line, _ := reader.ReadString('\n')
		res.Protocol = "imap"
		res.Banner = strings.TrimSpace(line)
	default:
		// Generic banner grab: try to read some bytes
		buf := make([]byte, 1024)
		n, _ := reader.Read(buf)
		if n > 0 {
			res.Banner = strings.TrimSpace(string(buf[:n]))
		} else {
			// fallback: try a small HTTP HEAD probe to detect http-like services
			tryReq := fmt.Sprintf("HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: ReconNio/1.0\r\nConnection: close\r\n\r\n", host)
			_, _ = conn.Write([]byte(tryReq))
			status, _ := reader.ReadString('\n')
			if strings.HasPrefix(status, "HTTP/") {
				res.Protocol = "http"
				res.Banner = strings.TrimSpace(status)
				collectHTTPHeaders(reader, &res)
			}
		}
	}

	return res
}

// collectHTTPHeaders reads up to the end of headers and captures Server and other useful lines.
func collectHTTPHeaders(reader *bufio.Reader, r *PortResult) {
	headers := make(map[string]string)
	for i := 0; i < 50; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			headers[strings.ToLower(k)] = v
		}
	}
	// prefer Server header if present
	if s, ok := headers["server"]; ok {
		if r.Banner == "" {
			r.Banner = "Server: " + s
		} else {
			r.ExtraLines = append(r.ExtraLines, "Server: "+s)
		}
	}
	if cl, ok := headers["content-length"]; ok {
		r.ExtraLines = append(r.ExtraLines, "Content-Length: "+cl)
	}
	if ce, ok := headers["content-encoding"]; ok {
		r.ExtraLines = append(r.ExtraLines, "Content-Encoding: "+ce)
	}
}

// tlsInfo holds TLS handshake result
type tlsInfo struct {
	Version string
	Cipher  string
}

// doTLSHandshake performs TLS handshake using a dialer and returns TLS version + cipher and any initial data read.
func doTLSHandshake(host string, port int, timeout time.Duration) (tlsInfo, string, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return tlsInfo{}, "", err
	}

	// configure TLS (use SNI when target is a hostname)
	cfg := &tls.Config{InsecureSkipVerify: true}
	if net.ParseIP(host) == nil && host != "" {
		cfg.ServerName = host
	}

	tlsConn := tls.Client(rawConn, cfg)
	_ = tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		return tlsInfo{}, "", err
	}
	state := tlsConn.ConnectionState()
	vers := tlsVersionName(state.Version)
	cipher := tls.CipherSuiteName(state.CipherSuite)

	// peek a small amount of data (some servers may send something after handshake)
	_ = tlsConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1024)
	n, _ := tlsConn.Read(buf)
	banner := ""
	if n > 0 {
		banner = strings.TrimSpace(string(buf[:n]))
	}
	_ = tlsConn.Close()
	return tlsInfo{Version: vers, Cipher: cipher}, banner, nil
}

// tlsVersionName returns human-readable TLS version code
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionSSL30:
		return "SSLv3"
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("unknown(0x%x)", v)
	}
}
