package reverseip

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ReverseIPCert holds TLS certificate details discovered for an IP
type ReverseIPCert struct {
	IP        string   `json:"ip"`
	SubjectCN string   `json:"subject_cn,omitempty"`
	SANs      []string `json:"sans,omitempty"`
	Issuer    string   `json:"issuer,omitempty"`
	NotBefore string   `json:"not_before,omitempty"`
	NotAfter  string   `json:"not_after,omitempty"`
}

// PortProbe holds lightweight port probe results
type PortProbe struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Open    bool   `json:"open"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
	Proto   string `json:"protocol,omitempty"` // "tcp" or "tls" or "http"
}

// ASNInfo contains RDAP/ASN-like data
type ASNInfo struct {
	CIDR          string `json:"cidr,omitempty"`
	ASN           string `json:"asn,omitempty"`
	ASName        string `json:"as_name,omitempty"`
	Registry      string `json:"registry,omitempty"`
	AllocationOrg string `json:"org,omitempty"`
	Country       string `json:"country,omitempty"`
	Handle        string `json:"handle,omitempty"`
	AbuseEmail    string `json:"abuse_contact,omitempty"`
}

// GeoInfo contains quick geolocation fields
type GeoInfo struct {
	Country  string  `json:"country,omitempty"`
	Region   string  `json:"region,omitempty"`
	City     string  `json:"city,omitempty"`
	Lat      float64 `json:"lat,omitempty"`
	Lon      float64 `json:"lon,omitempty"`
	ISP      string  `json:"isp,omitempty"`
	Org      string  `json:"org,omitempty"`
	QueryIP  string  `json:"query_ip,omitempty"`
	Timezone string  `json:"timezone,omitempty"`
}

// ReverseIPResult is a comprehensive result for a single LookupDetailed call
type ReverseIPResult struct {
	Input             string              `json:"input"`
	ResolvedIPs       []string            `json:"resolved_ips,omitempty"`
	PTRs              map[string][]string `json:"ptrs,omitempty"` // ip -> []ptrs
	DomainsFromAPI    []string            `json:"domains_from_api,omitempty"`
	DomainsFromCerts  []string            `json:"domains_from_certs,omitempty"`
	CurrentDomains    []string            `json:"domains_current,omitempty"` // domains that resolve to these IPs at time of check
	Certs             []ReverseIPCert     `json:"certificates,omitempty"`
	PortProbes        []PortProbe         `json:"port_probes,omitempty"`
	ASN               *ASNInfo            `json:"asn,omitempty"`
	Geo               *GeoInfo            `json:"geolocation,omitempty"`
	Notes             []string            `json:"notes,omitempty"`
	Timestamp         string              `json:"timestamp,omitempty"`
	RawRDAP           json.RawMessage     `json:"raw_rdap,omitempty"`
	RawHackertarget   string              `json:"raw_hackertarget,omitempty"`
	RawGeoProviderRaw string              `json:"raw_geo_provider,omitempty"`
}

// Lookup (legacy/compat) — returns a slice of domain strings (keeps existing callers happy).
// Internally it calls LookupDetailed and returns DomainsFromAPI (or a synthesized list).
func Lookup(input string) ([]string, error) {
	d, err := LookupDetailed(input)
	if err != nil {
		// If detailed failed but returned partial data, prefer partial rather than failing hard.
		if len(d.DomainsFromAPI) > 0 {
			return d.DomainsFromAPI, nil
		}
		if len(d.DomainsFromCerts) > 0 {
			return d.DomainsFromCerts, nil
		}
		if len(d.PTRs) > 0 {
			out := []string{}
			for _, v := range d.PTRs {
				out = append(out, v...)
			}
			if len(out) > 0 {
				return dedupeSorted(out), nil
			}
		}
		notes := strings.Join(d.Notes, " | ")
		if notes != "" {
			return []string{notes}, nil
		}
		return nil, err
	}

	// Prefer API domains, then certs, then PTRs
	if len(d.DomainsFromAPI) > 0 {
		return dedupeSorted(d.DomainsFromAPI), nil
	}
	if len(d.DomainsFromCerts) > 0 {
		return dedupeSorted(d.DomainsFromCerts), nil
	}
	if len(d.PTRs) > 0 {
		out := []string{}
		for _, v := range d.PTRs {
			out = append(out, v...)
		}
		return dedupeSorted(out), nil
	}
	return []string{}, nil
}

// LookupDetailed performs rich reverse-IP discovery and returns structured data.
//
// Steps performed:
//   - Resolve input (domain) -> IP(s) if required.
//   - Query hackertarget reverseiplookup (public API) for domains (rate-limited).
//   - PTR (reverse DNS) lookups for each IP.
//   - TLS handshake on 443 and 8443 for cert CN + SANs.
//   - Lightweight port probes on a small set of common ports (banners).
//   - Geolocation via public IP geolocation endpoint (ip-api.com).
//   - RDAP lookup (tries ARIN/RIPE/APNIC/LACNIC/AFRINIC endpoints in order).
//
// The function favors safety (timeouts) and is resilient to partial failures.
func LookupDetailed(input string) (ReverseIPResult, error) {
	res := ReverseIPResult{
		Input:     input,
		PTRs:      map[string][]string{},
		Notes:     []string{},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	// 1) Resolve to IP(s)
	ips := []string{}
	if parsed := net.ParseIP(input); parsed != nil {
		ips = append(ips, input)
	} else {
		// domain -> A/AAAA
		addrs, err := net.LookupHost(input)
		if err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("DNS resolve failed: %v", err))
			// continue — maybe API returns domains
		} else {
			ips = append(ips, addrs...)
		}
	}
	ips = dedupeSorted(ips)
	res.ResolvedIPs = ips

	// 2) Query Hackertarget reverse IP API (public, rate-limited)
	apiDomains, apiRaw, apiErr := queryHackertarget(input)
	if apiErr != nil {
		res.Notes = append(res.Notes, fmt.Sprintf("hackertarget: %v", apiErr))
	}
	res.RawHackertarget = apiRaw
	if len(apiDomains) > 0 {
		res.DomainsFromAPI = apiDomains
	}

	// 3) If we don't have IPs (input was domain and failed resolving), attempt to extract IPs by resolving a few domains
	if len(ips) == 0 && len(res.DomainsFromAPI) > 0 {
		for _, d := range res.DomainsFromAPI {
			if len(ips) >= 8 {
				break
			}
			adds, _ := net.LookupHost(d)
			for _, a := range adds {
				ips = append(ips, a)
			}
		}
		ips = dedupeSorted(ips)
		res.ResolvedIPs = ips
	}

	// 4) For each IP: PTR, certs, probes, rdap, geo
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Port list for light probing — can be extended or made configurable
	commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 3306, 3389, 5900, 8080, 8443}

	for _, ip := range ips {
		ip := ip
		wg.Add(1)
		go func() {
			defer wg.Done()

			// PTR
			ptrs, err := net.LookupAddr(ip)
			if err == nil && len(ptrs) > 0 {
				clean := make([]string, 0, len(ptrs))
				for _, p := range ptrs {
					clean = append(clean, strings.TrimSuffix(p, "."))
				}
				mu.Lock()
				res.PTRs[ip] = dedupeSorted(clean)
				mu.Unlock()
			} else if err != nil {
				mu.Lock()
				res.Notes = append(res.Notes, fmt.Sprintf("PTR lookup %s: %v", ip, err))
				mu.Unlock()
			}

			// TLS certificates on 443 & 8443 (SNI: use Input if it's a domain)
			for _, p := range []int{443, 8443} {
				certInfo, cerr := fetchCert(ip, p, input)
				if cerr != nil {
					mu.Lock()
					// record note but don't fail entirely
					res.Notes = append(res.Notes, fmt.Sprintf("cert fetch %s:%d: %v", ip, p, cerr))
					mu.Unlock()
					continue
				}
				if certInfo != nil {
					mu.Lock()
					res.Certs = append(res.Certs, *certInfo)
					mu.Unlock()
				}
			}

			// Lightweight port probes
			probes, perr := probePorts(ip, commonPorts, 600*time.Millisecond, input)
			if perr != nil {
				mu.Lock()
				res.Notes = append(res.Notes, fmt.Sprintf("port probes %s: %v", ip, perr))
				mu.Unlock()
			}
			if len(probes) > 0 {
				mu.Lock()
				res.PortProbes = append(res.PortProbes, probes...)
				mu.Unlock()
			}

			// Geo (only once; store first successful)
			mu.Lock()
			geoWasNil := (res.Geo == nil)
			mu.Unlock()
			if geoWasNil {
				geo, raw, gerr := fetchGeoSimple(ip)
				mu.Lock()
				if gerr == nil && geo != nil {
					res.Geo = geo
					res.RawGeoProviderRaw = raw
				} else if gerr != nil {
					res.Notes = append(res.Notes, fmt.Sprintf("geo lookup %s: %v", ip, gerr))
				}
				mu.Unlock()
			}

			// RDAP / ASN (only once; store first successful)
			mu.Lock()
			asnWasNil := (res.ASN == nil)
			mu.Unlock()
			if asnWasNil {
				asn, raw, rerr := fetchRDAP(ip)
				mu.Lock()
				if rerr == nil && asn != nil {
					res.ASN = asn
					res.RawRDAP = raw
				} else if rerr != nil {
					res.Notes = append(res.Notes, fmt.Sprintf("rdap %s: %v", ip, rerr))
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// 5) Build CurrentDomains: check which discovered domains (API + cert SANs + PTRs) currently resolve to any of the resolved IPs
	candidates := []string{}
	candidates = append(candidates, res.DomainsFromAPI...)
	for _, c := range res.Certs {
		candidates = append(candidates, c.SANs...)
		if c.SubjectCN != "" {
			candidates = append(candidates, c.SubjectCN)
		}
	}
	for _, ptrs := range res.PTRs {
		candidates = append(candidates, ptrs...)
	}
	candidates = dedupeSorted(filterHostnames(candidates))

	curmap := map[string]struct{}{}
	for _, dom := range candidates {
		addrs, err := net.LookupHost(dom)
		if err != nil || len(addrs) == 0 {
			continue
		}
		for _, a := range addrs {
			for _, ip := range res.ResolvedIPs {
				if a == ip {
					curmap[dom] = struct{}{}
				}
			}
		}
	}
	for d := range curmap {
		res.CurrentDomains = append(res.CurrentDomains, d)
	}
	sort.Strings(res.CurrentDomains)

	// 6) synthesize DomainsFromCerts (dedupe)
	dcerts := []string{}
	for _, c := range res.Certs {
		if c.SubjectCN != "" {
			dcerts = append(dcerts, c.SubjectCN)
		}
		dcerts = append(dcerts, c.SANs...)
	}
	res.DomainsFromCerts = dedupeSorted(filterHostnames(dcerts))

	// 7) final dedupe/sort for API domains
	res.DomainsFromAPI = dedupeSorted(filterHostnames(res.DomainsFromAPI))

	// If nothing meaningful, return error with notes
	if len(res.ResolvedIPs) == 0 && len(res.DomainsFromAPI) == 0 && len(res.Certs) == 0 && len(res.PTRs) == 0 {
		return res, fmt.Errorf("no useful reverse-ip data found; notes: %s", strings.Join(res.Notes, " | "))
	}

	return res, nil
}

// ----------- Helpers below -----------

// queryHackertarget calls public hackertarget reverseiplookup API.
// Returns list of domains (or an empty list) and raw response string.
func queryHackertarget(q string) ([]string, string, error) {
	u := fmt.Sprintf("https://api.hackertarget.com/reverseiplookup/?q=%s", url.QueryEscape(q))
	c := &http.Client{Timeout: 12 * time.Second}
	resp, err := c.Get(u)
	if err != nil {
		return nil, "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// read text body
	scanner := bufio.NewScanner(resp.Body)
	lines := []string{}
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	raw := strings.Join(lines, "\n")
	if resp.StatusCode != 200 {
		// return raw text as note if rate-limited
		return []string{raw}, raw, fmt.Errorf("api status %s", resp.Status)
	}
	out := []string{}
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		out = append(out, l)
	}
	return out, raw, nil
}

// fetchCert performs a TLS handshake to gather cert info for ip:port using optional sniHint.
func fetchCert(ip string, port int, sniHint string) (*ReverseIPCert, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	cfg := &tls.Config{InsecureSkipVerify: true}
	// prefer SNI when hint is domain-like
	if sniHint != "" && net.ParseIP(sniHint) == nil {
		cfg.ServerName = sniHint
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates presented")
	}
	c := state.PeerCertificates[0]
	ci := ReverseIPCert{
		IP:        ip,
		SubjectCN: c.Subject.CommonName,
		Issuer:    c.Issuer.CommonName,
		NotBefore: c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:  c.NotAfter.UTC().Format(time.RFC3339),
	}
	for _, n := range c.DNSNames {
		ci.SANs = append(ci.SANs, n)
	}
	for _, a := range c.IPAddresses {
		ci.SANs = append(ci.SANs, a.String())
	}
	ci.SANs = dedupeSorted(ci.SANs)
	return &ci, nil
}

// probePorts does simple TCP connect + banner for a list of ports on an IP.
// returns slice of PortProbe.
func probePorts(ip string, ports []int, timeout time.Duration, sniHint string) ([]PortProbe, error) {
	sem := make(chan struct{}, 50)
	var wg sync.WaitGroup
	var mu sync.Mutex
	out := []PortProbe{}

	for _, p := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
			conn, err := net.DialTimeout("tcp", addr, timeout)
			probe := PortProbe{
				IP:    ip,
				Port:  port,
				Open:  false,
				Proto: "tcp",
			}
			if err != nil {
				// closed/filtered
				mu.Lock()
				out = append(out, probe)
				mu.Unlock()
				return
			}
			// connection succeeded
			probe.Open = true

			// quick banner attempt
			_ = conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
			// for HTTP-like ports try HEAD
			if port == 80 || port == 8080 || port == 8000 || port == 8888 {
				fmt.Fprintf(conn, "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: ReconNio/1.0\r\nConnection: close\r\n\r\n", sniHint)
				r := bufio.NewReader(conn)
				line, _ := r.ReadString('\n')
				probe.Banner = strings.TrimSpace(line)
				probe.Proto = "http"
				// try to find Server header if available
				rest, _ := ioReadAllTimeout(r, 300*time.Millisecond)
				if hv := extractHeaderValue(string(rest), "Server"); hv != "" && probe.Banner == "" {
					probe.Banner = hv
				}
			} else {
				// try TLS handshake on common TLS ports
				if port == 443 || port == 8443 || port == 9443 {
					cfg := &tls.Config{InsecureSkipVerify: true}
					if sniHint != "" && net.ParseIP(sniHint) == nil {
						cfg.ServerName = sniHint
					}
					tconn := tls.Client(conn, cfg)
					if err := tconn.Handshake(); err == nil {
						state := tconn.ConnectionState()
						probe.Proto = "tls"
						if len(state.PeerCertificates) > 0 {
							c := state.PeerCertificates[0]
							probe.Banner = fmt.Sprintf("CN=%s, SANs=%v", c.Subject.CommonName, c.DNSNames)
						}
						_ = tconn.Close()
					} else {
						// fallback to raw read
						buf := make([]byte, 1024)
						n, _ := conn.Read(buf)
						if n > 0 {
							probe.Banner = strings.TrimSpace(string(buf[:n]))
						}
					}
				} else {
					// raw banner
					buf := make([]byte, 1024)
					n, _ := conn.Read(buf)
					if n > 0 {
						probe.Banner = strings.TrimSpace(string(buf[:n]))
					}
				}
			}
			_ = conn.Close()
			// try to fill well-known service name if empty
			if probe.Service == "" {
				probe.Service = serviceByPort(port)
			}
			mu.Lock()
			out = append(out, probe)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	// sort by port
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out, nil
}

// fetchGeoSimple uses ip-api.com (free, limited) to get quick geolocation info
func fetchGeoSimple(ip string) (*GeoInfo, string, error) {
	u := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,regionName,city,lat,lon,isp,org,query,timezone,message", url.QueryEscape(ip))
	c := &http.Client{Timeout: 6 * time.Second}
	resp, err := c.Get(u)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, "", err
	}
	rawb, _ := json.Marshal(raw)
	if raw["status"] == "fail" {
		msg := ""
		if s, ok := raw["message"].(string); ok {
			msg = s
		}
		return nil, string(rawb), fmt.Errorf("geo provider failed: %s", msg)
	}
	g := &GeoInfo{}
	if v, ok := raw["country"].(string); ok {
		g.Country = v
	}
	if v, ok := raw["regionName"].(string); ok {
		g.Region = v
	}
	if v, ok := raw["city"].(string); ok {
		g.City = v
	}
	if v, ok := raw["isp"].(string); ok {
		g.ISP = v
	}
	if v, ok := raw["org"].(string); ok {
		g.Org = v
	}
	if v, ok := raw["query"].(string); ok {
		g.QueryIP = v
	}
	if v, ok := raw["timezone"].(string); ok {
		g.Timezone = v
	}
	if lat, ok := raw["lat"].(float64); ok {
		g.Lat = lat
	}
	if lon, ok := raw["lon"].(float64); ok {
		g.Lon = lon
	}
	return g, string(rawb), nil
}

// fetchRDAP attempts to fetch RDAP info from several common RDAP endpoints.
// It returns lightweight ASNInfo and raw JSON response (first successful).
func fetchRDAP(ip string) (*ASNInfo, json.RawMessage, error) {
	rdapEndpoints := []string{
		"https://rdap.arin.net/registry/ip/%s",
		"https://rdap.db.ripe.net/ip/%s",
		"https://rdap.apnic.net/ip/%s",
		"https://rdap.lacnic.net/rdap/ip/%s",
		"https://rdap.afri.nic.net/rdap/ip/%s",
	}

	client := &http.Client{Timeout: 8 * time.Second}
	var lastErr error
	for _, tmpl := range rdapEndpoints {
		u := fmt.Sprintf(tmpl, url.QueryEscape(ip))
		resp, err := client.Get(u)
		if err != nil {
			lastErr = err
			continue
		}
		raw, err := ioReadAllTimeout(resp.Body, 2*time.Second)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("rdap %s -> %s", u, resp.Status)
			continue
		}
		// parse some fields if available
		var parsed map[string]any
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			// still return raw if unparseable
			return nil, json.RawMessage(raw), nil
		}
		asn := &ASNInfo{}
		if v, ok := parsed["handle"].(string); ok {
			asn.Handle = v
		}
		if v, ok := parsed["name"].(string); ok {
			asn.ASName = v
		}
		if v, ok := parsed["country"].(string); ok {
			asn.Country = v
		}
		// look for entities for abuse contact
		if entities, ok := parsed["entities"].([]any); ok {
			for _, e := range entities {
				if emap, ok := e.(map[string]any); ok {
					if roles, ok := emap["roles"].([]any); ok && len(roles) > 0 {
						for _, r := range roles {
							if rs, ok := r.(string); ok && strings.Contains(strings.ToLower(rs), "abuse") {
								if vcard, ok := emap["vcardArray"].([]any); ok && len(vcard) > 1 {
									if items, ok := vcard[1].([]any); ok {
										for _, item := range items {
											if it, ok := item.([]any); ok && len(it) >= 4 {
												key, _ := it[0].(string)
												val := it[3]
												if key == "email" {
													if s, sok := val.(string); sok {
														asn.AbuseEmail = s
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
		// try some hints for CIDR
		if v, ok := parsed["startAddress"].(string); ok {
			asn.CIDR = v
		}
		// try to detect ASN from fields
		for _, key := range []string{"autnum", "asn"} {
			if vv, ok := parsed[key]; ok {
				if s, ok := vv.(string); ok {
					asn.ASN = s
				}
			}
		}
		return asn, json.RawMessage(raw), nil
	}
	return nil, nil, lastErr
}

// Utility: read remaining body with a small timeout for blocking readers.
func ioReadAllTimeout(r io.Reader, d time.Duration) (string, error) {
	br := bufio.NewReader(r)
	ch := make(chan string, 1)
	errCh := make(chan error, 1)

	go func() {
		var sb strings.Builder
		buf := make([]byte, 1024)
		for {
			n, err := br.Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
			}
			if err != nil {
				if err == io.EOF {
					ch <- sb.String()
					return
				}
				errCh <- err
				return
			}
		}
	}()

	select {
	case s := <-ch:
		return s, nil
	case e := <-errCh:
		return "", e
	case <-time.After(d):
		return "", fmt.Errorf("read timeout")
	}
}

// extractHeaderValue looks for header: value lines inside a raw HTTP-like block
func extractHeaderValue(raw, header string) string {
	h := strings.ToLower(header)
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := sc.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			if strings.ToLower(strings.TrimSpace(parts[0])) == h {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// filterHostnames keeps only plausible hostnames / domain-looking strings
func filterHostnames(in []string) []string {
	out := []string{}
	rxh := regexp.MustCompile(`^[a-z0-9A-Z\-\_\.]+\.[a-zA-Z]{2,}$`)
	for _, s := range in {
		if s == "" {
			continue
		}
		s = strings.TrimSpace(strings.ToLower(s))
		// strip url parts
		s = strings.TrimPrefix(s, "http://")
		s = strings.TrimPrefix(s, "https://")
		s = strings.TrimSuffix(s, "/")
		// remove wildcard prefix
		if strings.HasPrefix(s, "*.") {
			s = strings.TrimPrefix(s, "*.")
		}
		if rxh.MatchString(s) {
			out = append(out, s)
		}
	}
	return dedupeSorted(out)
}

// dedupeSorted returns deduplicated sorted strings
func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return in
	}
	seen := map[string]struct{}{}
	out := []string{}
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// serviceByPort provides common service name guesses
func serviceByPort(p int) string {
	common := map[int]string{
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		25:   "smtp",
		53:   "dns",
		80:   "http",
		110:  "pop3",
		143:  "imap",
		443:  "https",
		445:  "microsoft-ds",
		587:  "smtp-submission",
		3306: "mysql",
		3389: "rdp",
		5900: "vnc",
		8080: "http-alt",
		8443: "https-alt",
	}
	if s, ok := common[p]; ok {
		return s
	}
	return ""
}
