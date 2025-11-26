package http

// Enhanced ReconHTTP that captures actual request headers (including final headers after redirect)
// and returns a rich HTTPReport (request + response + TLS + page analysis).

import (
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	stdhttp "net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// HTTPReport holds enriched results from an HTTP request + TLS details.
type HTTPReport struct {
	// Request side (actual)
	RequestMethod  string
	RequestURL     string
	RequestHeaders map[string][]string

	// Normalized target used by client
	Target           string
	NormalizedTarget string

	// Response side
	StatusCode      int
	Redirects       []string
	ResponseTimeMS  int64
	Headers         map[string][]string
	SecurityHeaders map[string]string
	Cookies         []HTTPCookie
	Title           string
	MetaTags        map[string]string
	JsFiles         []string
	Comments        []string
	Server          string
	XPoweredBy      string
	ContentType     string
	ContentLength   int64
	Compression     string
	AllowedMethods  []string
	Protocols       []string // TLS/HTTP protocols inferred (e.g., TLS1.2, TLS1.3, HTTP/2)
	TLS             *SSLInfo
	HTTP2           bool
	HTTP3Hint       bool // Alt-Svc / QUIC hints
	FaviconSHA1     string
	PageSize        int64
	Compressed      bool
	DirectoryHits   []string
	OpenRedirects   []string
	CORS            string
	TechCMS         []string
	TechFramework   []string
	WAFs            []string
}

// HTTPCookie describes cookie + flags
type HTTPCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"http_only"`
	SameSite string `json:"same_site"`
}

// SSLInfo describes certificate + connection info
type SSLInfo struct {
	Issuer       string    `json:"issuer"`
	Subject      string    `json:"subject"`
	ValidFrom    time.Time `json:"valid_from"`
	ValidTo      time.Time `json:"valid_to"`
	SANs         []string  `json:"sans"`
	Protocol     string    `json:"protocol"`
	Cipher       string    `json:"cipher"`
	IsExpired    bool      `json:"is_expired"`
	IsSelfSigned bool      `json:"is_self_signed"`
	OCSPStapled  bool      `json:"ocsp_stapled"`
	ALPN         string    `json:"alpn"`
}

func sameSiteToString(s stdhttp.SameSite) string {
	switch s {
	case stdhttp.SameSiteDefaultMode:
		return "Default"
	case stdhttp.SameSiteLaxMode:
		return "Lax"
	case stdhttp.SameSiteStrictMode:
		return "Strict"
	case stdhttp.SameSiteNoneMode:
		return "None"
	default:
		return "Unknown"
	}
}

// ReconHTTP performs a rich HTTP recon on a target (domain or host).
// It captures the actual request headers sent and returns them alongside response analysis.
func ReconHTTP(target string) (*HTTPReport, error) {
	normalized := target
	if !strings.HasPrefix(normalized, "http://") && !strings.HasPrefix(normalized, "https://") {
		normalized = "https://" + normalized
	}

	report := &HTTPReport{
		Target:           target,
		NormalizedTarget: normalized,
		Headers:          map[string][]string{},
		SecurityHeaders:  map[string]string{},
		MetaTags:         map[string]string{},
		JsFiles:          []string{},
		Comments:         []string{},
		DirectoryHits:    []string{},
		OpenRedirects:    []string{},
		TechCMS:          []string{},
		TechFramework:    []string{},
		WAFs:             []string{},
		RequestHeaders:   map[string][]string{},
	}

	// track redirects seen by the client
	redirects := []string{}
	client := &stdhttp.Client{
		Timeout: 18 * time.Second,
		CheckRedirect: func(req *stdhttp.Request, via []*stdhttp.Request) error {
			redirects = append(redirects, req.URL.String())
			if len(via) >= 10 {
				return stdhttp.ErrUseLastResponse
			}
			return nil
		},
	}

	// Build the request explicitly so we can inspect the exact headers we set.
	req, err := stdhttp.NewRequest("GET", report.NormalizedTarget, nil)
	if err != nil {
		return nil, err
	}

	// sensible defaults we want to send
	req.Header.Set("User-Agent", "ReconNio/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	// Keep-Alive / Connection header is typically handled by Transport; adding common header for visibility.
	req.Header.Set("Connection", "keep-alive")

	// capture request method & initial headers
	report.RequestMethod = req.Method
	report.RequestURL = req.URL.String()
	// copy initial request headers
	for k, v := range req.Header {
		report.RequestHeaders[k] = append([]string{}, v...)
	}
	// include Host explicitly
	if req.Host != "" {
		report.RequestHeaders["Host"] = []string{req.Host}
	} else if req.URL != nil {
		report.RequestHeaders["Host"] = []string{req.URL.Host}
	}

	// send request
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		// fallback to http if https fails
		if strings.HasPrefix(report.NormalizedTarget, "https://") {
			alt := "http://" + strings.TrimPrefix(report.NormalizedTarget, "https://")
			req2, err2 := stdhttp.NewRequest("GET", alt, nil)
			if err2 == nil {
				// copy same headers
				req2.Header = req.Header.Clone()
				if r2, err3 := client.Do(req2); err3 == nil {
					resp = r2
					report.NormalizedTarget = alt
				} else {
					return nil, fmt.Errorf("both https and http fetch failed: %w", err)
				}
			} else {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	defer resp.Body.Close()
	elapsed := time.Since(start)

	// If the client followed redirects, resp.Request corresponds to the final request.
	// Capture actual final request headers/method if available (this is what was actually sent last).
	if resp.Request != nil {
		report.RequestMethod = resp.Request.Method
		report.RequestURL = resp.Request.URL.String()
		report.RequestHeaders = map[string][]string{}
		for k, v := range resp.Request.Header {
			report.RequestHeaders[k] = append([]string{}, v...)
		}
		// ensure Host present
		if resp.Request.Host != "" {
			report.RequestHeaders["Host"] = []string{resp.Request.Host}
		} else if resp.Request.URL != nil {
			report.RequestHeaders["Host"] = []string{resp.Request.URL.Host}
		}
	}

	// Response summary
	report.StatusCode = resp.StatusCode
	report.ResponseTimeMS = elapsed.Milliseconds()
	report.Headers = map[string][]string(resp.Header)
	report.Server = resp.Header.Get("Server")
	report.XPoweredBy = resp.Header.Get("X-Powered-By")
	report.ContentType = resp.Header.Get("Content-Type")
	report.ContentLength = resp.ContentLength
	report.Compression = resp.Header.Get("Content-Encoding")

	// Redirect chain: include captured redirects and final URL
	if len(redirects) > 0 {
		report.Redirects = append([]string{}, redirects...)
	}
	if resp.Request != nil && resp.Request.URL != nil {
		final := resp.Request.URL.String()
		if len(report.Redirects) == 0 || report.Redirects[len(report.Redirects)-1] != final {
			report.Redirects = append(report.Redirects, final)
		}
	}

	// TLS / SSL info
	if resp.TLS != nil {
		report.Protocols = append(report.Protocols, tlsVersionName(resp.TLS.Version))
		report.TLS = &SSLInfo{
			Protocol:    tlsVersionName(resp.TLS.Version),
			Cipher:      tlsCipherSuiteName(resp.TLS.CipherSuite),
			ALPN:        resp.TLS.NegotiatedProtocol,
			OCSPStapled: len(resp.TLS.OCSPResponse) > 0,
		}
		if len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			report.TLS.Issuer = cert.Issuer.String()
			report.TLS.Subject = cert.Subject.String()
			report.TLS.ValidFrom = cert.NotBefore
			report.TLS.ValidTo = cert.NotAfter
			report.TLS.SANs = cert.DNSNames
			report.TLS.IsExpired = time.Now().After(cert.NotAfter)
			report.TLS.IsSelfSigned = cert.Issuer.String() == cert.Subject.String()
		}
		if resp.ProtoMajor == 2 || resp.TLS.NegotiatedProtocol == "h2" {
			report.HTTP2 = true
			report.Protocols = append(report.Protocols, "HTTP/2")
		}
		if resp.TLS.NegotiatedProtocol != "" {
			report.Protocols = append(report.Protocols, resp.TLS.NegotiatedProtocol)
		}
	}

	// Alt-Svc -> HTTP/3 hints
	if alt := resp.Header.Get("Alt-Svc"); alt != "" {
		if strings.Contains(strings.ToLower(alt), "h3") || strings.Contains(strings.ToLower(alt), "quic") {
			report.HTTP3Hint = true
			report.Protocols = append(report.Protocols, "HTTP/3(hint)")
		}
	}

	// Security headers
	securityKeys := []string{
		"Strict-Transport-Security",
		"X-Frame-Options",
		"X-XSS-Protection",
		"X-Content-Type-Options",
		"Content-Security-Policy",
		"Access-Control-Allow-Origin",
		"Referrer-Policy",
		"Permissions-Policy",
	}
	for _, k := range securityKeys {
		v := resp.Header.Get(k)
		if v == "" {
			report.SecurityHeaders[k] = "⚠️ Not Implemented"
		} else {
			report.SecurityHeaders[k] = v
		}
	}

	// Cookies
	for _, c := range resp.Cookies() {
		report.Cookies = append(report.Cookies, HTTPCookie{
			Name:     c.Name,
			Value:    c.Value,
			Secure:   c.Secure,
			HttpOnly: c.HttpOnly,
			SameSite: sameSiteToString(c.SameSite),
		})
	}

	// Read body (limited)
	const maxRead = int64(5 * 1024 * 1024) // 5 MB
	var reader io.Reader = resp.Body
	if resp.ContentLength > 0 && resp.ContentLength < maxRead {
		// read as is
	} else {
		reader = io.LimitReader(resp.Body, maxRead)
	}
	bodyBytes, _ := io.ReadAll(reader)
	bodyStr := string(bodyBytes)
	report.PageSize = int64(len(bodyBytes))
	report.Compressed = strings.Contains(strings.ToLower(report.Compression), "gzip") || strings.Contains(strings.ToLower(report.Compression), "br")

	// HTML parsing (title, meta, scripts, comments)
	if doc, err := html.Parse(strings.NewReader(bodyStr)); err == nil {
		report.Title = extractTitle(doc)
		report.MetaTags = extractMeta(doc)
		report.JsFiles = extractJS(doc)
		report.Comments = extractComments(bodyStr)
	} else {
		if t := quickTitle(bodyStr); t != "" {
			report.Title = t
		}
	}

	// Simple tech fingerprinting (page heuristics)
	bodyLower := strings.ToLower(bodyStr)
	if strings.Contains(bodyLower, "wp-content") || strings.Contains(bodyLower, "wp-includes") || strings.Contains(bodyLower, "wordpress") {
		report.TechCMS = append(report.TechCMS, "WordPress")
	}
	if strings.Contains(bodyLower, "drupal") || strings.Contains(bodyLower, "sites/default") {
		report.TechCMS = append(report.TechCMS, "Drupal")
	}
	if strings.Contains(bodyLower, "joomla") {
		report.TechCMS = append(report.TechCMS, "Joomla")
	}
	if strings.Contains(bodyLower, "laravel") {
		report.TechFramework = append(report.TechFramework, "Laravel")
	}
	if strings.Contains(bodyLower, "django") || strings.Contains(bodyLower, "csrfmiddlewaretoken") {
		report.TechFramework = append(report.TechFramework, "Django")
	}
	if strings.Contains(bodyLower, "flask") {
		report.TechFramework = append(report.TechFramework, "Flask")
	}
	if strings.Contains(bodyLower, "react") && strings.Contains(bodyLower, "data-reactroot") {
		report.TechFramework = append(report.TechFramework, "React")
	} else if strings.Contains(bodyLower, "ng-version") || strings.Contains(bodyLower, "angular") {
		report.TechFramework = append(report.TechFramework, "Angular")
	} else if strings.Contains(bodyLower, "vue") {
		report.TechFramework = append(report.TechFramework, "Vue.js")
	}

	// WAF/CDN heuristics via headers
	if _, ok := report.Headers["Cf-Ray"]; ok || strings.Contains(strings.ToLower(report.Server), "cloudflare") {
		report.WAFs = append(report.WAFs, "Cloudflare")
	}
	if _, ok := report.Headers["X-CDN"]; ok {
		report.WAFs = append(report.WAFs, "CDN (X-CDN)")
	}

	// OPTIONS -> allowed methods
	optReq, _ := stdhttp.NewRequest("OPTIONS", report.NormalizedTarget, nil)
	optReq.Header.Set("User-Agent", "ReconNio/1.0")
	if optResp, err := client.Do(optReq); err == nil {
		allow := optResp.Header.Get("Allow")
		if allow != "" {
			parts := strings.Split(allow, ",")
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			report.AllowedMethods = parts
		}
		optResp.Body.Close()
	}

	// Favicon hash (SHA1)
	if u, err := url.Parse(report.NormalizedTarget); err == nil {
		fav := fmt.Sprintf("%s://%s/favicon.ico", u.Scheme, u.Host)
		if fr, ferr := client.Get(fav); ferr == nil {
			if fr.StatusCode >= 200 && fr.StatusCode < 300 {
				b, _ := io.ReadAll(io.LimitReader(fr.Body, 1024*128))
				h := sha1.Sum(b)
				report.FaviconSHA1 = hex.EncodeToString(h[:])
			}
			fr.Body.Close()
		}
	}

	// Small safe directory probe (short list)
	dirs := []string{"/admin", "/administrator", "/login", "/wp-login.php", "/xmlrpc.php", "/robots.txt", "/.git/", "/.env", "/backup", "/backup.zip"}
	for _, p := range dirs {
		full := strings.TrimRight(report.NormalizedTarget, "/") + p
		headReq, _ := stdhttp.NewRequest("HEAD", full, nil)
		headReq.Header.Set("User-Agent", "ReconNio/1.0")
		if r2, err := client.Do(headReq); err == nil {
			if r2.StatusCode >= 200 && r2.StatusCode < 400 {
				report.DirectoryHits = append(report.DirectoryHits, fmt.Sprintf("%s -> %d", p, r2.StatusCode))
			}
			r2.Body.Close()
		}
	}

	// Open redirect checks
	redirectParamNames := []string{"next", "url", "redirect", "return", "r", "goto"}
	parsedBase, _ := url.Parse(report.NormalizedTarget)
	origHost := parsedBase.Hostname()
	for _, param := range redirectParamNames {
		q := parsedBase.Query()
		q.Set(param, "https://example.com/unique-callback")
		parsedBase.RawQuery = q.Encode()
		testURL := parsedBase.String()

		clientNoRedirect := *client
		clientNoRedirect.CheckRedirect = func(req *stdhttp.Request, via []*stdhttp.Request) error { return stdhttp.ErrUseLastResponse }
		if rr, err := clientNoRedirect.Get(testURL); err == nil {
			if loc := rr.Header.Get("Location"); loc != "" {
				if u2, perr := url.Parse(loc); perr == nil {
					if u2.Hostname() != "" && u2.Hostname() != origHost {
						report.OpenRedirects = append(report.OpenRedirects, fmt.Sprintf("%s => %s (param %s)", testURL, loc, param))
					}
				}
			}
			rr.Body.Close()
		}
	}

	// CORS
	aco := resp.Header.Get("Access-Control-Allow-Origin")
	if aco == "" {
		report.CORS = "Not present"
	} else if aco == "*" {
		report.CORS = "Wildcard: * (potentially unsafe)"
	} else {
		report.CORS = aco
	}

	// finalize protocol list (dedupe)
	report.Protocols = uniqueStrings(report.Protocols)

	return report, nil
}

// FetchHeaders returns only raw headers (compatibility)
func FetchHeaders(domain string) (map[string][]string, error) {
	r, err := ReconHTTP(domain)
	if err != nil {
		return nil, err
	}
	return r.Headers, nil
}

// ---------- helpers ----------
func uniqueStrings(in []string) []string {
	set := map[string]struct{}{}
	out := []string{}
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := set[s]; !ok {
			set[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

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

func tlsCipherSuiteName(id uint16) string {
	if name := tls.CipherSuiteName(id); name != "" {
		return name
	}
	return fmt.Sprintf("0x%x", id)
}

// HTML helpers
func extractTitle(n *html.Node) string {
	if n == nil {
		return ""
	}
	if n.Type == html.ElementNode && n.Data == "title" && n.FirstChild != nil {
		return strings.TrimSpace(n.FirstChild.Data)
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if t := extractTitle(c); t != "" {
			return t
		}
	}
	return ""
}

func quickTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title")
	if start == -1 {
		return ""
	}
	i := strings.Index(body[start:], ">")
	if i == -1 {
		return ""
	}
	body2 := body[start+i+1:]
	end := strings.Index(strings.ToLower(body2), "</title>")
	if end == -1 {
		return ""
	}
	return strings.TrimSpace(body2[:end])
}

func extractMeta(n *html.Node) map[string]string {
	meta := make(map[string]string)
	var crawl func(*html.Node)
	crawl = func(n *html.Node) {
		if n == nil {
			return
		}
		if n.Type == html.ElementNode && n.Data == "meta" {
			var name, content string
			for _, a := range n.Attr {
				if strings.EqualFold(a.Key, "name") || strings.EqualFold(a.Key, "property") {
					name = a.Val
				}
				if strings.EqualFold(a.Key, "content") {
					content = a.Val
				}
			}
			if name != "" {
				meta[name] = content
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			crawl(c)
		}
	}
	crawl(n)
	return meta
}

func extractJS(n *html.Node) []string {
	js := []string{}
	var crawl func(*html.Node)
	crawl = func(n *html.Node) {
		if n == nil {
			return
		}
		if n.Type == html.ElementNode && n.Data == "script" {
			for _, a := range n.Attr {
				if strings.EqualFold(a.Key, "src") && a.Val != "" {
					js = append(js, a.Val)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			crawl(c)
		}
	}
	crawl(n)
	return js
}

func extractComments(body string) []string {
	comments := []string{}
	parts := strings.Split(body, "<!--")
	for _, p := range parts[1:] {
		if strings.Contains(p, "-->") {
			comments = append(comments, strings.Split(p, "-->")[0])
		}
	}
	return comments
}
