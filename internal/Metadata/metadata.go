package metadata

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	htmlnode "golang.org/x/net/html"
)

// ---------- Types ----------

type CookieInfo struct {
	Name     string `json:"name"`
	Value    string `json:"value,omitempty"`
	HttpOnly bool   `json:"httponly"`
	Secure   bool   `json:"secure"`
	SameSite string `json:"samesite,omitempty"`
	Raw      string `json:"raw,omitempty"`
}

type CertInfo struct {
	IP           string   `json:"ip"`
	SubjectCN    string   `json:"subject_cn,omitempty"`
	SANs         []string `json:"sans,omitempty"`
	Issuer       string   `json:"issuer,omitempty"`
	IssuerOrg    string   `json:"issuer_org,omitempty"`
	NotBefore    string   `json:"not_before,omitempty"`
	NotAfter     string   `json:"not_after,omitempty"`
	IsExpired    bool     `json:"is_expired,omitempty"`
	IsSelfSigned bool     `json:"is_self_signed,omitempty"`
}

type ASNInfo struct {
	CIDR          string `json:"cidr,omitempty"`
	ASN           string `json:"asn,omitempty"`
	ASName        string `json:"as_name,omitempty"`
	Registry      string `json:"registry,omitempty"`
	AllocationOrg string `json:"org,omitempty"`
	Country       string `json:"country,omitempty"`
	Handle        string `json:"handle,omitempty"`
	AbuseEmail    string `json:"abuse_contact,omitempty"`
	Raw           string `json:"raw,omitempty"`
}

// MetadataResult is the aggregated result
type MetadataResult struct {
	// Basic
	RequestedURL string              `json:"requested_url,omitempty"`
	FinalURL     string              `json:"final_url,omitempty"`
	Status       int                 `json:"status,omitempty"`
	Headers      map[string][]string `json:"headers,omitempty"`

	// Timing
	ResponseTimeMs int64 `json:"response_time_ms,omitempty"`

	// Server / HTTP
	Server          string   `json:"server,omitempty"`
	ContentType     string   `json:"content_type,omitempty"`
	ContentLength   int64    `json:"content_length,omitempty"`
	ContentEncoding string   `json:"content_encoding,omitempty"`
	ETag            string   `json:"etag,omitempty"`
	CacheControl    string   `json:"cache_control,omitempty"`
	LastModified    string   `json:"last_modified,omitempty"`
	RedirectChain   []string `json:"redirect_chain,omitempty"`
	AllowedMethods  []string `json:"allowed_methods,omitempty"`
	HTTP2           bool     `json:"http2,omitempty"`
	HTTP3Hint       bool     `json:"http3_hint,omitempty"`

	// Security headers (subset)
	SecurityHeaders map[string]string `json:"security_headers,omitempty"`
	CSPDirectives   map[string]string `json:"csp_directives,omitempty"`

	// Cookies
	SetCookies []string     `json:"set_cookie_headers,omitempty"`
	Cookies    []CookieInfo `json:"cookies,omitempty"`

	// Robots & sitemap
	RobotsTxt   string   `json:"robots_txt,omitempty"`
	Sitemaps    []string `json:"sitemaps,omitempty"`
	SitemapURLs []string `json:"sitemap_urls,omitempty"`

	// HTML/SEO
	Title           string            `json:"title,omitempty"`
	HTMLLang        string            `json:"html_lang,omitempty"`
	MetaTags        map[string]string `json:"meta_tags,omitempty"`
	OGTags          map[string]string `json:"og_tags,omitempty"`
	TwitterTags     map[string]string `json:"twitter_tags,omitempty"`
	Canonical       string            `json:"canonical,omitempty"`
	Alternates      map[string]string `json:"alternates,omitempty"`
	Manifest        string            `json:"manifest,omitempty"`
	ThemeColor      string            `json:"theme_color,omitempty"`
	Refresh         string            `json:"meta_refresh,omitempty"`
	JSONLD          []string          `json:"json_ld,omitempty"` // raw (truncated)
	Trackers        []string          `json:"trackers_detected,omitempty"`
	ScriptSrcs      []string          `json:"script_srcs,omitempty"`
	Links           []string          `json:"link_hrefs,omitempty"`
	InlineScriptCnt int               `json:"inline_script_count,omitempty"`
	ExternalLinkCnt int               `json:"external_link_count,omitempty"`
	InternalLinkCnt int               `json:"internal_link_count,omitempty"`
	HasSRI          bool              `json:"has_sri,omitempty"`
	Generator       string            `json:"generator_meta,omitempty"`
	FaviconSHA1     string            `json:"favicon_sha1,omitempty"`
	FaviconSize     int64             `json:"favicon_size,omitempty"`

	// Tech detection
	Frameworks []string `json:"frameworks_detected,omitempty"`
	XPoweredBy string   `json:"x_powered_by,omitempty"`

	// DNS / TLS / RDAP
	ResolvedIPs []string            `json:"resolved_ips,omitempty"`
	PTRs        map[string][]string `json:"ptrs,omitempty"`
	Certs       []CertInfo          `json:"certificates,omitempty"`
	TLSVersion  string              `json:"tls_version,omitempty"` // best-effort (first successful)
	CipherSuite string              `json:"cipher_suite,omitempty"`
	ASN         *ASNInfo            `json:"asn,omitempty"`
	RawRDAP     string              `json:"raw_rdap,omitempty"`

	MXRecords  []string `json:"mx_records,omitempty"`
	NSRecords  []string `json:"ns_records,omitempty"`
	TXTRecords []string `json:"txt_records,omitempty"`
	SPF        string   `json:"spf_record,omitempty"`
	DMARC      string   `json:"dmarc_record,omitempty"`

	// Raw snippet (truncated) for debugging
	RawHTMLSnippet string `json:"raw_html_snippet,omitempty"`

	// Notes/errors
	Notes []string `json:"notes,omitempty"`

	// Timestamp
	Timestamp string `json:"timestamp,omitempty"`
}

// ---------- public API ----------

// FetchMetadata fetches and analyzes metadata for a target URL or hostname.
// If input has no scheme it will prefer https:// and fallback to http:// if needed.
func FetchMetadata(target string) (*MetadataResult, error) {
	m := &MetadataResult{
		RequestedURL: target,
		Headers:      map[string][]string{},
		MetaTags:     map[string]string{},
		OGTags:       map[string]string{},
		TwitterTags:  map[string]string{},
		Alternates:   map[string]string{},
		Trackers:     []string{},
		PTRs:         map[string][]string{},
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
	}

	// prepare URL
	u, err := normalizeURL(target)
	if err != nil {
		return nil, err
	}
	m.RequestedURL = u.String()

	// redirect collector
	redirects := []string{}

	// HTTP client with redirect capture and modest timeouts
	client := &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// capture the redirect destination
			if req != nil && req.URL != nil {
				redirects = append(redirects, req.URL.String())
			}
			// let the client follow up to 10 redirects
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// perform GET (prefer https)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	req.Header.Set("User-Agent", "ReconNio/1.0 (+https://github.com/shii9/ReconNio)")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		// try fallback to http if https failed
		if u.Scheme == "https" {
			fu := *u
			fu.Scheme = "http"
			ctx2, cancel2 := context.WithTimeout(context.Background(), 18*time.Second)
			defer cancel2()
			req2, _ := http.NewRequestWithContext(ctx2, http.MethodGet, fu.String(), nil)
			req2.Header.Set("User-Agent", req.Header.Get("User-Agent"))
			resp2, err2 := client.Do(req2)
			if err2 == nil {
				resp = resp2
				u = &fu
			} else {
				return nil, fmt.Errorf("http(s) request failed: https err=%v, http err=%v", err, err2)
			}
		} else {
			return nil, fmt.Errorf("request failed: %w", err)
		}
	}
	defer resp.Body.Close()

	m.ResponseTimeMs = time.Since(start).Milliseconds()

	// capture final URL (after redirects)
	if resp.Request != nil && resp.Request.URL != nil {
		m.FinalURL = resp.Request.URL.String()
	} else {
		m.FinalURL = u.String()
	}

	if len(redirects) > 0 {
		m.RedirectChain = dedupeStrings(redirects)
	}

	// basic header fields
	m.Status = resp.StatusCode
	m.Headers = resp.Header
	if s := resp.Header.Get("Server"); s != "" {
		m.Server = s
		m.XPoweredBy = resp.Header.Get("X-Powered-By")
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		m.ContentType = ct
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" {
		m.ContentEncoding = ce
	}
	if et := resp.Header.Get("Etag"); et != "" {
		m.ETag = et
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "" {
		m.CacheControl = cc
	}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		m.LastModified = lm
	}
	if cl := resp.ContentLength; cl > 0 {
		m.ContentLength = cl
	}

	// HTTP2 detection
	if resp.ProtoMajor >= 2 {
		m.HTTP2 = true
	}
	// HTTP3 hint via Alt-Svc header (contains h3 or http3)
	if alt := resp.Header.Get("Alt-Svc"); strings.Contains(strings.ToLower(alt), "h3") || strings.Contains(strings.ToLower(alt), "http3") {
		m.HTTP3Hint = true
	}

	// Allowed methods
	if allow := resp.Header.Get("Allow"); allow != "" {
		methods := strings.Split(allow, ",")
		for i := range methods {
			methods[i] = strings.TrimSpace(methods[i])
		}
		m.AllowedMethods = dedupeStrings(methods)
	}

	// security headers
	secHeaders := []string{
		"Content-Security-Policy",
		"Strict-Transport-Security",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Referrer-Policy",
		"Permissions-Policy",
		"X-Robots-Tag",
		"Expect-CT",
		"Feature-Policy",
		"Server-Timing",
	}
	m.SecurityHeaders = map[string]string{}
	for _, k := range secHeaders {
		if v := resp.Header.Get(k); v != "" {
			m.SecurityHeaders[k] = v
			if k == "Content-Security-Policy" {
				m.CSPDirectives = parseCSP(v)
			}
		}
	}

	// cookies
	m.SetCookies = resp.Header["Set-Cookie"]
	for _, sc := range m.SetCookies {
		cinfo := parseSetCookieHeader(sc)
		cinfo.Raw = sc
		m.Cookies = append(m.Cookies, cinfo)
	}

	// read limited body for parsing
	limit := int64(512 * 1024) // 512 KB
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
	if len(bodyBytes) > 0 {
		snippet := string(bodyBytes)
		if len(snippet) > 24*1024 {
			m.RawHTMLSnippet = snippet[:24*1024]
		} else {
			m.RawHTMLSnippet = snippet
		}
		// parse html
		parseHTMLSnippet(snippet, m, u)
	}

	// robots.txt
	if rtxt, sitemaps := fetchRobotsAndSitemaps(u); rtxt != "" || len(sitemaps) > 0 {
		m.RobotsTxt = rtxt
		if len(sitemaps) > 0 {
			m.Sitemaps = sitemaps
			urls := setFromSitemaps(u, sitemaps, 1000)
			if len(urls) > 0 {
				m.SitemapURLs = urls
			}
		}
	}

	// trackers heuristic from HTML snippet + script srcs
	trs := detectTrackers(m.RawHTMLSnippet, m.ScriptSrcs)
	if len(trs) > 0 {
		uniq := dedupeStrings(trs)
		sort.Strings(uniq)
		m.Trackers = uniq
	}

	// DNS: resolve host to IPs and other records
	host := u.Hostname()
	ips, derr := net.LookupIP(host)
	if derr == nil && len(ips) > 0 {
		for _, ip := range ips {
			m.ResolvedIPs = append(m.ResolvedIPs, ip.String())
		}
	} else if derr != nil {
		m.Notes = append(m.Notes, fmt.Sprintf("dns lookup failed: %v", derr))
	}
	m.ResolvedIPs = dedupeStrings(m.ResolvedIPs)

	// PTRs for IPs
	for _, ip := range m.ResolvedIPs {
		ptrs, err := net.LookupAddr(ip)
		if err == nil && len(ptrs) > 0 {
			clean := []string{}
			for _, p := range ptrs {
				clean = append(clean, strings.TrimSuffix(p, "."))
			}
			m.PTRs[ip] = dedupeStrings(clean)
		}
	}

	// TLS certs & handshake details — try multiple IPs and collect cert info
	firstTLSVersion := ""
	firstCipher := ""
	for _, ip := range m.ResolvedIPs {
		tlsv, cipher, certs, err := fetchTLSDetails(ip, host)
		if err != nil {
			m.Notes = append(m.Notes, fmt.Sprintf("tls(%s): %v", ip, err))
			continue
		}
		if firstTLSVersion == "" {
			firstTLSVersion = tlsv
		}
		if firstCipher == "" {
			firstCipher = cipher
		}
		if len(certs) > 0 {
			m.Certs = append(m.Certs, certs...)
		}
	}
	if firstTLSVersion != "" {
		m.TLSVersion = firstTLSVersion
	}
	if firstCipher != "" {
		m.CipherSuite = firstCipher
	}

	// RDAP / ASN
	if len(m.ResolvedIPs) > 0 {
		asn, raw, err := fetchRDAP(m.ResolvedIPs[0])
		if err == nil && asn != nil {
			m.ASN = asn
			m.RawRDAP = raw
		} else if err != nil {
			m.Notes = append(m.Notes, fmt.Sprintf("rdap error: %v", err))
		}
	}

	// DNS extra records
	m.MXRecords = getMXRecords(host)
	m.NSRecords = getNSRecords(host)
	m.TXTRecords = getTXTRecords(host)
	m.SPF = extractSPF(m.TXTRecords)
	m.DMARC = getDMARCRecord(host)

	// Favicon SHA1 (try discovered links first)
	if sha1hex, size, err := fetchFaviconSHA1(u, m.Links); err == nil {
		m.FaviconSHA1 = sha1hex
		m.FaviconSize = size
	} else {
		// not fatal
		if err != nil {
			m.Notes = append(m.Notes, "favicon: "+err.Error())
		}
	}

	// framework detection
	m.Frameworks = detectFrameworks(m.RawHTMLSnippet, m.ScriptSrcs)

	return m, nil
}

// ---------- helpers ----------

func normalizeURL(input string) (*url.URL, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, fmt.Errorf("empty target")
	}
	if !strings.HasPrefix(input, "http://") && !strings.HasPrefix(input, "https://") {
		input = "https://" + input
	}
	u, err := url.Parse(input)
	if err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid URL/host")
	}
	return u, nil
}

func parseSetCookieHeader(raw string) CookieInfo {
	parts := strings.Split(raw, ";")
	first := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
	c := CookieInfo{}
	if len(first) > 0 {
		c.Name = strings.TrimSpace(first[0])
	}
	if len(first) > 1 {
		c.Value = strings.TrimSpace(first[1])
	}
	for i := 1; i < len(parts); i++ {
		p := strings.TrimSpace(parts[i])
		l := strings.ToLower(p)
		if l == "httponly" {
			c.HttpOnly = true
		} else if l == "secure" {
			c.Secure = true
		} else if strings.HasPrefix(l, "samesite=") {
			c.SameSite = strings.TrimSpace(strings.SplitN(p, "=", 2)[1])
		}
	}
	return c
}

// parseHTMLSnippet extracts title, meta, og, twitter, links, script srcs, json-ld
func parseHTMLSnippet(snippet string, m *MetadataResult, base *url.URL) {
	r := strings.NewReader(snippet)
	z := htmlnode.NewTokenizer(r)

	for {
		tt := z.Next()
		switch tt {
		case htmlnode.ErrorToken:
			return
		case htmlnode.StartTagToken, htmlnode.SelfClosingTagToken:
			t := z.Token()
			tag := strings.ToLower(t.Data)
			switch tag {
			case "title":
				tt2 := z.Next()
				if tt2 == htmlnode.TextToken {
					title := strings.TrimSpace(string(z.Text()))
					if title != "" && m.Title == "" {
						m.Title = title
					}
				}
			case "meta":
				var name, prop, content, httpEquiv string
				for _, a := range t.Attr {
					k := strings.ToLower(strings.TrimSpace(a.Key))
					v := strings.TrimSpace(a.Val)
					switch k {
					case "name":
						name = strings.ToLower(v)
					case "property":
						prop = strings.ToLower(v)
					case "content":
						content = v
					case "http-equiv":
						httpEquiv = strings.ToLower(v)
					case "charset":
						if m.MetaTags["charset"] == "" {
							m.MetaTags["charset"] = v
						}
					}
				}
				if content != "" {
					if prop != "" {
						m.OGTags[prop] = content
					} else if name != "" {
						ln := strings.ToLower(name)
						m.MetaTags[ln] = content
						if strings.HasPrefix(ln, "twitter:") {
							m.TwitterTags[ln] = content
						}
						if ln == "generator" && m.Generator == "" {
							m.Generator = content
						}
						if ln == "theme-color" {
							m.ThemeColor = content
						}
						if ln == "refresh" {
							m.Refresh = content
						}
					} else if httpEquiv != "" {
						if httpEquiv == "content-security-policy" {
							m.CSPDirectives = parseCSP(content)
						}
					}
				}
				if strings.HasPrefix(strings.ToLower(prop), "og:") && content != "" {
					m.OGTags[strings.ToLower(prop)] = content
				}
			case "link":
				var rel, href, hreflang string
				for _, a := range t.Attr {
					k := strings.ToLower(strings.TrimSpace(a.Key))
					v := strings.TrimSpace(a.Val)
					switch k {
					case "rel":
						rel = strings.ToLower(v)
					case "href":
						href = resolveURL(base, v)
					case "hreflang":
						hreflang = v
					}
				}
				if href != "" {
					m.Links = append(m.Links, href)
					if rel == "canonical" && m.Canonical == "" {
						m.Canonical = href
					}
					if rel == "manifest" && m.Manifest == "" {
						m.Manifest = href
					}
					if rel == "alternate" && hreflang != "" {
						m.Alternates[hreflang] = href
					}
					if strings.Contains(rel, "icon") {
						m.Links = append(m.Links, href)
					}
				}
			case "script":
				var src, integrity string
				isJSONLD := false
				for _, a := range t.Attr {
					k := strings.ToLower(strings.TrimSpace(a.Key))
					v := strings.TrimSpace(a.Val)
					if k == "src" {
						src = resolveURL(base, v)
					}
					if k == "type" && strings.Contains(strings.ToLower(v), "ld+json") {
						isJSONLD = true
					}
					if k == "integrity" {
						integrity = v
					}
				}
				if src != "" {
					m.ScriptSrcs = append(m.ScriptSrcs, src)
					if integrity != "" {
						m.HasSRI = true
					}
				} else {
					// inline script — capture a small portion for trackers/JSON-LD
					tt2 := z.Next()
					if tt2 == htmlnode.TextToken {
						snip := strings.TrimSpace(string(z.Text()))
						if snip != "" {
							m.InlineScriptCnt++
							if isJSONLD && len(m.JSONLD) < 20 {
								if len(snip) > 8192 {
									m.JSONLD = append(m.JSONLD, snip[:8192])
								} else {
									m.JSONLD = append(m.JSONLD, snip)
								}
							}
							if detector := detectTrackersInScript(snip); len(detector) > 0 {
								m.Trackers = append(m.Trackers, detector...)
							}
						}
					}
				}
			case "a":
				var href string
				for _, a := range t.Attr {
					if strings.ToLower(a.Key) == "href" {
						href = a.Val
					}
				}
				if href != "" {
					u2 := resolveURL(base, href)
					m.Links = append(m.Links, u2)
					if isExternalLink(u2, base) {
						m.ExternalLinkCnt++
					} else {
						m.InternalLinkCnt++
					}
				}
			case "html":
				for _, a := range t.Attr {
					if strings.ToLower(a.Key) == "lang" && m.HTMLLang == "" {
						m.HTMLLang = a.Val
					}
				}
			}
		}
	}
}

func resolveURL(base *url.URL, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	if strings.HasPrefix(ref, "//") {
		return base.Scheme + ":" + ref
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	if u.IsAbs() {
		return u.String()
	}
	return base.ResolveReference(u).String()
}

func isExternalLink(href string, base *url.URL) bool {
	u, err := url.Parse(href)
	if err != nil || u.Host == "" {
		return false
	}
	return !strings.EqualFold(u.Hostname(), base.Hostname())
}

// fetchRobotsAndSitemaps fetches robots.txt and extracts Sitemap lines
func fetchRobotsAndSitemaps(u *url.URL) (robots string, sitemaps []string) {
	client := &http.Client{Timeout: 8 * time.Second}
	base := &url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/robots.txt"}
	resp, err := client.Get(base.String())
	if err != nil || resp == nil {
		return "", nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	txt := string(b)
	robots = txt
	for _, line := range strings.Split(txt, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "sitemap:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				loc := strings.TrimSpace(parts[1])
				if loc != "" {
					sitemaps = append(sitemaps, loc)
				}
			}
		}
	}
	return robots, dedupeStrings(sitemaps)
}

// parse sitemaps (XML) and gather up to `limit` URLs
func setFromSitemaps(base *url.URL, sitemaps []string, limit int) []string {
	out := []string{}
	client := &http.Client{Timeout: 10 * time.Second}
	seen := map[string]struct{}{}
	type urlEntry struct {
		Loc string `xml:"loc"`
	}
	type urlset struct {
		Urls []urlEntry `xml:"url"`
	}
	type sitemapEntry struct {
		Loc string `xml:"loc"`
	}
	type sitemapindex struct {
		Sites []sitemapEntry `xml:"sitemap"`
	}
	for _, s := range sitemaps {
		if len(out) >= limit {
			break
		}
		resp, err := client.Get(s)
		if err != nil || resp == nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()
		var us urlset
		if err := xml.Unmarshal(b, &us); err == nil && len(us.Urls) > 0 {
			for _, e := range us.Urls {
				if e.Loc != "" {
					if _, ok := seen[e.Loc]; !ok {
						out = append(out, e.Loc)
						seen[e.Loc] = struct{}{}
						if len(out) >= limit {
							break
						}
					}
				}
			}
			continue
		}
		var si sitemapindex
		if err := xml.Unmarshal(b, &si); err == nil && len(si.Sites) > 0 {
			for _, se := range si.Sites {
				if len(out) >= limit {
					break
				}
				if se.Loc != "" {
					resp2, err2 := client.Get(se.Loc)
					if err2 != nil || resp2 == nil {
						continue
					}
					b2, _ := io.ReadAll(io.LimitReader(resp2.Body, 512*1024))
					resp2.Body.Close()
					var us2 urlset
					if err := xml.Unmarshal(b2, &us2); err == nil && len(us2.Urls) > 0 {
						for _, e := range us2.Urls {
							if _, ok := seen[e.Loc]; !ok {
								out = append(out, e.Loc)
								seen[e.Loc] = struct{}{}
								if len(out) >= limit {
									break
								}
							}
						}
					}
				}
			}
		}
	}
	return dedupeStrings(out)
}

var trackerPatterns = []struct {
	Name string
	Re   *regexp.Regexp
}{
	{"Google Analytics (gtag)", regexp.MustCompile(`(?i)gtag\(|analytics\.js|UA-\d{4,}|G-[A-Z0-9\-]{4,}`)},
	{"Google Tag Manager", regexp.MustCompile(`(?i)googletagmanager|gtm\.js`)},
	{"Facebook Pixel", regexp.MustCompile(`(?i)fbq\(|facebook\.net|facebook\.com/tr`)},
	{"Hotjar", regexp.MustCompile(`(?i)hotjar\.`)},
	{"Microsoft Clarity", regexp.MustCompile(`(?i)clarity\.ms|clarity\.io`)},
	{"Mixpanel", regexp.MustCompile(`(?i)mixpanel\.`)},
	{"TikTok Pixel", regexp.MustCompile(`(?i)tiktok\.com|ttq\.`)},
	{"Optimizely", regexp.MustCompile(`(?i)optimizely|snapshots`)},
}

func detectTrackers(htmlSnippet string, scriptSrcs []string) []string {
	out := []string{}
	text := htmlSnippet + "\n" + strings.Join(scriptSrcs, "\n")
	for _, p := range trackerPatterns {
		if p.Re.MatchString(text) {
			out = append(out, p.Name)
		}
	}
	return dedupeStrings(out)
}

func detectTrackersInScript(s string) []string {
	out := []string{}
	for _, p := range trackerPatterns {
		if p.Re.MatchString(s) {
			out = append(out, p.Name)
		}
	}
	return dedupeStrings(out)
}

func dedupeStrings(in []string) []string {
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
	return out
}

// fetchTLSDetails returns human-friendly TLS version and cipher, and cert chain
func fetchTLSDetails(ip, sni string) (string, string, []CertInfo, error) {
	addr := net.JoinHostPort(ip, "443")
	dialer := &net.Dialer{Timeout: 6 * time.Second}
	cfg := &tls.Config{InsecureSkipVerify: true}
	// set SNI when possible
	if net.ParseIP(sni) == nil && sni != "" {
		cfg.ServerName = sni
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		return "", "", nil, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	ver := tlsVersionString(state.Version)
	cipher := fmt.Sprintf("0x%x", state.CipherSuite)

	certs := []CertInfo{}
	now := time.Now().UTC()
	for _, c := range state.PeerCertificates {
		ci := CertInfo{IP: ip}
		if c.Subject.CommonName != "" {
			ci.SubjectCN = c.Subject.CommonName
		}
		for _, n := range c.DNSNames {
			ci.SANs = append(ci.SANs, n)
		}
		for _, a := range c.IPAddresses {
			ci.SANs = append(ci.SANs, a.String())
		}
		if c.Issuer.CommonName != "" {
			ci.Issuer = c.Issuer.CommonName
		}
		if len(c.Issuer.Organization) > 0 {
			ci.IssuerOrg = c.Issuer.Organization[0]
		}
		ci.NotBefore = c.NotBefore.UTC().Format(time.RFC3339)
		ci.NotAfter = c.NotAfter.UTC().Format(time.RFC3339)
		ci.IsExpired = now.After(c.NotAfter.UTC())
		// self-signed heuristic: signature validates from itself OR subject==issuer
		isSelf := false
		if c.CheckSignatureFrom(c) == nil {
			isSelf = true
		}
		if c.Issuer.CommonName == c.Subject.CommonName {
			isSelf = true
		}
		ci.IsSelfSigned = isSelf
		ci.SANs = dedupeStrings(ci.SANs)
		certs = append(certs, ci)
	}
	return ver, cipher, certs, nil
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionSSL30:
		return "SSL3.0"
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

// fetchRDAP tries multiple RDAP endpoints and parses a few fields (best-effort)
func fetchRDAP(ip string) (*ASNInfo, string, error) {
	endpoints := []string{
		"https://rdap.arin.net/registry/ip/%s",
		"https://rdap.db.ripe.net/ip/%s",
		"https://rdap.apnic.net/ip/%s",
		"https://rdap.lacnic.net/rdap/ip/%s",
		"https://rdap.afrinic.net/rdap/ip/%s",
	}
	client := &http.Client{Timeout: 8 * time.Second}
	var lastErr error
	for _, tmpl := range endpoints {
		u := fmt.Sprintf(tmpl, url.QueryEscape(ip))
		resp, err := client.Get(u)
		if err != nil {
			lastErr = err
			continue
		}
		rawb, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("rdap %s -> %s", u, resp.Status)
			continue
		}
		var parsed map[string]interface{}
		if err := json.Unmarshal(rawb, &parsed); err != nil {
			// return raw content if JSON parse fails
			return nil, string(rawb), nil
		}
		asn := &ASNInfo{Raw: string(rawb)}
		if v, ok := parsed["name"].(string); ok {
			asn.ASName = v
		}
		if v, ok := parsed["handle"].(string); ok {
			asn.Handle = v
		}
		if v, ok := parsed["country"].(string); ok {
			asn.Country = v
		}
		if v, ok := parsed["startAddress"].(string); ok {
			asn.CIDR = v
		}
		if entities, ok := parsed["entities"].([]interface{}); ok {
			for _, e := range entities {
				if em, ok := e.(map[string]interface{}); ok {
					if roles, ok := em["roles"].([]interface{}); ok {
						for _, r := range roles {
							if rs, ok := r.(string); ok && strings.Contains(strings.ToLower(rs), "abuse") {
								if vcard, ok := em["vcardArray"].([]interface{}); ok && len(vcard) > 1 {
									if items, ok := vcard[1].([]interface{}); ok {
										for _, item := range items {
											if it, ok := item.([]interface{}); ok && len(it) >= 4 {
												if key, ok := it[0].(string); ok && strings.ToLower(key) == "email" {
													if val, ok := it[3].(string); ok {
														asn.AbuseEmail = val
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
		return asn, string(rawb), nil
	}
	return nil, "", lastErr
}

// DNS helpers
func getMXRecords(host string) []string {
	mxs, err := net.LookupMX(host)
	out := []string{}
	if err != nil {
		return out
	}
	for _, m := range mxs {
		out = append(out, fmt.Sprintf("%s %d", strings.TrimSuffix(m.Host, "."), m.Pref))
	}
	return dedupeStrings(out)
}

func getNSRecords(host string) []string {
	ns, err := net.LookupNS(host)
	out := []string{}
	if err != nil {
		return out
	}
	for _, n := range ns {
		out = append(out, strings.TrimSuffix(n.Host, "."))
	}
	return dedupeStrings(out)
}

func getTXTRecords(host string) []string {
	txts, err := net.LookupTXT(host)
	if err != nil {
		return []string{}
	}
	return dedupeStrings(txts)
}

func extractSPF(txts []string) string {
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
			return t
		}
	}
	return ""
}

func getDMARCRecord(host string) string {
	d := "_dmarc." + host
	t, err := net.LookupTXT(d)
	if err != nil {
		return ""
	}
	for _, v := range t {
		if strings.HasPrefix(strings.ToLower(v), "v=dmarc1") {
			return v
		}
	}
	return ""
}

// parseCSP returns a simple map of directive -> value (first tokenized)
func parseCSP(csp string) map[string]string {
	out := map[string]string{}
	parts := strings.Split(csp, ";")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, " ", 2)
		if len(kv) == 1 {
			out[kv[0]] = ""
		} else {
			out[kv[0]] = kv[1]
		}
	}
	return out
}

// Framework detection (simple heuristics)
var frameworkPatterns = []struct {
	Name string
	Re   *regexp.Regexp
}{
	{"Next.js", regexp.MustCompile(`(?i)next\.js|__next`)},
	{"React", regexp.MustCompile(`(?i)react-dom|react/jsx-runtime|data-reactroot`)},
	{"Angular", regexp.MustCompile(`(?i)angular\.js|ng-app`)},
	{"Vue.js", regexp.MustCompile(`(?i)vue(?:\.runtime)?|__vue`)},
	{"jQuery", regexp.MustCompile(`(?i)jquery(\.min)?\.js|\$\('`)},
	{"Nuxt.js", regexp.MustCompile(`(?i)__nuxt|nuxt`)},
}

func detectFrameworks(htmlSnippet string, scriptSrcs []string) []string {
	text := htmlSnippet + "\n" + strings.Join(scriptSrcs, "\n")
	out := []string{}
	for _, p := range frameworkPatterns {
		if p.Re.MatchString(text) {
			out = append(out, p.Name)
		}
	}
	return dedupeStrings(out)
}

// fetchFaviconSHA1 tries to find a favicon URL from links; else fetch /favicon.ico
// returns hex sha1, size, error
func fetchFaviconSHA1(u *url.URL, links []string) (string, int64, error) {
	candidates := []string{}
	for _, l := range links {
		ll := strings.ToLower(l)
		if strings.Contains(ll, "favicon") || strings.Contains(ll, "icon") {
			candidates = append(candidates, l)
		}
	}
	// ensure unique
	candidates = dedupeStrings(candidates)
	if len(candidates) == 0 {
		// fallback
		fb := &url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/favicon.ico"}
		candidates = append(candidates, fb.String())
	}
	client := &http.Client{Timeout: 8 * time.Second}
	for _, c := range candidates {
		resp, err := client.Get(c)
		if err != nil || resp == nil {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()
		if err != nil || len(b) == 0 {
			continue
		}
		sum := sha1.Sum(b)
		return hex.EncodeToString(sum[:]), int64(len(b)), nil
	}
	return "", 0, fmt.Errorf("no favicon retrieved")
}
