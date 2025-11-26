package endpoint

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// EndpointOptions controls behavior of discovery/probing.
type EndpointOptions struct {
	// If true, do not perform active GET/OPTIONS probing (only passive extraction).
	DisableActive bool

	// Max concurrent probes
	Concurrency int

	// HTTP client used for network requests (should set Timeout and Transport as needed).
	Client *http.Client

	// UA list (rotation)
	UAList []string

	// Retries for transient HTTP errors
	Retries int

	// Max body bytes to read when probing GET
	MaxBody int64

	// EnableLightGraphQLProbe will attempt a tiny introspection query when a GraphQL endpoint is found.
	EnableLightGraphQLProbe bool

	// If >0, jitter (seconds) between requests (randomized)
	Jitter float64

	// Optional SNI hostname for TLS probes
	SNI string
}

// Endpoint is the structured result for a discovered endpoint.
type Endpoint struct {
	URL             string            `json:"url"`
	Normalized      string            `json:"normalized,omitempty"`
	MethodHints     []string          `json:"method_hints,omitempty"`
	AllowedMethods  []string          `json:"allowed_methods,omitempty"`
	StatusCodes     []int             `json:"status_codes,omitempty"`
	ContentType     string            `json:"content_type,omitempty"`
	ResponseSnippet string            `json:"response_snippet,omitempty"`
	ResponseSize    int64             `json:"response_size,omitempty"`
	ResponseTimeMs  int64             `json:"response_time_ms,omitempty"`
	Redirects       []string          `json:"redirects,omitempty"`
	TLS             *TLSInfo          `json:"tls,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	Cookies         []string          `json:"cookies,omitempty"`
	CORS            map[string]string `json:"cors,omitempty"`
	DiscoverySource string            `json:"discovered_in,omitempty"` // "html", "js", "sitemap", "robots", "dir", "source_map"
	Tags            []string          `json:"tags,omitempty"`
	Confidence      string            `json:"confidence,omitempty"` // low / medium / high
	Evidence        []string          `json:"evidence,omitempty"`   // snippets / file:line
	Notes           []string          `json:"notes,omitempty"`
}

// TLSInfo stores TLS certificate metadata (minimal)
type TLSInfo struct {
	Protocol     string    `json:"protocol,omitempty"`
	Cipher       string    `json:"cipher,omitempty"`
	Issuer       string    `json:"issuer,omitempty"`
	Subject      string    `json:"subject,omitempty"`
	ValidFrom    time.Time `json:"valid_from,omitempty"`
	ValidTo      time.Time `json:"valid_to,omitempty"`
	IsExpired    bool      `json:"is_expired,omitempty"`
	IsSelfSigned bool      `json:"is_self_signed,omitempty"`
}

var (
	hrefRe                 = regexp.MustCompile(`(?i)<a[^>]+href=['"]([^'"]+)['"]`)
	formActionRe           = regexp.MustCompile(`(?i)<form[^>]+action=['"]([^'"]+)['"]`)
	scriptSrcRe            = regexp.MustCompile(`(?i)<script[^>]+src=['"]([^'"]+)['"]`)
	metaRe                 = regexp.MustCompile(`(?i)<meta[^>]+content=['"]([^'"]+)['"][^>]*name=['"]([^'"]+)['"]`)
	fetchRe                = regexp.MustCompile(`(?i)fetch\s*\(\s*['"]([^'"]+)['"]`)
	xhrOpenRe              = regexp.MustCompile(`(?i)\.open\s*\(\s*['"]?(GET|POST|PUT|DELETE|PATCH|OPTIONS)['"]?\s*,\s*['"]([^'"]+)['"]`)
	axiosRe                = regexp.MustCompile(`(?i)axios\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]`)
	wsRe                   = regexp.MustCompile(`(?i)new\s+WebSocket\s*\(\s*['"]([^'"]+)['"]`)
	sourceMapRe            = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL\s*=\s*(.+)$`)
	graphqlRe              = regexp.MustCompile(`(?i)graphql`)
	jwtRe                  = regexp.MustCompile(`[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+`)
	apiKeyHeuristic        = regexp.MustCompile(`(?i)(?:api_key|apiKey|apikey|access_token|token|secret|client_secret|aws_access_key_id|AKIA[0-9A-Z]{16})['"]?\s*[:=]\s*['"]?([A-Za-z0-9\-_.=+/]{8,128})['"]?`)
	urlLikeRe              = regexp.MustCompile(`(?i)(https?:\/\/[^\s'"]+|wss?:\/\/[^\s'"]+|\/[a-z0-9_\-\/\.\?\=&%]+)`)
	openRedirectParamNames = []string{"redirect", "next", "url", "return", "rurl", "dest", "destination", "continue", "redir"}
)

// safeReadAll reads up to limit bytes
func safeReadAll(r io.Reader, limit int64) ([]byte, error) {
	lr := io.LimitReader(r, limit+1)
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return b[:limit], nil
	}
	return b, nil
}

// randSleep jitter
func randSleep(max float64) {
	if max <= 0 {
		return
	}
	d := time.Duration((max * float64(time.Second)) * (0.5 + (0.5 * randFloat())))
	time.Sleep(d)
}

func randFloat() float64 {
	return float64(time.Now().UnixNano()%1000) / 1000.0
}

func normalizeCandidate(raw string, base *url.URL) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(raw), "javascript:") ||
		strings.HasPrefix(strings.ToLower(raw), "mailto:") ||
		strings.HasPrefix(strings.ToLower(raw), "tel:") {
		return ""
	}
	if strings.HasPrefix(raw, "//") && base != nil {
		return base.Scheme + ":" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if base != nil {
		u = base.ResolveReference(u)
	}
	u.Fragment = ""
	if u.Port() != "" {
		if (u.Scheme == "http" && u.Port() == "80") || (u.Scheme == "https" && u.Port() == "443") {
			u.Host = u.Hostname()
		}
	}
	return u.String()
}

func extractCandidatesFromHTML(body []byte, base *url.URL) []string {
	out := []string{}
	seen := map[string]struct{}{}

	tryAdd := func(s string) {
		n := normalizeCandidate(s, base)
		if n == "" {
			return
		}
		if _, ok := seen[n]; ok {
			return
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}

	for _, m := range hrefRe.FindAllSubmatch(body, -1) {
		if len(m) >= 2 {
			tryAdd(string(m[1]))
		}
	}
	for _, m := range formActionRe.FindAllSubmatch(body, -1) {
		if len(m) >= 2 {
			tryAdd(string(m[1]))
		}
	}
	for _, m := range scriptSrcRe.FindAllSubmatch(body, -1) {
		if len(m) >= 2 {
			tryAdd(string(m[1]))
		}
	}
	for _, m := range metaRe.FindAllSubmatch(body, -1) {
		if len(m) >= 3 {
			tryAdd(string(m[1]))
		}
	}
	for _, m := range fetchRe.FindAllSubmatch(body, -1) {
		if len(m) >= 2 {
			tryAdd(string(m[1]))
		}
	}
	for _, m := range xhrOpenRe.FindAllSubmatch(body, -1) {
		if len(m) >= 3 {
			tryAdd(string(m[2]))
		}
	}
	for _, m := range axiosRe.FindAllSubmatch(body, -1) {
		if len(m) >= 3 {
			tryAdd(string(m[2]))
		}
	}
	for _, m := range wsRe.FindAllSubmatch(body, -1) {
		if len(m) >= 2 {
			tryAdd(string(m[1]))
		}
	}
	for _, m := range urlLikeRe.FindAllSubmatch(body, -1) {
		if len(m) >= 2 {
			tryAdd(string(m[1]))
		}
	}
	return out
}

func extractSourceMapURLs(js []byte, base *url.URL) []string {
	out := []string{}
	for _, m := range sourceMapRe.FindAllSubmatch(js, -1) {
		if len(m) >= 2 {
			raw := strings.TrimSpace(string(m[1]))
			if raw != "" {
				n := normalizeCandidate(raw, base)
				if n != "" {
					out = append(out, n)
				}
			}
		}
	}
	return out
}

// doHead performs HEAD or GET (if HEAD not allowed) to collect headers quickly.
func doHead(client *http.Client, rawurl string, ua string, maxBody int64) (body []byte, status int, headers map[string][]string, redirects []string, tlsInfo *tls.ConnectionState, duration time.Duration, err error) {
	start := time.Now()
	req, err := http.NewRequest("HEAD", rawurl, nil)
	if err != nil {
		return nil, 0, nil, nil, nil, 0, err
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	visited := map[string]struct{}{}
	redirects = []string{}
	cl := *client
	cl.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		u := req.URL.String()
		if _, ok := visited[u]; ok {
			return http.ErrUseLastResponse
		}
		visited[u] = struct{}{}
		redirects = append(redirects, u)
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	}
	resp, err := cl.Do(req)
	if err != nil {
		req2, err2 := http.NewRequest("GET", rawurl, nil)
		if err2 != nil {
			return nil, 0, nil, nil, nil, 0, err
		}
		if ua != "" {
			req2.Header.Set("User-Agent", ua)
		}
		start = time.Now()
		resp, err = client.Do(req2)
		if err != nil {
			return nil, 0, nil, nil, nil, 0, err
		}
	}
	defer resp.Body.Close()
	headers = map[string][]string{}
	for k, v := range resp.Header {
		headers[k] = v
	}
	var tlsInfoState *tls.ConnectionState
	if resp.TLS != nil {
		tlsInfoState = resp.TLS
	}
	var b []byte
	if resp.Request != nil && resp.Request.Method != "HEAD" {
		lr := io.LimitReader(resp.Body, maxBody)
		b, _ = io.ReadAll(lr)
	}
	duration = time.Since(start)
	return b, resp.StatusCode, headers, redirects, tlsInfoState, duration, nil
}

// doOptions collects allowed methods cheaply.
func doOptions(client *http.Client, rawurl string, ua string) (allowed []string, headers map[string][]string, status int, err error) {
	req, err := http.NewRequest("OPTIONS", rawurl, nil)
	if err != nil {
		return nil, nil, 0, err
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, 0, err
	}
	defer resp.Body.Close()
	headers = map[string][]string{}
	for k, v := range resp.Header {
		headers[k] = v
	}
	status = resp.StatusCode
	if vals, ok := headers["Allow"]; ok && len(vals) > 0 {
		parts := strings.Split(vals[0], ",")
		for _, p := range parts {
			allowed = append(allowed, strings.TrimSpace(p))
		}
	}
	if len(allowed) == 0 {
		if vals, ok := headers["Access-Control-Allow-Methods"]; ok && len(vals) > 0 {
			parts := strings.Split(vals[0], ",")
			for _, p := range parts {
				allowed = append(allowed, strings.TrimSpace(p))
			}
		}
	}
	return allowed, headers, status, nil
}

// doGet performs a GET capturing snippet and size (non-streaming)
func doGet(client *http.Client, rawurl string, ua string, maxBody int64) (body []byte, status int, headers map[string][]string, redirects []string, tlsInfo *tls.ConnectionState, duration time.Duration, err error) {
	start := time.Now()
	req, err := http.NewRequest("GET", rawurl, nil)
	if err != nil {
		return nil, 0, nil, nil, nil, 0, err
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	visited := map[string]struct{}{}
	redirects = []string{}
	cl := *client
	cl.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		u := req.URL.String()
		if _, ok := visited[u]; ok {
			return http.ErrUseLastResponse
		}
		visited[u] = struct{}{}
		redirects = append(redirects, u)
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, 0, nil, nil, nil, 0, err
	}
	defer resp.Body.Close()
	headers = map[string][]string{}
	for k, v := range resp.Header {
		headers[k] = v
	}
	if resp.TLS != nil {
		tlsInfo = resp.TLS
	}
	lr := io.LimitReader(resp.Body, maxBody+1)
	b, _ := io.ReadAll(lr)
	if int64(len(b)) > maxBody {
		body = b[:maxBody]
	} else {
		body = b
	}
	duration = time.Since(start)
	return body, resp.StatusCode, headers, redirects, tlsInfo, duration, nil
}

func headerMapToSimple(in map[string][]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = strings.Join(v, "; ")
	}
	return out
}

func tlsStateToInfo(s *tls.ConnectionState) *TLSInfo {
	if s == nil {
		return nil
	}
	info := TLSInfo{}
	info.Protocol = tlsVersionName(s.Version)
	info.Cipher = tls.CipherSuiteName(s.CipherSuite)
	if len(s.PeerCertificates) > 0 {
		c := s.PeerCertificates[0]
		info.Issuer = c.Issuer.CommonName
		info.Subject = c.Subject.CommonName
		info.ValidFrom = c.NotBefore
		info.ValidTo = c.NotAfter
		info.IsExpired = time.Now().After(c.NotAfter)
		info.IsSelfSigned = c.Issuer.CommonName == c.Subject.CommonName
	}
	return &info
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

func detectCORS(headers map[string][]string) map[string]string {
	out := map[string]string{}
	if v, ok := headers["Access-Control-Allow-Origin"]; ok && len(v) > 0 {
		out["allow_origin"] = v[0]
	}
	if v, ok := headers["Access-Control-Allow-Credentials"]; ok && len(v) > 0 {
		out["allow_credentials"] = v[0]
	}
	if v, ok := headers["Access-Control-Allow-Methods"]; ok && len(v) > 0 {
		out["allow_methods"] = v[0]
	}
	if v, ok := headers["Access-Control-Allow-Headers"]; ok && len(v) > 0 {
		out["allow_headers"] = v[0]
	}
	return out
}

func sniffTokensAndSecrets(body []byte) (tokens []string, keys []string) {
	if body == nil {
		return nil, nil
	}
	s := string(body)
	for _, m := range jwtRe.FindAllString(s, -1) {
		tokens = append(tokens, m)
	}
	for _, gr := range apiKeyHeuristic.FindAllStringSubmatch(s, -1) {
		if len(gr) >= 2 && gr[1] != "" {
			keys = append(keys, gr[1])
		}
	}
	tokens = dedupeStrings(tokens)
	keys = dedupeStrings(keys)
	return tokens, keys
}

func dedupeStrings(in []string) []string {
	out := []string{}
	seen := map[string]struct{}{}
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

func isLikelyEndpoint(u string) bool {
	u = strings.ToLower(u)
	if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "ws://") || strings.HasPrefix(u, "wss://") {
		if strings.HasSuffix(u, ".png") || strings.HasSuffix(u, ".jpg") || strings.HasSuffix(u, ".jpeg") || strings.HasSuffix(u, ".css") || strings.HasSuffix(u, ".svg") {
			return false
		}
		return true
	}
	if strings.HasPrefix(u, "/") {
		if strings.Contains(u, "/api/") || strings.Contains(u, "/v1/") || strings.Contains(u, "/v2/") || strings.Contains(u, "graphql") || strings.Contains(u, "login") || strings.Contains(u, "token") || strings.Contains(u, "auth") {
			return true
		}
	}
	return false
}

func containsOpenRedirectParam(rawurl string) bool {
	u, err := url.Parse(rawurl)
	if err != nil {
		return false
	}
	q := u.Query()
	for _, n := range openRedirectParamNames {
		if _, ok := q[n]; ok {
			return true
		}
	}
	return false
}

// DiscoverEndpoints extracts and probes endpoints for a target. Parameters:
// - client: HTTP client (with timeouts)
// - base: base URL (e.g. "https://example.com") used to resolve relative paths
// - rootHTML: root page HTML bytes (can be nil)
// - jsFiles: list of JS file URLs to fetch+scan (can be nil)
// - opts: discovery options
//
// Returns a deduped slice of Endpoint objects.
func DiscoverEndpoints(client *http.Client, base string, rootHTML []byte, jsFiles []string, opts EndpointOptions) ([]Endpoint, error) {
	if client == nil {
		return nil, errors.New("http client required")
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 8
	}
	if opts.MaxBody <= 0 {
		opts.MaxBody = 128 * 1024
	}
	var baseURL *url.URL
	if base != "" {
		if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
			base = "https://" + strings.TrimSuffix(base, "/")
		}
		u, err := url.Parse(base)
		if err == nil {
			baseURL = u
		}
	}

	candidates := []string{}
	if rootHTML != nil {
		fromHTML := extractCandidatesFromHTML(rootHTML, baseURL)
		for _, c := range fromHTML {
			if isLikelyEndpoint(c) {
				candidates = append(candidates, c)
			}
		}
	}

	for _, j := range jsFiles {
		n := normalizeCandidate(j, baseURL)
		if n != "" {
			candidates = append(candidates, n)
		}
	}

	jsContentCandidates := dedupeStrings(candidates)
	jsToFetch := []string{}
	for _, s := range jsContentCandidates {
		lower := strings.ToLower(s)
		if strings.Contains(lower, ".js") || strings.Contains(lower, "static") || strings.Contains(lower, "bundle") || strings.Contains(lower, "app.") {
			jsToFetch = append(jsToFetch, s)
		}
	}
	for _, j := range jsFiles {
		if j != "" {
			jsToFetch = append(jsToFetch, j)
		}
	}
	jsToFetch = dedupeStrings(jsToFetch)

	var mu sync.Mutex
	allCandidates := map[string]string{} // url -> discovery source
	for _, c := range candidates {
		allCandidates[c] = "html"
	}

	sem := make(chan struct{}, opts.Concurrency)
	wg := sync.WaitGroup{}
	for _, jsURL := range jsToFetch {
		jsURL := jsURL
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			ua := ""
			if len(opts.UAList) > 0 {
				ua = opts.UAList[0]
			}
			if opts.DisableActive {
				return
			}
			randSleep(opts.Jitter)
			body, status, _, _, _, _, err := doGet(client, jsURL, ua, opts.MaxBody)
			if err != nil || status >= 400 {
			} else {
				found := extractCandidatesFromHTML(body, baseURL)
				smaps := extractSourceMapURLs(body, baseURL)
				found = append(found, smaps...)
				mu.Lock()
				for _, f := range found {
					if isLikelyEndpoint(f) {
						allCandidates[f] = "js"
					}
				}
				mu.Unlock()
				for _, sm := range smaps {
					randSleep(opts.Jitter)
					smBody, smStatus, _, _, _, _, err := doGet(client, sm, ua, opts.MaxBody)
					if err == nil && smStatus >= 200 && smStatus < 400 {
						var smObj map[string]interface{}
						_ = json.Unmarshal(smBody, &smObj)
						if srcs, ok := smObj["sources"]; ok {
							if arr, ok := srcs.([]interface{}); ok {
								mu.Lock()
								for _, ai := range arr {
									if sstr, ok := ai.(string); ok {
										nn := normalizeCandidate(sstr, baseURL)
										if nn != "" && isLikelyEndpoint(nn) {
											allCandidates[nn] = "source_map"
										}
									}
								}
								mu.Unlock()
							}
						}
						for _, m := range urlLikeRe.FindAllSubmatch(smBody, -1) {
							if len(m) >= 2 {
								nn := normalizeCandidate(string(m[1]), baseURL)
								if nn != "" && isLikelyEndpoint(nn) {
									mu.Lock()
									allCandidates[nn] = "source_map"
									mu.Unlock()
								}
							}
						}
					}
				}
			}
		}()
	}
	wg.Wait()

	candList := make([]string, 0, len(allCandidates))
	for u := range allCandidates {
		candList = append(candList, u)
	}
	sort.Strings(candList)

	type probeJob struct {
		URL    string
		Source string
	}
	jobs := make(chan probeJob, len(candList))
	results := make(chan Endpoint, len(candList))
	workerWg := sync.WaitGroup{}
	for i := 0; i < opts.Concurrency; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for job := range jobs {
				ep := Endpoint{
					URL:             job.URL,
					Normalized:      job.URL,
					DiscoverySource: job.Source,
					Headers:         map[string]string{},
				}
				ua := ""
				if len(opts.UAList) > 0 {
					ua = opts.UAList[0]
				}
				if opts.DisableActive {
					lower := strings.ToLower(job.URL)
					if strings.Contains(lower, "graphql") {
						ep.Tags = append(ep.Tags, "graphql")
					}
					if strings.HasPrefix(lower, "ws://") || strings.HasPrefix(lower, "wss://") {
						ep.Tags = append(ep.Tags, "websocket")
					}
					if strings.Contains(lower, "/admin") || strings.Contains(lower, "wp-admin") || strings.Contains(lower, "dashboard") {
						ep.Tags = append(ep.Tags, "admin")
					}
					results <- ep
					continue
				}

				randSleep(opts.Jitter)
				body, status, headers, redirects, tlsState, dur, err := doHead(client, job.URL, ua, opts.MaxBody)
				if err != nil {
					randSleep(opts.Jitter)
					body, status, headers, redirects, tlsState, dur, err = doGet(client, job.URL, ua, opts.MaxBody)
					if err != nil {
						ep.Notes = append(ep.Notes, fmt.Sprintf("probe error: %v", err))
						results <- ep
						continue
					}
				}
				ep.ResponseTimeMs = dur.Milliseconds()
				if status != 0 {
					ep.StatusCodes = append(ep.StatusCodes, status)
				}
				ep.Headers = headerMapToSimple(headers)
				if ct := headers["Content-Type"]; len(ct) > 0 {
					ep.ContentType = ct[0]
				}
				if len(redirects) > 0 {
					ep.Redirects = redirects
				}
				if tlsState != nil {
					ep.TLS = tlsStateToInfo(tlsState)
				}

				randSleep(opts.Jitter)
				allowed, _, _, _ := doOptions(client, job.URL, ua)
				if len(allowed) > 0 {
					ep.AllowedMethods = allowed
				}

				if len(body) > 0 {
					ep.ResponseSize = int64(len(body))
					ep.ResponseSnippet = string(body)
					if len(ep.ResponseSnippet) > 1024 {
						ep.ResponseSnippet = ep.ResponseSnippet[:1024] + "..."
					}
					toks, keys := sniffTokensAndSecrets(body)
					for _, t := range toks {
						ep.Evidence = append(ep.Evidence, fmt.Sprintf("token:%s", t))
					}
					for _, k := range keys {
						ep.Evidence = append(ep.Evidence, fmt.Sprintf("key:%s", k))
						ep.Tags = append(ep.Tags, "exposed_api_key")
					}
					if containsOpenRedirectParam(job.URL) {
						ep.Tags = append(ep.Tags, "open_redirect_param")
					}
				}

				ep.CORS = detectCORS(headers)

				if sc, ok := headers["Set-Cookie"]; ok && len(sc) > 0 {
					ep.Cookies = append(ep.Cookies, sc...)
				}

				lower := strings.ToLower(job.URL)
				if strings.Contains(lower, "/graphql") || graphqlRe.MatchString(lower) {
					ep.Tags = append(ep.Tags, "graphql")
				}
				if strings.HasPrefix(lower, "ws://") || strings.HasPrefix(lower, "wss://") {
					ep.Tags = append(ep.Tags, "websocket")
				}
				if strings.Contains(lower, "/admin") || strings.Contains(lower, "wp-admin") || strings.Contains(lower, "dashboard") {
					ep.Tags = append(ep.Tags, "admin")
				}
				if strings.Contains(lower, "/login") || strings.Contains(lower, "/token") || strings.Contains(lower, "/oauth") || strings.Contains(lower, "/authorize") {
					ep.Tags = append(ep.Tags, "auth")
				}
				if strings.Contains(lower, "/health") || strings.Contains(lower, "/status") || strings.Contains(lower, "/version") {
					ep.Tags = append(ep.Tags, "health")
				}
				if strings.Contains(lower, ".sql") || strings.Contains(lower, ".zip") || strings.Contains(lower, ".env") {
					ep.Tags = append(ep.Tags, "backup")
				}

				conf := "low"
				score := 0
				if contains(ep.Tags, "exposed_api_key") {
					score += 50
				}
				if contains(ep.Tags, "auth") {
					score += 20
				}
				if contains(ep.Tags, "admin") {
					score += 30
				}
				if len(ep.Evidence) > 0 {
					score += 20
				}
				if len(ep.CORS) > 0 {
					if v, ok := ep.CORS["allow_origin"]; ok && (v == "*" || strings.HasPrefix(v, "http")) {
						score += 15
						ep.Notes = append(ep.Notes, fmt.Sprintf("CORS: %s", v))
					}
				}
				if score >= 70 {
					conf = "high"
				} else if score >= 30 {
					conf = "medium"
				}
				ep.Confidence = conf

				if opts.EnableLightGraphQLProbe && contains(ep.Tags, "graphql") && !opts.DisableActive {
					q := `{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name } } }"}`
					req, _ := http.NewRequest("POST", job.URL, strings.NewReader(q))
					req.Header.Set("User-Agent", ua)
					req.Header.Set("Content-Type", "application/json")
					resp, err := client.Do(req)
					if err == nil {
						sl, _ := safeReadAll(resp.Body, 64*1024)
						resp.Body.Close()
						if bytes.Contains(sl, []byte("__schema")) {
							ep.Tags = append(ep.Tags, "graphql_introspection")
							ep.Evidence = append(ep.Evidence, string(sl))
							ep.Notes = append(ep.Notes, fmt.Sprintf("GraphQL introspection appears enabled (HTTP %d)", resp.StatusCode))
						}
					}
				}

				if vals, ok := headers["Allow"]; ok && len(vals) > 0 {
					for _, p := range strings.Split(vals[0], ",") {
						ep.MethodHints = append(ep.MethodHints, strings.TrimSpace(p))
					}
				}
				if strings.Contains(strings.ToLower(ep.ContentType), "application/graphql") || contains(ep.Tags, "graphql") {
					ep.MethodHints = appendIfMissing(ep.MethodHints, "POST")
				}

				ep.Headers = headerMapToSimple(headers)
				results <- ep
			}
		}()
	}

	for _, c := range candList {
		src := allCandidates[c]
		if src == "" {
			src = "unknown"
		}
		jobs <- probeJob{URL: c, Source: src}
	}
	close(jobs)
	workerWg.Wait()
	close(results)

	out := []Endpoint{}
	for e := range results {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		rank := map[string]int{"high": 3, "medium": 2, "low": 1}
		ri := rank[out[i].Confidence]
		rj := rank[out[j].Confidence]
		if ri == rj {
			return out[i].URL < out[j].URL
		}
		return ri > rj
	})
	return out, nil
}

func contains(a []string, v string) bool {
	for _, x := range a {
		if x == v {
			return true
		}
	}
	return false
}

func appendIfMissing(a []string, v string) []string {
	if contains(a, v) {
		return a
	}
	return append(a, v)
}
