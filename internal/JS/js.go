package js

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// -------------------- Options & Types --------------------

type JSOptions struct {
	FetchSourceMaps bool
	MaxFetchBytes   int64
	HTTPTimeout     time.Duration
	UserAgent       string
}

func DefaultJSOptions() JSOptions {
	return JSOptions{
		FetchSourceMaps: false,
		MaxFetchBytes:   3 * 1024 * 1024, // 3MB
		HTTPTimeout:     15 * time.Second,
		UserAgent:       "ReconNio/JS/1.0",
	}
}

type InlineScriptMeta struct {
	Index       int      `json:"index"`
	Lines       int      `json:"lines"`
	FirstLines  string   `json:"first_lines,omitempty"`
	LastLines   string   `json:"last_lines,omitempty"`
	Size        int      `json:"size_bytes"`
	Minified    bool     `json:"minified"`
	Obfuscated  bool     `json:"obfuscated"`
	Findings    []string `json:"findings,omitempty"`
	CommentHits []string `json:"comment_hits,omitempty"`
	Snippet     string   `json:"snippet,omitempty"`
}

type ExternalScriptMeta struct {
	URL          string `json:"url"`
	TypeAttr     string `json:"type,omitempty"`
	Async        bool   `json:"async,omitempty"`
	Defer        bool   `json:"defer,omitempty"`
	CrossOrigin  string `json:"crossorigin,omitempty"`
	Integrity    string `json:"integrity,omitempty"`
	Size         int64  `json:"size_bytes,omitempty"`
	SHA1         string `json:"sha1,omitempty"`
	HasSourceMap bool   `json:"has_sourcemap,omitempty"`
	Minified     bool   `json:"minified,omitempty"`
	Obfuscated   bool   `json:"obfuscated,omitempty"`
	Lines        int    `json:"lines,omitempty"`
	Snippet      string `json:"snippet,omitempty"`
}

type SourceMapInfo struct {
	URL                   string   `json:"url"`
	Accessible            bool     `json:"accessible"`
	SourcesCount          int      `json:"sources_count"`
	SourcesContentPresent bool     `json:"sources_content_present"`
	TopFilenames          []string `json:"top_filenames,omitempty"`
	SnippetPreview        string   `json:"snippet_preview,omitempty"`
	DetectedSecrets       []string `json:"detected_secrets,omitempty"`
}

type Evidence struct {
	Context string `json:"context"`
	Snippet string `json:"snippet"`
}

type JSReport struct {
	InputTarget string `json:"input_target,omitempty"`
	PageURL     string `json:"page_url,omitempty"`
	PageStatus  int    `json:"page_status,omitempty"`

	ExternalScripts []ExternalScriptMeta `json:"external_scripts,omitempty"`
	InlineScripts   []InlineScriptMeta   `json:"inline_scripts,omitempty"`
	SourceMaps      []SourceMapInfo      `json:"sourcemaps,omitempty"`

	// categorized buckets
	Frameworks        []Evidence `json:"frameworks,omitempty"`
	Libraries         []Evidence `json:"libraries,omitempty"`
	Trackers          []Evidence `json:"trackers,omitempty"`
	APIs              []Evidence `json:"apis,omitempty"`
	GraphQLEndpoints  []Evidence `json:"graphql_endpoints,omitempty"`
	WebSockets        []Evidence `json:"websockets,omitempty"`
	KeysTokens        []Evidence `json:"keys_tokens,omitempty"`
	ConfigObjects     []Evidence `json:"config_objects,omitempty"`
	CommentsTodos     []Evidence `json:"comments_todos,omitempty"`
	LogicLeaks        []Evidence `json:"logic_leaks,omitempty"`
	DangerousPatterns []Evidence `json:"dangerous_patterns,omitempty"`
	LazyImports       []Evidence `json:"lazy_imports,omitempty"`
	ObfuscationSigns  []Evidence `json:"obfuscation_signs,omitempty"`
	StorageUsage      []Evidence `json:"storage_usage,omitempty"`
	CryptoUsage       []Evidence `json:"crypto_usage,omitempty"`
	RegexPatterns     []Evidence `json:"regex_patterns,omitempty"`
	Dependencies      []Evidence `json:"dependencies,omitempty"`
	ErrorsAndLogs     []Evidence `json:"errors_and_logs,omitempty"`
	OSINT             []Evidence `json:"osint,omitempty"`

	Notes     []string `json:"notes,omitempty"`
	Timestamp string   `json:"timestamp,omitempty"`
}

// -------------------- Regexes & heuristics --------------------

var (
	reScriptTag = regexp.MustCompile(`(?is)<script\b([^>]*)>([\s\S]*?)<\/script>`)

	// attributes (avoid backreferences)
	reAttrSrc       = regexp.MustCompile(`(?i)\bsrc\s*=\s*["']?([^'"\s>]+)["']?`)
	reAttrType      = regexp.MustCompile(`(?i)\btype\s*=\s*["']?([^'"\s>]+)["']?`)
	reAttrAsync     = regexp.MustCompile(`(?i)\basync\b`)
	reAttrDefer     = regexp.MustCompile(`(?i)\bdefer\b`)
	reAttrCross     = regexp.MustCompile(`(?i)\bcrossorigin\s*=\s*["']?([^'"\s>]+)["']?`)
	reAttrIntegrity = regexp.MustCompile(`(?i)\bintegrity\s*=\s*["']?([^'"\s>]+)["']?`)

	reSourceMap1 = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL\s*=\s*(\S+)`)
	reSourceMap2 = regexp.MustCompile(`(?m)/\*#\s*sourceMappingURL\s*=\s*(\S+)\s*\*/`)

	reAWSKey       = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	reGoogleKey    = regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)
	reJWT          = regexp.MustCompile(`eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+`)
	reStripePub    = regexp.MustCompile(`pk_(?:live|test)_[A-Za-z0-9]{16,}`)
	reSentryDSN    = regexp.MustCompile(`https?://[0-9a-fA-F]+@sentry\.io/\d+`)
	reFirebase     = regexp.MustCompile(`(?i)firebaseConfig|firebase:|firebase-app`)
	reGenericToken = regexp.MustCompile(`[A-Za-z0-9\-_]{32,}`)

	reNext    = regexp.MustCompile(`__NEXT_DATA__|next/|NEXT_PUBLIC_`)
	reNuxt    = regexp.MustCompile(`__NUXT__`)
	reReact   = regexp.MustCompile(`(?i)ReactDOM|React\.createElement|react\/`)
	reVue     = regexp.MustCompile(`(?i)__VUE_DEVTOOLS_GLOBAL_HOOK__|Vue\.`)
	reAngular = regexp.MustCompile(`(?i)angular\.module|@angular\/`)
	reSvelte  = regexp.MustCompile(`(?i)\bsvelte\b`)
	reWebpack = regexp.MustCompile(`(?i)__webpack_require__|webpackBootstrap|webpackJsonp`)
	reVite    = regexp.MustCompile(`(?i)import\.meta\.env|Vite`)

	reGTM      = regexp.MustCompile(`(?i)googletagmanager|gtag\(|gtm\.js`)
	reGA       = regexp.MustCompile(`(?i)google-analytics|ga\(|gtag\(`)
	reHotjar   = regexp.MustCompile(`(?i)hotjar`)
	reMixpanel = regexp.MustCompile(`(?i)mixpanel`)
	reIntercom = regexp.MustCompile(`(?i)intercom|intercomSettings`)
	reStripe   = regexp.MustCompile(`(?i)stripe`)
	rePayPal   = regexp.MustCompile(`(?i)paypal`)
	reSentry   = regexp.MustCompile(`(?i)sentry|Raven\.`)

	reAPIpath   = regexp.MustCompile(`(?i)(https?:\/\/[^\s"'()]+\/(api|v[0-9]+)[^\s"'()]*)|(\/(api|v[0-9]+)[^\s"'()]*)`)
	reGraphql   = regexp.MustCompile(`(?i)(https?:\/\/[^\s"'()]+\/graphql[^\s"'()]*)|(\/graphql[^\s"'()]*)`)
	reWebSocket = regexp.MustCompile(`(?i)(wss?:\/\/[^\s"'()]+)|(new\s+WebSocket\s*\(|WebSocket\()`)

	reDanger = regexp.MustCompile(`(?i)\beval\s*\(|\bnew\s+Function\b|document\.write\(|innerHTML\b|insertAdjacentHTML|setTimeout\s*\(\s*["']`)

	reStorage = regexp.MustCompile(`(?i)localStorage\.setItem|localStorage\.getItem|sessionStorage|indexedDB|document\.cookie`)
	reCrypto  = regexp.MustCompile(`(?i)crypto\.subtle|window\.crypto|subtle\.encrypt|subtle\.decrypt|AES|RSA|forge|sjcl`)

	reComments = regexp.MustCompile(`(?s)//.*|/\*[\s\S]*?\*/`)
	reTodo     = regexp.MustCompile(`(?i)\b(TODO|FIXME|CREDENTIAL|PASSWORD|SECRET|DEBUG)\b`)

	reObf                    = regexp.MustCompile(`_0x[a-f0-9]{3,}|\\x[a-f0-9]{2}|var _0x[a-f0-9]{3,}`)
	minifiedLineLenThreshold = 200

	reEmail   = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	reGitHash = regexp.MustCompile(`\b[0-9a-f]{7,40}\b`)

	reDynamicImport = regexp.MustCompile(`(?i)import\(|require\.ensure|System\.import`)
	reDeps          = regexp.MustCompile(`(?i)(?:require\(|import\s+[^\s]+\s+from\s+|/node_modules/|cdnjs\.cloudflare\.com/ajax/libs/)([A-Za-z0-9_@\/\-\.\:]+)`)

	// new: find JS-like URLs in HTML and script content (absolute .js, root-relative .js, /xjs/ loaders)
	reJSURL = regexp.MustCompile(`(?i)(https?:\/\/[^\s"'()]+?\.js[^\s"'()]*)|((?:\/)[^\s"'()]*?\.js\b[^\s"'()]*)|(/xjs/[^\s"'()]*)`)
	// find assignments like el.src = "..."
	reSetSrc = regexp.MustCompile(`(?i)\.src\s*=\s*["']([^"']+)["']`)
	// createElement('script') then set src in same snippet
	reCreateSrc = regexp.MustCompile(`(?is)createElement\(\s*['"]script['"]\s*\).*?src\s*=\s*['"]([^'"]+)['"]`)
	// find escaped \xNN and \uNNNN sequences common in Google loaders
	reHexEscape = regexp.MustCompile(`(?i)\\x([0-9a-f]{2})|\\u([0-9a-f]{4})`)
)

// -------------------- HTTP helpers --------------------

func httpClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		// default transport options; keep it simple so TLS works normally
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}

// returns body, status, finalRequestURL, error
func fetchBytesWithUA(client *http.Client, rawurl string, maxBytes int64, ua string) ([]byte, int, string, error) {
	req, err := http.NewRequest("GET", rawurl, nil)
	if err != nil {
		return nil, 0, "", err
	}
	// set a reasonable UA and accept headers so CDNs / Google don't block us as "Go-http-client"
	if ua == "" {
		ua = "ReconNio/JS/1.0"
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity") // avoid automatic gzip handling complexity
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, "", err
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, maxBytes)
	b, _ := io.ReadAll(limited)
	final := ""
	if resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.String()
	}
	return b, resp.StatusCode, final, nil
}

// -------------------- Utilities --------------------

func sha1Hex(b []byte) string {
	h := sha1.Sum(b)
	return hex.EncodeToString(h[:])
}

func trimSnippet(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func isLikelyMinified(content string) bool {
	lines := strings.Count(content, "\n") + 1
	if lines == 0 {
		return true
	}
	avg := float64(len(content)) / float64(lines)
	return avg > float64(minifiedLineLenThreshold)
}

func findContext(content, pat string, ctx int) string {
	lower := strings.ToLower(content)
	idx := strings.Index(lower, strings.ToLower(pat))
	if idx == -1 {
		if len(content) > ctx {
			return trimSnippet(content, ctx)
		}
		return content
	}
	start := idx - ctx/2
	if start < 0 {
		start = 0
	}
	end := idx + ctx/2
	if end > len(content) {
		end = len(content)
	}
	return strings.TrimSpace(content[start:end])
}

func dedupeEvidence(e []Evidence) []Evidence {
	seen := map[string]struct{}{}
	out := make([]Evidence, 0, len(e))
	for _, it := range e {
		key := it.Context + "|" + it.Snippet
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, it)
	}
	return out
}

// -------------------- Decoding helpers --------------------

// decodeEscapes converts \xNN and \uNNNN sequences to real chars and percent-unescapes.
func decodeEscapes(raw string) string {
	if raw == "" {
		return ""
	}
	// first percent-unescape common cases (so %5Cx becomes \x)
	if u, err := url.PathUnescape(raw); err == nil {
		raw = u
	}
	// replace \xNN and \uNNNN
	out := reHexEscape.ReplaceAllStringFunc(raw, func(m string) string {
		sub := reHexEscape.FindStringSubmatch(m)
		if len(sub) >= 3 {
			// sub[1] = hex for \x, sub[2] = hex for \u (maybe empty)
			if sub[1] != "" {
				v, err := strconv.ParseInt(sub[1], 16, 32)
				if err == nil {
					return string(rune(v))
				}
			}
			if sub[2] != "" {
				v, err := strconv.ParseInt(sub[2], 16, 32)
				if err == nil {
					return string(rune(v))
				}
			}
		}
		return m
	})
	// also unescape common HTML escapes if present
	out = strings.ReplaceAll(out, `\"`, `"`)
	out = strings.ReplaceAll(out, `\'`, `'`)
	return out
}

// normalizeAndResolveURL takes candidate URL/fragment and resolves against base.
// It decodes percent and \x escapes, handles //host paths and relative paths.
func normalizeAndResolveURL(candidate, base string) string {
	c := strings.TrimSpace(candidate)
	if c == "" {
		return ""
	}
	// decode escapes like %5Cx3d -> \x3d and then \x3d -> '=' etc.
	c = decodeEscapes(c)

	// if protocol-relative //example.com/path
	if strings.HasPrefix(c, "//") {
		// use scheme from base if present
		if strings.HasPrefix(base, "http://") || strings.HasPrefix(base, "https://") {
			u, err := url.Parse(base)
			if err == nil && u.Scheme != "" {
				return u.Scheme + ":" + c
			}
		}
		// default to https
		return "https:" + c
	}

	// if absolute URL with scheme
	if strings.HasPrefix(c, "http://") || strings.HasPrefix(c, "https://") {
		return c
	}

	// if root-relative or xjs style
	if strings.HasPrefix(c, "/") || strings.HasPrefix(c, "xjs/") || strings.HasPrefix(c, "/xjs/") {
		if base != "" {
			if b, err := url.Parse(base); err == nil {
				if ru, err2 := url.Parse(c); err2 == nil {
					return b.ResolveReference(ru).String()
				}
			}
		}
		// fallback to https:// + host from base
		if base != "" {
			if b, err := url.Parse(base); err == nil {
				return b.Scheme + "://" + b.Host + c
			}
		}
		// generic fallback
		return "https://" + strings.TrimPrefix(c, "/")
	}

	// relative path (no leading slash)
	if base != "" {
		if b, err := url.Parse(base); err == nil {
			if ru, err2 := url.Parse(c); err2 == nil {
				return b.ResolveReference(ru).String()
			}
		}
	}
	// if nothing else, return as-is
	return c
}

// -------------------- Core scanner --------------------

// Build candidate URLs but prefer ones that keep the user's original host
func buildCandidates(input string) (cands []string, inputHost string) {
	input = strings.TrimSpace(input)
	// if user provided scheme
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		u, err := url.Parse(input)
		if err == nil && u.Host != "" {
			inputHost = u.Hostname()
			cands = []string{input}
			// add canonical host urls as fallback
			cands = append(cands, "https://"+inputHost, "http://"+inputHost)
			return cands, inputHost
		}
	}
	// treat as host-only
	if strings.Contains(input, "://") {
		if u, err := url.Parse(input); err == nil && u.Host != "" {
			inputHost = u.Hostname()
		}
	}
	// strip path if present
	host := input
	if strings.IndexByte(host, '/') != -1 {
		host = strings.SplitN(host, "/", 2)[0]
	}
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimSuffix(host, "/")
	inputHost = host
	cands = []string{"https://" + host, "http://" + host}
	return cands, inputHost
}

// FetchJSInfo: main scanner
func FetchJSInfo(target string, opts *JSOptions) (*JSReport, error) {
	if opts == nil {
		d := DefaultJSOptions()
		opts = &d
	}
	client := httpClient(opts.HTTPTimeout)

	report := &JSReport{
		// preserve exactly what user passed
		InputTarget: strings.TrimSpace(target),
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}

	cands, inputHost := buildCandidates(target)
	var pageBody []byte
	var pageFinal string
	var status int

	// Try candidates, prefer same-host successful response
	var lastErr error
	for _, u := range cands {
		b, code, final, err := fetchBytesWithUA(client, u, opts.MaxFetchBytes, opts.UserAgent)
		if err != nil {
			lastErr = err
			continue
		}
		finalHost := ""
		if final != "" {
			if pu, err := url.Parse(final); err == nil {
				finalHost = pu.Hostname()
			}
		}
		if code >= 200 && code < 400 {
			// host match priority
			if inputHost != "" && finalHost != "" && strings.EqualFold(stripPort(finalHost), stripPort(inputHost)) {
				pageBody = b
				status = code
				pageFinal = final
				break
			}
			// fallback first success
			if pageBody == nil {
				pageBody = b
				status = code
				pageFinal = final
			}
		} else {
			// record non-2xx response as lastErr for diagnostics
			lastErr = fmt.Errorf("HTTP %d", code)
		}
	}

	if pageBody == nil {
		// try direct https/http host attempts
		if inputHost != "" {
			for _, scheme := range []string{"https://", "http://"} {
				u := scheme + inputHost
				b, code, final, err := fetchBytesWithUA(client, u, opts.MaxFetchBytes, opts.UserAgent)
				if err != nil {
					lastErr = err
					continue
				}
				if code >= 200 && code < 400 {
					pageBody = b
					status = code
					pageFinal = final
					break
				} else {
					lastErr = fmt.Errorf("HTTP %d", code)
				}
			}
		}
	}

	if pageBody == nil {
		if lastErr != nil {
			report.Notes = append(report.Notes, fmt.Sprintf("failed to fetch page HTML: %v", lastErr))
		} else {
			report.Notes = append(report.Notes, "failed to fetch page HTML: unknown error")
		}
		// return an empty-but-valid report so the caller still gets something
		return report, nil
	}

	// set page info
	if pageFinal == "" {
		pageFinal = cands[0]
	}
	report.PageURL = pageFinal
	report.PageStatus = status

	html := string(pageBody)

	// scan page HTML itself for endpoints / patterns (helps when inline content contains endpoints)
	scanScriptContent(html, pageFinal, report)

	// find <script> tags and inline scripts
	matches := reScriptTag.FindAllStringSubmatch(html, -1)

	external := []ExternalScriptMeta{}
	inline := []InlineScriptMeta{}

	for idx, mm := range matches {
		attrs := mm[1]
		body := mm[2]

		if reAttrSrc.MatchString(attrs) {
			m := reAttrSrc.FindStringSubmatch(attrs)
			src := ""
			if len(m) >= 2 {
				src = strings.TrimSpace(m[1])
			}
			resolved := normalizeAndResolveURL(src, pageFinal)
			meta := ExternalScriptMeta{URL: resolved}
			if t := reAttrType.FindStringSubmatch(attrs); len(t) >= 2 {
				meta.TypeAttr = t[1]
			}
			meta.Async = reAttrAsync.MatchString(attrs)
			meta.Defer = reAttrDefer.MatchString(attrs)
			if cr := reAttrCross.FindStringSubmatch(attrs); len(cr) >= 2 {
				meta.CrossOrigin = cr[1]
			}
			if ig := reAttrIntegrity.FindStringSubmatch(attrs); len(ig) >= 2 {
				meta.Integrity = ig[1]
			}
			external = append(external, meta)
			continue
		}

		// inline script
		content := strings.TrimSpace(body)
		lines := strings.Count(content, "\n") + 1
		first, last, preview := "", "", ""
		if lines <= 12 {
			preview = content
		} else {
			parts := strings.Split(content, "\n")
			if len(parts) > 6 {
				first = strings.Join(parts[:6], "\n")
				last = strings.Join(parts[len(parts)-6:], "\n")
				preview = first + "\n...snip...\n" + last
			} else {
				preview = content
			}
		}
		meta := InlineScriptMeta{
			Index:      idx + 1,
			Lines:      lines,
			FirstLines: first,
			LastLines:  last,
			Size:       len(content),
			Minified:   isLikelyMinified(content),
			Obfuscated: reObf.MatchString(content),
			Findings:   []string{},
			Snippet:    trimSnippet(preview, 1200),
		}
		if reGTM.MatchString(content) || reGA.MatchString(content) {
			meta.Findings = append(meta.Findings, "Analytics/GTM")
		}
		if reJWT.MatchString(content) {
			meta.Findings = append(meta.Findings, "JWT")
		}
		if reAWSKey.MatchString(content) {
			meta.Findings = append(meta.Findings, "AWS Key")
		}
		if reDanger.MatchString(content) {
			meta.Findings = append(meta.Findings, "Dangerous functions")
		}
		for _, c := range reComments.FindAllString(content, -1) {
			if reTodo.MatchString(c) {
				meta.CommentHits = append(meta.CommentHits, trimSnippet(c, 400))
			}
		}
		inline = append(inline, meta)

		// also scan inline snippet for src assignments and createElement patterns
		for _, m := range reSetSrc.FindAllStringSubmatch(content, -1) {
			if len(m) >= 2 {
				u := strings.TrimSpace(m[1])
				if u != "" {
					res := normalizeAndResolveURL(u, pageFinal)
					external = append(external, ExternalScriptMeta{URL: res})
				}
			}
		}
		for _, m := range reCreateSrc.FindAllStringSubmatch(content, -1) {
			if len(m) >= 2 {
				u := strings.TrimSpace(m[1])
				if u != "" {
					res := normalizeAndResolveURL(u, pageFinal)
					external = append(external, ExternalScriptMeta{URL: res})
				}
			}
		}
	}

	// dedupe external by URL
	external = dedupeExternal(external)

	// --- NEW: scan whole HTML for .js URLs and xjs loader patterns (including escaped ones) ---
	found := map[string]struct{}{}
	// seed from explicit external
	for _, e := range external {
		if strings.TrimSpace(e.URL) != "" {
			found[e.URL] = struct{}{}
		}
	}
	// scan HTML raw for typical JS URL patterns (may be percent-encoded or have \x escapes)
	for _, m := range reJSURL.FindAllString(html, -1) {
		if m == "" {
			continue
		}
		res := normalizeAndResolveURL(m, pageFinal)
		found[res] = struct{}{}
	}
	// also search for escaped xjs strings like k\x3dxjs... inside HTML (common in google)
	// quick heuristic: look for sequences with "\x3d" or "%5Cx3d"
	if strings.Contains(html, `\x3d`) || strings.Contains(strings.ToLower(html), `%5cx3d`) {
		// find possible quoted tokens around xjs fragments
		// coarse: scan for "/xjs/" substring and capture surrounding token by finding nearest quotes/brackets
		i := 0
		for _, idx := range regexp.MustCompile(`(?i)/xjs/`).FindAllStringIndex(html, -1) {
			start := idx[0]
			// capture up to 200 chars around start for decoding
			a := start - 80
			if a < 0 {
				a = 0
			}
			b := start + 200
			if b > len(html) {
				b = len(html)
			}
			snip := html[a:b]
			decoded := decodeEscapes(snip)
			for _, m2 := range reJSURL.FindAllString(decoded, -1) {
				if m2 == "" {
					continue
				}
				res := normalizeAndResolveURL(m2, pageFinal)
				found[res] = struct{}{}
			}
			i++
			if i > 40 {
				break
			}
		}
	}

	// build final jsList
	jsList := make([]ExternalScriptMeta, 0, len(found))
	for u := range found {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		jsList = append(jsList, ExternalScriptMeta{URL: u})
	}

	// fetch and scan each JS candidate
	for i := range jsList {
		meta := &jsList[i]
		if meta.URL == "" {
			continue
		}
		b, code, final, err := fetchBytesWithUA(client, meta.URL, opts.MaxFetchBytes, opts.UserAgent)
		if err != nil {
			report.Notes = append(report.Notes, fmt.Sprintf("failed to fetch %s: %v", meta.URL, err))
			continue
		}
		if code < 200 || code >= 400 || len(b) == 0 {
			report.Notes = append(report.Notes, fmt.Sprintf("failed to fetch %s: HTTP %d (len=%d)", meta.URL, code, len(b)))
			continue
		}
		content := string(b)
		meta.Size = int64(len(b))
		meta.SHA1 = sha1Hex(b)
		meta.Lines = strings.Count(content, "\n") + 1
		meta.Minified = isLikelyMinified(content)
		meta.Obfuscated = reObf.MatchString(content)
		if reSourceMap1.MatchString(content) || reSourceMap2.MatchString(content) {
			meta.HasSourceMap = true
		}
		if len(content) > 400 {
			meta.Snippet = trimSnippet(content, 400)
		} else {
			meta.Snippet = content
		}

		// scan JS content into report buckets
		scanScriptContent(content, meta.URL, report)

		// handle source maps
		baseForSM := meta.URL
		if final != "" {
			baseForSM = final
		}
		if sm := reSourceMap1.FindStringSubmatch(content); len(sm) >= 2 {
			smref := strings.Trim(sm[1], " '\"")
			resolveAndFetchSourcemap(smref, baseForSM, report, client, opts.FetchSourceMaps, opts.MaxFetchBytes, opts.UserAgent)
		} else if sm2 := reSourceMap2.FindStringSubmatch(content); len(sm2) >= 2 {
			smref := strings.Trim(sm2[1], " '\"")
			resolveAndFetchSourcemap(smref, baseForSM, report, client, opts.FetchSourceMaps, opts.MaxFetchBytes, opts.UserAgent)
		}
		_ = code
	}

	// set report external/inlines
	report.ExternalScripts = dedupeExternal(jsList)
	report.InlineScripts = inline

	// dedupe buckets
	report.Frameworks = dedupeEvidence(report.Frameworks)
	report.Libraries = dedupeEvidence(report.Libraries)
	report.Trackers = dedupeEvidence(report.Trackers)
	report.APIs = dedupeEvidence(report.APIs)
	report.GraphQLEndpoints = dedupeEvidence(report.GraphQLEndpoints)
	report.WebSockets = dedupeEvidence(report.WebSockets)
	report.KeysTokens = dedupeEvidence(report.KeysTokens)
	report.ConfigObjects = dedupeEvidence(report.ConfigObjects)
	report.CommentsTodos = dedupeEvidence(report.CommentsTodos)
	report.LogicLeaks = dedupeEvidence(report.LogicLeaks)
	report.DangerousPatterns = dedupeEvidence(report.DangerousPatterns)
	report.LazyImports = dedupeEvidence(report.LazyImports)
	report.ObfuscationSigns = dedupeEvidence(report.ObfuscationSigns)
	report.StorageUsage = dedupeEvidence(report.StorageUsage)
	report.CryptoUsage = dedupeEvidence(report.CryptoUsage)
	report.RegexPatterns = dedupeEvidence(report.RegexPatterns)
	report.Dependencies = dedupeEvidence(report.Dependencies)
	report.ErrorsAndLogs = dedupeEvidence(report.ErrorsAndLogs)
	report.OSINT = dedupeEvidence(report.OSINT)

	report.Notes = append(report.Notes, "passive static scan complete")
	if opts.FetchSourceMaps {
		report.Notes = append(report.Notes, "source maps were requested; inspect SourceMaps entries carefully")
	}
	return report, nil
}

// -------------------- Content scanning --------------------

func scanScriptContent(content, context string, report *JSReport) {
	if reNext.MatchString(content) {
		report.Frameworks = append(report.Frameworks, Evidence{Context: context, Snippet: findContext(content, "__NEXT_DATA__|NEXT_PUBLIC_|next/", 120)})
	}
	if reNuxt.MatchString(content) {
		report.Frameworks = append(report.Frameworks, Evidence{Context: context, Snippet: findContext(content, "__NUXT__", 120)})
	}
	if reReact.MatchString(content) {
		report.Frameworks = append(report.Frameworks, Evidence{Context: context, Snippet: findContext(content, "ReactDOM|React.createElement", 120)})
	}
	if reVue.MatchString(content) {
		report.Frameworks = append(report.Frameworks, Evidence{Context: context, Snippet: findContext(content, "Vue.", 120)})
	}
	if reAngular.MatchString(content) {
		report.Frameworks = append(report.Frameworks, Evidence{Context: context, Snippet: findContext(content, "angular.module", 120)})
	}
	if reSvelte.MatchString(content) {
		report.Frameworks = append(report.Frameworks, Evidence{Context: context, Snippet: "Svelte markers present"})
	}
	if reWebpack.MatchString(content) {
		report.Frameworks = append(report.Frameworks, Evidence{Context: context, Snippet: "Webpack bootstrap detected"})
	}
	if reVite.MatchString(content) {
		report.Frameworks = append(report.Frameworks, Evidence{Context: context, Snippet: "Vite markers detected"})
	}

	if reGTM.MatchString(content) {
		report.Trackers = append(report.Trackers, Evidence{Context: context, Snippet: findContext(content, "googletagmanager|gtag", 120)})
		report.Libraries = append(report.Libraries, Evidence{Context: context, Snippet: "GTM/gtag detected"})
	}
	if reGA.MatchString(content) {
		report.Trackers = append(report.Trackers, Evidence{Context: context, Snippet: findContext(content, "ga(", 120)})
	}
	if reHotjar.MatchString(content) {
		report.Trackers = append(report.Trackers, Evidence{Context: context, Snippet: "Hotjar detected"})
	}
	if reMixpanel.MatchString(content) {
		report.Trackers = append(report.Trackers, Evidence{Context: context, Snippet: "Mixpanel detected"})
	}
	if reIntercom.MatchString(content) {
		report.Libraries = append(report.Libraries, Evidence{Context: context, Snippet: "Intercom detected"})
	}
	if reStripe.MatchString(content) {
		report.Libraries = append(report.Libraries, Evidence{Context: context, Snippet: "Stripe JS detected"})
	}
	if rePayPal.MatchString(content) {
		report.Libraries = append(report.Libraries, Evidence{Context: context, Snippet: "PayPal SDK detected"})
	}
	if reSentry.MatchString(content) {
		report.Libraries = append(report.Libraries, Evidence{Context: context, Snippet: "Sentry / Raven detected"})
	}

	for _, m := range reAPIpath.FindAllString(content, -1) {
		report.APIs = append(report.APIs, Evidence{Context: context, Snippet: trimSnippet(m, 400)})
	}
	for _, g := range reGraphql.FindAllString(content, -1) {
		report.GraphQLEndpoints = append(report.GraphQLEndpoints, Evidence{Context: context, Snippet: trimSnippet(g, 400)})
	}
	for _, w := range reWebSocket.FindAllString(content, -1) {
		report.WebSockets = append(report.WebSockets, Evidence{Context: context, Snippet: trimSnippet(w, 400)})
	}

	for _, r := range []*regexp.Regexp{reAWSKey, reGoogleKey, reJWT, reStripePub, reSentryDSN, reFirebase} {
		for _, f := range r.FindAllString(content, -1) {
			report.KeysTokens = append(report.KeysTokens, Evidence{Context: context, Snippet: trimSnippet(f, 300)})
		}
	}
	for _, f := range reGenericToken.FindAllString(content, -1) {
		if len(f) >= 32 {
			report.KeysTokens = append(report.KeysTokens, Evidence{Context: context, Snippet: trimSnippet(f, 200)})
		}
	}

	if strings.Contains(content, "window.__APP_CONFIG__") || strings.Contains(content, "window.APP_CONFIG") {
		report.ConfigObjects = append(report.ConfigObjects, Evidence{Context: context, Snippet: findContext(content, "window.__APP_CONFIG__|window.APP_CONFIG", 120)})
	}
	if strings.Contains(content, "process.env") || strings.Contains(content, "REACT_APP_") || strings.Contains(content, "NEXT_PUBLIC_") {
		report.ConfigObjects = append(report.ConfigObjects, Evidence{Context: context, Snippet: findContext(content, "process.env|REACT_APP_|NEXT_PUBLIC_", 120)})
	}

	for _, c := range reComments.FindAllString(content, -1) {
		if reTodo.MatchString(c) {
			report.CommentsTodos = append(report.CommentsTodos, Evidence{Context: context, Snippet: trimSnippet(c, 400)})
		}
	}

	for _, kw := range []string{"isAdmin", "getToken", "loginUser", "/admin", "/staging", "internalApi", "internal_api"} {
		if strings.Contains(strings.ToLower(content), strings.ToLower(kw)) {
			report.LogicLeaks = append(report.LogicLeaks, Evidence{Context: context, Snippet: findContext(content, kw, 120)})
		}
	}

	for _, s := range reDanger.FindAllString(content, -1) {
		report.DangerousPatterns = append(report.DangerousPatterns, Evidence{Context: context, Snippet: trimSnippet(s, 200)})
	}

	for _, s := range reDynamicImport.FindAllString(content, -1) {
		report.LazyImports = append(report.LazyImports, Evidence{Context: context, Snippet: trimSnippet(s, 200)})
	}

	if reObf.MatchString(content) {
		report.ObfuscationSigns = append(report.ObfuscationSigns, Evidence{Context: context, Snippet: findContext(content, "_0x", 120)})
	}
	if isLikelyMinified(content) {
		report.ObfuscationSigns = append(report.ObfuscationSigns, Evidence{Context: context, Snippet: "File appears minified (long lines / few line breaks)"})
	}

	for _, s := range reStorage.FindAllString(content, -1) {
		report.StorageUsage = append(report.StorageUsage, Evidence{Context: context, Snippet: trimSnippet(s, 200)})
	}
	for _, s := range reCrypto.FindAllString(content, -1) {
		report.CryptoUsage = append(report.CryptoUsage, Evidence{Context: context, Snippet: trimSnippet(s, 200)})
	}

	if rr := findFirstMatch(rePasswordLike(), content); rr != "" {
		report.RegexPatterns = append(report.RegexPatterns, Evidence{Context: context, Snippet: trimSnippet(rr, 300)})
	}

	for _, d := range reDeps.FindAllStringSubmatch(content, -1) {
		if len(d) >= 2 {
			report.Dependencies = append(report.Dependencies, Evidence{Context: context, Snippet: trimSnippet(d[1], 200)})
		}
	}

	if strings.Contains(content, "console.log") || strings.Contains(content, "console.error") {
		report.ErrorsAndLogs = append(report.ErrorsAndLogs, Evidence{Context: context, Snippet: findContext(content, "console.log|console.error", 120)})
	}
	if strings.Contains(content, ".stack") || strings.Contains(strings.ToLower(content), "stacktrace") {
		report.ErrorsAndLogs = append(report.ErrorsAndLogs, Evidence{Context: context, Snippet: findContext(content, ".stack", 120)})
	}

	for _, em := range reEmail.FindAllString(content, -1) {
		report.OSINT = append(report.OSINT, Evidence{Context: context, Snippet: em})
	}
	for _, h := range reGitHash.FindAllString(content, -1) {
		if len(h) >= 7 && len(h) <= 40 {
			report.OSINT = append(report.OSINT, Evidence{Context: context, Snippet: h})
		}
	}
}

func rePasswordLike() *regexp.Regexp {
	return regexp.MustCompile(`(?i)(password|minlength|minLength|match\(|minLength)`)
}

func findFirstMatch(r *regexp.Regexp, content string) string {
	if r == nil {
		return ""
	}
	return r.FindString(content)
}

// -------------------- Source map handling --------------------

// note: added ua param so sourcemap fetches use same UA
func resolveAndFetchSourcemap(smref, baseURL string, report *JSReport, client *http.Client, fetch bool, maxBytes int64, ua string) {
	if smref == "" {
		return
	}
	smURL := smref
	if u, err := url.Parse(smref); err == nil && u.Scheme == "" {
		if b, err2 := url.Parse(baseURL); err2 == nil {
			smURL = b.ResolveReference(u).String()
		}
	}
	sm := SourceMapInfo{URL: smURL}
	if !fetch {
		report.SourceMaps = append(report.SourceMaps, sm)
		return
	}
	b, status, _, err := fetchBytesWithUA(client, smURL, maxBytes, ua)
	if err != nil {
		sm.Accessible = false
		sm.SnippetPreview = fmt.Sprintf("fetch error: %v", err)
		report.SourceMaps = append(report.SourceMaps, sm)
		return
	}
	if status < 200 || status >= 400 {
		sm.Accessible = false
		sm.SnippetPreview = fmt.Sprintf("HTTP %d", status)
		report.SourceMaps = append(report.SourceMaps, sm)
		return
	}
	sm.Accessible = true

	var parsed map[string]interface{}
	if err := json.Unmarshal(b, &parsed); err != nil {
		sm.SnippetPreview = trimSnippet(string(b), 400)
		report.SourceMaps = append(report.SourceMaps, sm)
		return
	}

	if srcs, ok := parsed["sources"].([]interface{}); ok {
		for _, s := range srcs {
			if ss, ok2 := s.(string); ok2 {
				sm.TopFilenames = append(sm.TopFilenames, ss)
			}
		}
		sm.SourcesCount = len(sm.TopFilenames)
	}
	if sc, ok := parsed["sourcesContent"].([]interface{}); ok && len(sc) > 0 {
		sm.SourcesContentPresent = true
		ds := []string{}
		for i := 0; i < len(sc) && i < 3; i++ {
			if part, ok2 := sc[i].(string); ok2 {
				preview := trimSnippet(part, 400)
				if sm.SnippetPreview == "" {
					sm.SnippetPreview = preview
				} else {
					sm.SnippetPreview += "\n---\n" + preview
				}
				foundAny := []string{}
				if k := reAWSKey.FindString(part); k != "" {
					foundAny = append(foundAny, k)
				}
				if j := reJWT.FindString(part); j != "" {
					foundAny = append(foundAny, j)
				}
				if g := reGoogleKey.FindString(part); g != "" {
					foundAny = append(foundAny, g)
				}
				if len(foundAny) > 0 {
					ds = append(ds, strings.Join(foundAny, " | "))
				}
			}
		}
		sm.DetectedSecrets = ds
	}
	report.SourceMaps = append(report.SourceMaps, sm)
}

// -------------------- Helpers --------------------

func dedupeExternal(in []ExternalScriptMeta) []ExternalScriptMeta {
	seen := map[string]struct{}{}
	out := make([]ExternalScriptMeta, 0, len(in))
	for _, s := range in {
		u := strings.TrimSpace(s.URL)
		if u == "" {
			out = append(out, s)
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, s)
	}
	return out
}

func stripPort(host string) string {
	if i := strings.IndexByte(host, ':'); i != -1 {
		return host[:i]
	}
	return host
}

// -------------------- Console formatter --------------------

func FormatConsole(r *JSReport) string {
	var sb strings.Builder
	w := func(s string) { sb.WriteString(s + "\n") }

	w("┌─ JavaScript Recon (detailed)")
	if r.InputTarget != "" {
		w(fmt.Sprintf("│  Input: %s", r.InputTarget))
	}
	if r.PageURL != "" {
		w(fmt.Sprintf("│  Page: %s", r.PageURL))
	}
	if r.PageStatus != 0 {
		w(fmt.Sprintf("│  HTTP status: %d", r.PageStatus))
	}
	w(fmt.Sprintf("│  Generated: %s", r.Timestamp))

	w(fmt.Sprintf("│  External scripts: %d", len(r.ExternalScripts)))
	for _, s := range r.ExternalScripts {
		w(fmt.Sprintf("│    - %s", s.URL))
	}
	w(fmt.Sprintf("│  Inline scripts: %d", len(r.InlineScripts)))
	limitInline := 6
	if limitInline > len(r.InlineScripts) {
		limitInline = len(r.InlineScripts)
	}
	for i := 0; i < limitInline; i++ {
		ins := r.InlineScripts[i]
		w(fmt.Sprintf("│    snippet[%d]: %s", i+1, trimSnippet(ins.Snippet, 320)))
	}
	if len(r.InlineScripts) > limitInline {
		w(fmt.Sprintf("│    ... (%d more inline scripts)", len(r.InlineScripts)-limitInline))
	}

	w(fmt.Sprintf("│  SourceMaps: %d", len(r.SourceMaps)))
	for _, sm := range r.SourceMaps {
		w(fmt.Sprintf("│    - %s (accessible=%v sources=%d content=%v)",
			sm.URL, sm.Accessible, sm.SourcesCount, sm.SourcesContentPresent))
		if sm.SnippetPreview != "" {
			w(fmt.Sprintf("│       preview: %s", trimSnippet(sm.SnippetPreview, 180)))
		}
		if len(sm.DetectedSecrets) > 0 {
			w(fmt.Sprintf("│       detected_secrets: %s", strings.Join(sm.DetectedSecrets, ", ")))
		}
	}

	printFew := func(title string, items []Evidence, limit int) {
		w(fmt.Sprintf("│  %s: %d", title, len(items)))
		if len(items) == 0 {
			return
		}
		if limit <= 0 || limit > len(items) {
			limit = len(items)
		}
		for i := 0; i < limit; i++ {
			it := items[i]
			w(fmt.Sprintf("│    - [%s] %s", it.Context, trimSnippet(it.Snippet, 180)))
		}
		if len(items) > limit {
			w(fmt.Sprintf("│    ... and %d more", len(items)-limit))
		}
	}

	printFew("Framework markers", r.Frameworks, 3)
	printFew("Libraries/SDKs", r.Libraries, 4)
	printFew("Trackers", r.Trackers, 6)
	printFew("APIs discovered", r.APIs, 8)
	printFew("GraphQL endpoints", r.GraphQLEndpoints, 6)
	printFew("WebSocket endpoints", r.WebSockets, 6)
	printFew("Keys/Tokens", r.KeysTokens, 12)
	printFew("Dangerous patterns", r.DangerousPatterns, 6)
	printFew("Obfuscation signs", r.ObfuscationSigns, 6)
	printFew("Storage usage", r.StorageUsage, 4)
	printFew("Crypto usage", r.CryptoUsage, 4)
	printFew("Regex / validation patterns", r.RegexPatterns, 4)
	printFew("Dependency hints", r.Dependencies, 8)
	printFew("Errors & console logs", r.ErrorsAndLogs, 6)
	printFew("Comments / TODOs", r.CommentsTodos, 6)
	printFew("OSINT (emails/hashes/ids)", r.OSINT, 12)

	if len(r.Notes) > 0 {
		w("│  Notes:")
		for _, n := range r.Notes {
			w(fmt.Sprintf("│    - %s", n))
		}
	}
	w("└────────────────────────────")
	return sb.String()
}

// small utility for facebook detection
func reFacebookMatch(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "facebook") || strings.Contains(l, "fbq(")
}
