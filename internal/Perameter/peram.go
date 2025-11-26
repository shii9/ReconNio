// internal/Perameter/perameter.go
package perameter

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// -------------------- Public types --------------------

type ParamLocation struct {
	Type   string `json:"type"`             // query|body|header|cookie|path|form|graphql
	URL    string `json:"url,omitempty"`    // location URL
	Method string `json:"method,omitempty"` // GET/POST
	Field  string `json:"field,omitempty"`  // field/key/header name
}

type ParameterFinding struct {
	Name            string          `json:"name"`
	Locations       []ParamLocation `json:"locations,omitempty"`
	ExampleValues   []string        `json:"example_values,omitempty"`
	Sensitive       bool            `json:"sensitive,omitempty"`
	PotentialIssues []string        `json:"potential_issues,omitempty"` // e.g., open-redirect, idor, xss
	Confidence      string          `json:"confidence,omitempty"`       // low|medium|high
	Notes           []string        `json:"notes,omitempty"`
	Severity        string          `json:"severity,omitempty"` // informational|low|medium|high
	Evidence        []string        `json:"evidence,omitempty"`
}

type Report struct {
	Target    string             `json:"target"`
	Findings  []ParameterFinding `json:"findings,omitempty"`
	ScannedAt string             `json:"scanned_at,omitempty"`
}

// Options controls behaviour of the parameter module
type Options struct {
	UA               string
	Enable           bool // whether to run parameter module at all
	DisableActive    bool // respect -disable-active
	JS               bool // whether to fetch/analyze JS files (if main didn't already fetch)
	ParamWordlist    string
	ParamConcurrency int
	TimeoutSec       int

	// Additional controls
	ExternalClient   *http.Client // if provided, use this client (allows sharing configs)
	AllowRequest     func()       // optional hook called before each network request (e.g., rate limiter)
	UAList           []string     // optional UA rotation list
	Jitter           float64      // seconds
	Retries          int          // retry attempts
	EnableSSRF       bool         // explicit opt-in for SSRF-style active probes
	EnableTamper     bool         // explicit opt-in for tamper tests (signed params, replay)
	EnableHeaderFuzz bool         // opt-in header fuzzing
	MaxBodyRead      int64        // maximum body bytes to read
}

// -------------------- internal regexes & lists --------------------

var (
	formRe           = regexp.MustCompile(`(?is)<form[^>]*>(.*?)</form>`)
	inputNameRe      = regexp.MustCompile(`(?i)(?:name|id)=["']?([^"'\s>]+)`)
	actionRe         = regexp.MustCompile(`(?i)action=["']?([^"'\s>]+)`)
	fetchRe          = regexp.MustCompile(`(?i)fetch\s*\(\s*['"]([^'")]+)['"]`)
	urlLikeRe        = regexp.MustCompile(`(?i)https?://[A-Za-z0-9\-\._~:\/\?#\[\]@!$&'()*+,;=%]+|\/[A-Za-z0-9\-\._~:\/\?#@!$&'()*+,;=%]+\?[A-Za-z0-9_\-=&%]+`)
	sourceMapRe      = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL\s*=\s*(.+)$`)
	sensitiveKeys    = []string{"token", "key", "secret", "passwd", "password", "auth", "api", "bearer", "session", "jwt", "access", "private", "client_secret", "secret_key"}
	jwtRe            = regexp.MustCompile(`(?i)(?:bearer\s+)?([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)`) // crude JWT detector
	signedParamNames = []string{"sig", "signature", "hash", "hmac", "mac", "digest"}
	ssrfParamNames   = []string{"url", "redirect", "callback", "next", "return", "img", "endpoint", "target"}
)

func containsSensitive(name string) bool {
	ln := strings.ToLower(name)
	for _, w := range sensitiveKeys {
		if strings.Contains(ln, w) {
			return true
		}
	}
	return false
}

func dedupeStrings(s []string) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, v := range s {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func dedupeFindings(in []ParameterFinding) []ParameterFinding {
	m := map[string]*ParameterFinding{}
	for _, f := range in {
		k := strings.ToLower(strings.TrimSpace(f.Name))
		if k == "" {
			continue
		}
		if ex, ok := m[k]; ok {
			ex.Locations = append(ex.Locations, f.Locations...)
			ex.ExampleValues = append(ex.ExampleValues, f.ExampleValues...)
			ex.PotentialIssues = append(ex.PotentialIssues, f.PotentialIssues...)
			ex.Notes = append(ex.Notes, f.Notes...)
			ex.Evidence = append(ex.Evidence, f.Evidence...)
			if !ex.Sensitive && f.Sensitive {
				ex.Sensitive = true
			}
			rank := map[string]int{"high": 3, "medium": 2, "low": 1}
			if rank[f.Confidence] > rank[ex.Confidence] {
				ex.Confidence = f.Confidence
			}
			// severity: pick higher
			sr := map[string]int{"high": 3, "medium": 2, "low": 1, "informational": 0}
			if sr[f.Severity] > sr[ex.Severity] {
				ex.Severity = f.Severity
			}
		} else {
			copyF := f
			m[k] = &copyF
		}
	}
	out := []ParameterFinding{}
	for _, v := range m {
		v.ExampleValues = dedupeStrings(v.ExampleValues)
		v.PotentialIssues = dedupeStrings(v.PotentialIssues)
		v.Notes = dedupeStrings(v.Notes)
		v.Evidence = dedupeStrings(v.Evidence)
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Sensitive != out[j].Sensitive {
			return out[i].Sensitive
		}
		r := map[string]int{"high": 3, "medium": 2, "low": 1}
		return r[out[i].Confidence] > r[out[j].Confidence]
	})
	return out
}

func sizeSimilarity(a, b []byte) float64 {
	la := len(a)
	lb := len(b)
	if la == 0 && lb == 0 {
		return 1.0
	}
	max := la
	if lb > max {
		max = lb
	}
	if max == 0 {
		return 1.0
	}
	diff := la - lb
	if diff < 0 {
		diff = -diff
	}
	r := 1.0 - (float64(diff) / float64(max))
	if r < 0 {
		r = 0
	}
	return r
}

func buildClient(timeoutSec int, ext *http.Client) *http.Client {
	if ext != nil {
		return ext
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeoutSec) * time.Second,
	}
}

// simple request with retries, jitter, UA rotation and optional AllowRequest hook
func simpleDo(opts Options, method, raw string, body io.Reader, maxBody int64, extraHeaders map[string]string) ([]byte, int, http.Header, error) {
	client := buildClient(opts.TimeoutSec, opts.ExternalClient)
	ua := opts.UA
	if ua == "" {
		ua = "ReconNio/1.0"
	}
	// choose ua from list if provided
	if len(opts.UAList) > 0 {
		rand.Seed(time.Now().UnixNano())
		ua = opts.UAList[rand.Intn(len(opts.UAList))]
	}

	if opts.AllowRequest != nil {
		opts.AllowRequest()
	}

	attempts := 1
	if opts.Retries > 0 {
		attempts = opts.Retries + 1
	}

	var lastErr error
	for a := 0; a < attempts; a++ {
		if opts.Jitter > 0 {
			time.Sleep(time.Duration(rand.Int63n(int64(opts.Jitter*1000))) * time.Millisecond)
		}
		req, err := http.NewRequest(method, raw, body)
		if err != nil {
			return nil, 0, nil, err
		}
		req.Header.Set("User-Agent", ua)
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			// backoff
			time.Sleep(time.Duration(200*(a+1)) * time.Millisecond)
			continue
		}
		defer resp.Body.Close()
		limited := io.LimitReader(resp.Body, maxBody)
		b, err := io.ReadAll(limited)
		if err != nil {
			lastErr = err
			continue
		}
		return b, resp.StatusCode, resp.Header, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("unknown request error")
	}
	return nil, 0, nil, lastErr
}

// -------------------- extractors --------------------

func extractParamsFromURL(u *url.URL) []ParameterFinding {
	out := []ParameterFinding{}
	if u == nil {
		return out
	}
	q := u.Query()
	for k, vals := range q {
		p := ParameterFinding{
			Name:          k,
			Locations:     []ParamLocation{{Type: "query", URL: u.String(), Method: "GET", Field: k}},
			ExampleValues: dedupeStrings(vals),
			Sensitive:     containsSensitive(k),
			Confidence:    "medium",
			Severity:      "informational",
		}
		out = append(out, p)
	}
	return out
}

func extractParamsFromHTML(body []byte, base *url.URL) []ParameterFinding {
	out := []ParameterFinding{}
	s := string(body)
	forms := formRe.FindAllStringSubmatch(s, -1)
	for _, fm := range forms {
		formBlock := fm[1]
		action := ""
		if am := actionRe.FindStringSubmatch(formBlock); len(am) >= 2 {
			action = strings.TrimSpace(am[1])
			if u, err := url.Parse(action); err == nil && u != nil && base != nil {
				action = base.ResolveReference(u).String()
			}
		}
		inputs := inputNameRe.FindAllStringSubmatch(formBlock, -1)
		for _, in := range inputs {
			name := strings.TrimSpace(in[1])
			if name == "" {
				continue
			}
			p := ParameterFinding{
				Name:          name,
				Locations:     []ParamLocation{{Type: "form", URL: actionOrBase(action, base), Method: "POST", Field: name}},
				Sensitive:     containsSensitive(name),
				Confidence:    "medium",
				ExampleValues: []string{},
				Severity:      "informational",
			}
			out = append(out, p)
		}
	}

	links := urlLikeRe.FindAllString(s, -1)
	for _, l := range links {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "/") && base != nil {
			u := base.ResolveReference(&url.URL{Path: l})
			if u != nil && u.RawQuery != "" {
				out = append(out, extractParamsFromURL(u)...)
			}
			continue
		}
		if strings.HasPrefix(l, "http") {
			if u, err := url.Parse(l); err == nil && u.RawQuery != "" {
				if base != nil && u.Host == base.Host {
					out = append(out, extractParamsFromURL(u)...)
				}
			}
		}
	}

	return out
}

func actionOrBase(action string, base *url.URL) string {
	if action == "" {
		if base == nil {
			return ""
		}
		return base.String()
	}
	if u, err := url.Parse(action); err == nil && u != nil && base != nil {
		return base.ResolveReference(u).String()
	}
	return action
}

func extractParamsFromJS(body []byte, base *url.URL) ([]ParameterFinding, []string) {
	out := []ParameterFinding{}
	endpoints := []string{}
	s := string(body)

	for _, m := range fetchRe.FindAllStringSubmatch(s, -1) {
		if len(m) >= 2 {
			raw := strings.TrimSpace(m[1])
			if u, err := url.Parse(raw); err == nil && u != nil {
				if u.Host == "" && base != nil {
					u = base.ResolveReference(u)
				}
				if u != nil {
					endpoints = append(endpoints, u.String())
					if u.RawQuery != "" {
						out = append(out, extractParamsFromURL(u)...)
					}
					continue
				}
			}
			qre := regexp.MustCompile(`[?&]([A-Za-z0-9_\-]+)=`)
			for _, mm := range qre.FindAllStringSubmatch(raw, -1) {
				if len(mm) >= 2 {
					name := mm[1]
					out = append(out, ParameterFinding{
						Name:          name,
						Locations:     []ParamLocation{{Type: "query", URL: baseString(base), Method: "GET", Field: name}},
						ExampleValues: []string{},
						Sensitive:     containsSensitive(name),
						Confidence:    "low",
						Severity:      "informational",
					})
				}
			}
		}
	}

	for _, m := range urlLikeRe.FindAllString(s, -1) {
		if strings.HasPrefix(m, "/") || strings.HasPrefix(m, "http") {
			if u, err := url.Parse(m); err == nil && u != nil {
				if u.Host == "" && base != nil {
					u = base.ResolveReference(u)
				}
				if u != nil {
					endpoints = append(endpoints, u.String())
					if u.RawQuery != "" {
						out = append(out, extractParamsFromURL(u)...)
					}
				}
			}
		}
	}

	return out, dedupeStrings(endpoints)
}

func baseString(b *url.URL) string {
	if b == nil {
		return ""
	}
	return b.String()
}

// extract parameters from headers (Set-Cookie, Authorization, custom headers)
func extractParamsFromHeaders(h http.Header, source string) []ParameterFinding {
	out := []ParameterFinding{}
	// Authorization
	if auth := h.Get("Authorization"); auth != "" {
		// try to extract token
		if m := jwtRe.FindStringSubmatch(auth); len(m) >= 2 {
			val := m[1]
			pf := ParameterFinding{
				Name:          "Authorization",
				Locations:     []ParamLocation{{Type: "header", URL: source, Field: "Authorization"}},
				ExampleValues: []string{auth, val},
				Sensitive:     true,
				Confidence:    "high",
				Severity:      "high",
				Notes:         []string{"Bearer token detected"},
			}
			out = append(out, pf)
		}
	}

	// Set-Cookie values
	for _, sc := range h.Values("Set-Cookie") {
		// split on ; first part
		parts := strings.SplitN(sc, ";", 2)
		if len(parts) >= 1 {
			kv := strings.SplitN(parts[0], "=", 2)
			if len(kv) == 2 {
				name := strings.TrimSpace(kv[0])
				val := strings.TrimSpace(kv[1])
				pf := ParameterFinding{
					Name:          name,
					Locations:     []ParamLocation{{Type: "cookie", URL: source, Field: name}},
					ExampleValues: []string{val},
					Sensitive:     containsSensitive(name),
					Confidence:    "medium",
					Severity:      "informational",
				}
				out = append(out, pf)
			}
		}
	}

	// custom headers that look like API keys
	for k, vals := range h {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-api-") || strings.HasPrefix(lk, "x-aws-") || strings.Contains(lk, "api") || strings.Contains(lk, "key") {
			pf := ParameterFinding{
				Name:          k,
				Locations:     []ParamLocation{{Type: "header", URL: source, Field: k}},
				ExampleValues: vals,
				Sensitive:     true,
				Confidence:    "medium",
				Severity:      "medium",
			}
			out = append(out, pf)
		}
	}

	return out
}

// OpenAPI passive scan (unchanged but improved confidence)
func fetchOpenAPI(client *http.Client, base *url.URL, opts Options) []ParameterFinding {
	paths := []string{"/openapi.json", "/swagger.json", "/v2/api-docs", "/swagger/v1/swagger.json"}
	out := []ParameterFinding{}
	for _, p := range paths {
		u := base.ResolveReference(&url.URL{Path: p})
		b, status, _, err := simpleDo(opts, "GET", u.String(), nil, 2*1024*1024, nil)
		if err != nil || status >= 400 {
			continue
		}
		var doc map[string]interface{}
		if json.Unmarshal(b, &doc) != nil {
			continue
		}
		walkOpenAPI(doc, &out, u.String())
	}
	return out
}

func walkOpenAPI(v interface{}, out *[]ParameterFinding, source string) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			if strings.ToLower(k) == "parameters" {
				if arr, ok := val.([]interface{}); ok {
					for _, it := range arr {
						if pm, ok2 := it.(map[string]interface{}); ok2 {
							name := ""
							in := ""
							if n, ok3 := pm["name"].(string); ok3 {
								name = n
							}
							if ni, ok3 := pm["in"].(string); ok3 {
								in = ni
							}
							pf := ParameterFinding{
								Name:          name,
								Locations:     []ParamLocation{{Type: in, URL: source, Field: name}},
								Sensitive:     containsSensitive(name),
								Confidence:    "high",
								ExampleValues: []string{},
								Severity:      "medium",
							}
							*out = append(*out, pf)
						}
					}
				}
			}
			walkOpenAPI(val, out, source)
		}
	case []interface{}:
		for _, e := range t {
			walkOpenAPI(e, out, source)
		}
	}
}

// GraphQL detection & optional introspection
func detectGraphQL(client *http.Client, base *url.URL, opts Options) []ParameterFinding {
	cands := []string{"/graphql", "/api/graphql", "/gql"}
	out := []ParameterFinding{}
	for _, p := range cands {
		u := base.ResolveReference(&url.URL{Path: p})
		_, status, _, err := simpleDo(opts, "GET", u.String(), nil, 1, nil)
		if err != nil || status >= 400 {
			continue
		}
		if opts.DisableActive {
			out = append(out, ParameterFinding{
				Name:       "__graphql_endpoint",
				Locations:  []ParamLocation{{Type: "graphql", URL: u.String()}},
				Confidence: "medium",
				Notes:      []string{"GraphQL endpoint found; introspection disabled"},
				Severity:   "informational",
			})
			continue
		}
		query := `{"query":"query IntrospectionQuery { __schema { types { name fields { name args { name } } } } }" }`
		b, st, _, err := simpleDo(opts, "POST", u.String(), bytes.NewReader([]byte(query)), 1024*1024, map[string]string{"Content-Type": "application/json"})
		if err != nil || st >= 400 {
			// still report endpoint discovered
			out = append(out, ParameterFinding{Name: "__graphql_endpoint", Locations: []ParamLocation{{Type: "graphql", URL: u.String()}}, Confidence: "medium", Notes: []string{"GraphQL endpoint found; introspection failed or blocked"}, Severity: "informational"})
			continue
		}
		var doc map[string]interface{}
		if json.Unmarshal(b, &doc) != nil {
			continue
		}
		if data, ok := doc["data"].(map[string]interface{}); ok {
			collectGraphQLArgs(data, &out, u.String())
		}
	}
	return out
}

func collectGraphQLArgs(v interface{}, out *[]ParameterFinding, source string) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			if k == "types" {
				if arr, ok := val.([]interface{}); ok {
					for _, it := range arr {
						if m, ok2 := it.(map[string]interface{}); ok2 {
							if fields, ok3 := m["fields"].([]interface{}); ok3 {
								for _, f := range fields {
									if fm, ok4 := f.(map[string]interface{}); ok4 {
										if args, ok5 := fm["args"].([]interface{}); ok5 {
											for _, a := range args {
												if am, ok6 := a.(map[string]interface{}); ok6 {
													if name, ok7 := am["name"].(string); ok7 {
														*out = append(*out, ParameterFinding{Name: name, Locations: []ParamLocation{{Type: "graphql", URL: source, Field: name}}, Sensitive: containsSensitive(name), Confidence: "high", ExampleValues: []string{}, Severity: "medium"})
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
			collectGraphQLArgs(val, out, source)
		}
	case []interface{}:
		for _, e := range t {
			collectGraphQLArgs(e, out, source)
		}
	}
}

// -------------------- Wordlist loader & active fuzz --------------------

func loadWordlist(path string) ([]string, error) {
	out := []string{}
	if path == "" {
		out = []string{"id", "page", "q", "search", "redirect", "next", "token", "auth", "user", "email", "ref", "url", "callback", "session", "order", "sort", "file", "path", "template", "sig", "signature", "hash", "role", "uid", "amount"}
		return out, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return dedupeStrings(out), nil
}

// header fuzz payloads
var headerFuzzers = map[string][]string{
	"X-Forwarded-For": {"127.0.0.1", "169.254.169.254", "8.8.8.8"},
	"Origin":          {"https://evil.com", "null"},
	"Referer":         {"https://evil.com"},
	"X-Api-Key":       {"reconnio_probe_key"},
}

func fuzzParams(opts Options, endpoints []string, wordlist []string, concurrency int) []ParameterFinding {
	out := []ParameterFinding{}
	if len(endpoints) == 0 || len(wordlist) == 0 {
		return out
	}
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, ep := range endpoints {
		u0, err := url.Parse(ep)
		if err != nil {
			continue
		}
		baseBody, _, headers, err := simpleDo(opts, "GET", u0.String(), nil, 512*1024, nil)
		if err != nil {
			baseBody = nil
		}
		// capture headers as findings
		headFinds := extractParamsFromHeaders(headers, u0.String())
		for _, hf := range headFinds {
			out = append(out, hf)
		}

		for _, param := range wordlist {
			wg.Add(1)
			sem <- struct{}{}
			go func(epurl *url.URL, p string, baseline []byte) {
				defer wg.Done()
				defer func() { <-sem }()
				probeVal := "reconnio_probe_" + fmt.Sprintf("%d", time.Now().UnixNano()%1000000)
				// GET probe
				u := *epurl
				q := u.Query()
				q.Set(p, probeVal)
				u.RawQuery = q.Encode()

				body, status, respHeaders, err := simpleDo(opts, "GET", u.String(), nil, 512*1024, nil)
				if err == nil {
					issues := []string{}
					found := false
					if bytes.Contains(body, []byte(probeVal)) {
						found = true
						issues = append(issues, "reflection")
					}
					if status >= 300 && status < 400 {
						found = true
						issues = append(issues, "redirect")
						if loc := respHeaders.Get("Location"); loc != "" {
							if strings.HasPrefix(strings.ToLower(loc), "http") {
								issues = append(issues, "open_redirect")
							}
						}
					}
					if baseline != nil && len(baseline) > 0 && len(body) > 0 {
						sim := sizeSimilarity(baseline, body)
						if sim < 0.75 {
							found = true
							issues = append(issues, "different_size")
						}
					}

					// header reflection detection
					for hn, _ := range respHeaders {
						for _, hv := range respHeaders.Values(hn) {
							if strings.Contains(hv, probeVal) {
								found = true
								issues = append(issues, "header_reflection")
							}
						}
					}

					// Parameter pollution test (double param)
					u2 := *epurl
					q2 := u2.Query()
					q2.Add(p, "first")
					q2.Add(p, "second")
					u2.RawQuery = q2.Encode()
					b2, st2, _, _ := simpleDo(opts, "GET", u2.String(), nil, 512*1024, nil)
					if st2 >= 200 && st2 < 400 && !bytes.Equal(b2, body) {
						found = true
						issues = append(issues, "parameter_pollution")
					}

					// length/boundary test (long payload)
					longVal := strings.Repeat("A", 2000)
					u3 := *epurl
					q3 := u3.Query()
					q3.Set(p, longVal)
					u3.RawQuery = q3.Encode()
					b3, st3, _, _ := simpleDo(opts, "GET", u3.String(), nil, 512*1024, nil)
					if st3 >= 500 || (len(b3) > 0 && baseline != nil && sizeSimilarity(baseline, b3) < 0.3) {
						found = true
						issues = append(issues, "boundary_error")
					}

					// signed param heuristic
					for _, spn := range signedParamNames {
						if p == spn {
							// if signature param exists we try tamper test on another param (non-destructive)
							if opts.EnableTamper {
								u4 := *epurl
								q4 := u4.Query()
								q4.Set(p, probeVal)
								// change another param without updating signature
								u4.RawQuery = q4.Encode()
								b4, st4, _, _ := simpleDo(opts, "GET", u4.String(), nil, 512*1024, nil)
								if st4 >= 200 && st4 < 400 && bytes.Equal(b4, body) {
									issues = append(issues, "signed_param_not_validated")
									found = true
								}
							}
						}
					}

					if found {
						pf := ParameterFinding{
							Name:            p,
							Locations:       []ParamLocation{{Type: "query", URL: epurl.String(), Method: "GET", Field: p}},
							ExampleValues:   []string{probeVal},
							Sensitive:       containsSensitive(p),
							PotentialIssues: dedupeStrings(issues),
							Confidence:      "medium",
							Severity:        "medium",
							Notes:           []string{fmt.Sprintf("status=%d", status)},
						}
						mu.Lock()
						out = append(out, pf)
						mu.Unlock()
					}
				}
				// header fuzzing
				if opts.EnableHeaderFuzz && len(headerFuzzers) > 0 {
					for hk, vals := range headerFuzzers {
						for _, hv := range vals {
							h := map[string]string{hk: hv}
							bH, stH, hHdrs, _ := simpleDo(opts, "GET", epurl.String(), nil, 512*1024, h)
							if stH >= 200 && bytes.Contains(bH, []byte(hv)) {
								mu.Lock()
								out = append(out, ParameterFinding{Name: hk, Locations: []ParamLocation{{Type: "header", URL: epurl.String(), Field: hk}}, ExampleValues: []string{hv}, Sensitive: false, PotentialIssues: []string{"header_reflection"}, Confidence: "medium", Severity: "informational", Evidence: []string{fmt.Sprintf("reflected in response headers: %v", hHdrs)}})
								mu.Unlock()
							}
						}
					}
				}

			}(u0, param, baseBody)
		}
	}
	wg.Wait()
	return dedupeFindings(out)
}

// -------------------- Top-level Run --------------------

func Run(target string, opts Options) (*Report, error) {
	rep := &Report{Target: target, ScannedAt: time.Now().UTC().Format(time.RFC3339)}
	if !opts.Enable {
		return rep, nil
	}
	base := target
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "https://" + strings.TrimSuffix(base, "/")
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return rep, err
	}

	if opts.ParamConcurrency <= 0 {
		opts.ParamConcurrency = 8
	}
	if opts.TimeoutSec <= 0 {
		opts.TimeoutSec = 10
	}

	client := buildClient(opts.TimeoutSec, opts.ExternalClient)
	opts.ExternalClient = client

	// fetch root HTML
	maxBody := int64(512 * 1024)
	if opts.MaxBodyRead > 0 {
		maxBody = opts.MaxBodyRead
	}
	body, status, headers, err := simpleDo(opts, "GET", baseURL.String(), nil, maxBody, nil)
	if err == nil && status >= 200 && status < 400 {
		htmlFinds := extractParamsFromHTML(body, baseURL)
		rep.Findings = append(rep.Findings, htmlFinds...)

		// extract headers
		headFinds := extractParamsFromHeaders(headers, baseURL.String())
		rep.Findings = append(rep.Findings, headFinds...)

		jsrefs := []string{}
		scriptRe := regexp.MustCompile(`(?i)<script[^>]+src=['"]([^'"]+)['"]`)
		for _, sm := range scriptRe.FindAllSubmatch(body, -1) {
			if len(sm) >= 2 {
				src := strings.TrimSpace(string(sm[1]))
				if u, err := url.Parse(src); err == nil {
					if u.Host == "" {
						if baseURL != nil {
							u = baseURL.ResolveReference(u)
						}
					}
					jsrefs = append(jsrefs, u.String())
				}
			}
		}

		jsFinds, endpoints := extractParamsFromJS(body, baseURL)
		rep.Findings = append(rep.Findings, jsFinds...)
		for _, e := range endpoints {
			jsrefs = append(jsrefs, e)
		}

		if opts.JS && len(jsrefs) > 0 {
			for _, j := range dedupeStrings(jsrefs) {
				jb, st, _, err := simpleDo(opts, "GET", j, nil, 1024*1024, nil)
				if err != nil || st < 200 || st >= 400 {
					continue
				}
				pf, eps := extractParamsFromJS(jb, baseURL)
				rep.Findings = append(rep.Findings, pf...)
				for _, ep := range eps {
					jsrefs = append(jsrefs, ep)
				}
				if sm := sourceMapRe.FindSubmatch(jb); len(sm) >= 2 {
					smurl := strings.TrimSpace(string(sm[1]))
					if u, err := url.Parse(smurl); err == nil {
						if u.Host == "" && baseURL != nil {
							smfull := baseURL.ResolveReference(u).String()
							// attempt pull - ignore returned content
							simpleDo(opts, "GET", smfull, nil, 1024*1024, nil)
						}
					}
				}
			}
		}
	}

	// OpenAPI
	oas := fetchOpenAPI(client, baseURL, opts)
	rep.Findings = append(rep.Findings, oas...)

	// GraphQL
	gql := detectGraphQL(client, baseURL, opts)
	rep.Findings = append(rep.Findings, gql...)

	rep.Findings = dedupeFindings(rep.Findings)

	// Prepare endpoints for fuzzing
	endpointsSet := map[string]struct{}{}
	for _, f := range rep.Findings {
		for _, loc := range f.Locations {
			if loc.URL != "" && (loc.Type == "query" || loc.Type == "form" || loc.Type == "graphql" || loc.Type == "path") {
				endpointsSet[loc.URL] = struct{}{}
			}
		}
	}
	endpointsSet[baseURL.String()] = struct{}{}
	endpoints := []string{}
	for e := range endpointsSet {
		endpoints = append(endpoints, e)
	}

	if !opts.DisableActive {
		wordlist, err := loadWordlist(opts.ParamWordlist)
		if err != nil {
			wordlist, _ = loadWordlist("")
		}
		fuzz := fuzzParams(opts, endpoints, wordlist, opts.ParamConcurrency)
		rep.Findings = append(rep.Findings, fuzz...)
	}

	rep.Findings = dedupeFindings(rep.Findings)
	return rep, nil
}
