// dir.go
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------- Types & Output Schema ----------

type ScanOptions struct {
	Target        string
	WordlistFile  string
	ExtraWords    []string
	Concurrency   int
	Timeout       time.Duration
	FollowSitemap bool
	FetchJS       bool
	OutputJSON    string
	OnlyHighValue bool
	UserAgent     string
	MaxProbes     int
}

type TLSInfo struct {
	Subject   string    `json:"subject,omitempty"`
	Issuer    string    `json:"issuer,omitempty"`
	ValidFrom time.Time `json:"valid_from,omitempty"`
	ValidTo   time.Time `json:"valid_to,omitempty"`
}

type Finding struct {
	URL                string            `json:"url"`
	Method             string            `json:"method"`
	Status             int               `json:"status"`
	ContentLength      int               `json:"content_length"`
	ContentType        string            `json:"content_type,omitempty"`
	BodySnippet        string            `json:"body_snippet,omitempty"`
	KeywordsFound      []string          `json:"keywords_found,omitempty"`
	Redirects          []string          `json:"redirect_chain,omitempty"`
	ResponseHeaders    map[string]string `json:"response_headers,omitempty"`
	TLS                *TLSInfo          `json:"tls_info,omitempty"`
	BaselineSimilarity float64           `json:"baseline_similarity,omitempty"`
	WordlistName       string            `json:"wordlist_name,omitempty"`
	Timestamp          string            `json:"probe_timestamp,omitempty"`
	Confidence         string            `json:"confidence,omitempty"`
	Severity           string            `json:"severity,omitempty"`
	EvidenceType       string            `json:"evidence_type,omitempty"`
	Category           string            `json:"category,omitempty"`
	Notes              []string          `json:"notes,omitempty"`
	Remediation        []string          `json:"remediation,omitempty"`
}

type Report struct {
	Target     string            `json:"target"`
	ScannedAt  string            `json:"scanned_at"`
	Baseline   *Finding          `json:"baseline_404,omitempty"`
	Robots     []string          `json:"robots_entries,omitempty"`
	Sitemap    []string          `json:"sitemap_entries,omitempty"`
	JSFiles    []string          `json:"js_files,omitempty"`
	Findings   []Finding         `json:"findings"`
	Stats      map[string]int    `json:"stats,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty"`
}

// ---------- Built-in wordlists (small, extend with -wordlist) ----------

var (
	defaultAdmin = []string{
		"admin", "administrator", "manage", "dashboard", "console", "cp", "adm",
		"login", "user/login", "user/login.php", "wp-admin", "wp-login.php",
	}
	defaultConfig = []string{
		".env", ".env.example", "config.php", "config.json", "settings.php", "application.properties",
		".htaccess", "web.config", "secrets.json", "credentials.json",
	}
	defaultBackups = []string{
		"backup.zip", "backup.tar.gz", "site.zip", "site.tar.gz", "db.sql", "db.sql.gz",
		"dump.sql", "dump.sql.gz", "backup.bak", "backup.gz",
	}
	defaultSource = []string{
		".git/", ".git/config", ".git/HEAD", ".git/index", ".svn/", ".hg/", "composer.lock",
	}
	defaultJSAndAPI = []string{
		"app.js", "main.js", "bundle.js", "vendor.js", "index.js", "service-worker.js",
		"api", "graphql", "graphql.php", "graphiql", "api/v1", "api/v2", "internal-api",
	}
	defaultMisc = []string{
		"robots.txt", "sitemap.xml", ".well-known/security.txt", "favicon.ico",
		"phpinfo.php", "server-status", "health", "metrics", "status", "ping",
	}
)

// ---------- Detection regexes & checklist mapping ----------

var detectionRegexes = map[string]*regexp.Regexp{
	"private_key":        regexp.MustCompile(`(?i)-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`),
	"aws_key_id":         regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"aws_access_key":     regexp.MustCompile(`(?i)(aws_access_key_id|aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*['"]?[^'"\s]+`),
	"db_password":        regexp.MustCompile(`(?i)(DB_PASSWORD|DB_PASS|database_password|password)\s*[:=]\s*['"]?[^'"\s]+`),
	"email":              regexp.MustCompile(`[\w.+-]+@[\w-]+\.[\w.-]+`),
	"index_of":           regexp.MustCompile(`(?i)Index of /`),
	"phpinfo":            regexp.MustCompile(`(?i)<title>phpinfo\(`),
	"json_object":        regexp.MustCompile(`(?s){\s*".+?"\s*:`),
	"source_map_comment": regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL\s*=\s*(.+)$`),
	"javascript_url":     regexp.MustCompile(`(?i)(https?:\/\/[^\s'"]+\.js|\/[^\s'"]+\.js)`),
	"credentials_file":   regexp.MustCompile(`(?i)(credential|credentials|secret|token|api_key|client_secret)`),
	"backup_pattern":     regexp.MustCompile(`(?i)(backup|dump|db|sql|tar|zip|gz|bak)`),
	"git_config":         regexp.MustCompile(`(?i)\[core\]`),
	"swagger":            regexp.MustCompile(`(?i)swagger|openapi`),
	"aws_meta":           regexp.MustCompile(`(?:169\.254\.169\.254|latest\/meta-data)`),
	"oauth_redirect":     regexp.MustCompile(`(?i)(redirect_uri|oauth|saml|acs|sso)`),
	"bearer_token":       regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*`),
	"jwt":                regexp.MustCompile(`eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*`),
}

var checklistCategories = map[string]string{
	"A": "Web pages & UI endpoints (admin, dashboards, login, vendor UIs)",
	"B": "API surfaces (REST, GraphQL, versioned endpoints)",
	"C": "Files that may leak secrets / data (.env, config, dumps)",
	"D": "Source control / build artifacts (.git, source maps, node_modules)",
	"E": "Directory listings & indexes (Index of /)",
	"F": "Logs, debug pages & diagnostic endpoints (phpinfo, server-status)",
	"G": "Uploaded files & user content (uploads, shells)",
	"H": "CI/CD artifacts & cloud endpoints (artifacts, metadata exposure)",
	"I": "Autodiscover, mail and identity endpoints (owa, autodiscover)",
	"J": "Hidden functionality & feature flags (feature toggles, beta)",
	"K": "Redirects & open-redirect endpoints",
	"L": "Localization / language resources (/locales, i18n)",
	"M": "Miscellaneous surprising things (.well-known, README, env.example)",
}

// ---------- Utility helpers used by Parameters population ----------

func newRunID() string {
	b := make([]byte, 6)
	_, err := rand.Read(b)
	if err != nil {
		return fmt.Sprintf("run-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%s-%s", time.Now().UTC().Format("20060102T150405Z"), hex.EncodeToString(b))
}

func putParam(m map[string]string, k, v string) {
	if m == nil {
		return
	}
	m[k] = v
}

func hashBytesSHA256Hex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func invokedBy() string {
	return strings.Join(os.Args, " ")
}

func safeTrim(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// ---------- PopulateDirParameters (integrates as requested) ----------

func PopulateDirParameters(report *Report, opts ScanOptions, baseline *Finding, seedsCount int, jsCandidates int, start, end time.Time, outputFormat, outputFile string) {
	if report.Parameters == nil {
		report.Parameters = map[string]string{}
	}
	// provenance
	putParam(report.Parameters, "tool_name", "ReconNio")
	putParam(report.Parameters, "tool_version", "unknown")
	putParam(report.Parameters, "git_commit", "unknown")
	putParam(report.Parameters, "build_time", "unknown")
	putParam(report.Parameters, "run_id", newRunID())
	putParam(report.Parameters, "invoked_by", safeTrim(invokedBy(), 4096))

	// target
	putParam(report.Parameters, "target_input_raw", safeTrim(opts.Target, 1024))
	putParam(report.Parameters, "target_normalized", safeTrim(opts.Target, 1024))
	putParam(report.Parameters, "is_ip", fmt.Sprintf("%v", false))

	// flags & toggles
	putParam(report.Parameters, "flag_dir", "true")
	putParam(report.Parameters, "flag_dir_fetch_js", fmt.Sprintf("%v", opts.FetchJS))
	putParam(report.Parameters, "flag_dir_follow_sitemap", fmt.Sprintf("%v", opts.FollowSitemap))
	putParam(report.Parameters, "flag_dir_wordlist", safeTrim(opts.WordlistFile, 512))
	putParam(report.Parameters, "flag_dir_concurrency", fmt.Sprintf("%d", opts.Concurrency))
	putParam(report.Parameters, "flag_dir_timeout_seconds", fmt.Sprintf("%d", int(opts.Timeout.Seconds())))
	putParam(report.Parameters, "flag_dir_ua", safeTrim(opts.UserAgent, 256))
	putParam(report.Parameters, "flag_dir_only_high_value", fmt.Sprintf("%v", opts.OnlyHighValue))
	putParam(report.Parameters, "flag_dir_max_probes_per_worker", fmt.Sprintf("%d", opts.MaxProbes))

	// timing
	putParam(report.Parameters, "start_time", start.UTC().Format(time.RFC3339Nano))
	putParam(report.Parameters, "end_time", end.UTC().Format(time.RFC3339Nano))
	putParam(report.Parameters, "duration_seconds", fmt.Sprintf("%.3f", end.Sub(start).Seconds()))

	// wordlist / seeds
	putParam(report.Parameters, "dir_wordlist_path", safeTrim(opts.WordlistFile, 1024))
	putParam(report.Parameters, "dir_wordlist_items", fmt.Sprintf("%d", report.Stats["wordlist_items"]))
	putParam(report.Parameters, "dir_seed_count", fmt.Sprintf("%d", seedsCount))
	putParam(report.Parameters, "dir_js_candidates", fmt.Sprintf("%d", jsCandidates))
	putParam(report.Parameters, "dir_sitemap_entries", fmt.Sprintf("%d", len(report.Sitemap)))
	putParam(report.Parameters, "dir_robots_entries", fmt.Sprintf("%d", len(report.Robots)))

	// baseline
	if baseline != nil {
		putParam(report.Parameters, "baseline_url", safeTrim(baseline.URL, 1024))
		putParam(report.Parameters, "baseline_status", fmt.Sprintf("%d", baseline.Status))
		putParam(report.Parameters, "baseline_size_bytes", fmt.Sprintf("%d", baseline.ContentLength))
		if baseline.BodySnippet != "" {
			putParam(report.Parameters, "baseline_hash", hashBytesSHA256Hex([]byte(baseline.BodySnippet)))
		}
	}

	// detections
	putParam(report.Parameters, "detection_signatures_version", "builtin-1")
	putParam(report.Parameters, "detection_rules_count", fmt.Sprintf("%d", len(detectionRegexes)))

	// environment
	hn, _ := os.Hostname()
	putParam(report.Parameters, "host_name", safeTrim(hn, 128))
	putParam(report.Parameters, "go_version", runtime.Version())
	putParam(report.Parameters, "os", runtime.GOOS)

	// output
	putParam(report.Parameters, "output_format", safeTrim(outputFormat, 64))
	putParam(report.Parameters, "output_file", safeTrim(outputFile, 1024))
	putParam(report.Parameters, "redact_sensitive", "false")

	// numeric metrics (ensure map exists)
	if report.Stats == nil {
		report.Stats = map[string]int{}
	}
	report.Stats["total_findings"] = len(report.Findings)

	// breakdown
	h, m, l, i := 0, 0, 0, 0
	for _, f := range report.Findings {
		switch f.Severity {
		case "critical", "high":
			h++
		case "medium":
			m++
		case "low":
			l++
		default:
			i++
		}
	}
	report.Stats["findings_high"] = h
	report.Stats["findings_medium"] = m
	report.Stats["findings_low"] = l
	report.Stats["findings_info"] = i

	putParam(report.Parameters, "summary", fmt.Sprintf("findings=%d (H=%d M=%d L=%d I=%d)", report.Stats["total_findings"], h, m, l, i))
}

// ---------- Helpers (existing) ----------

func dedupeStrings(s []string) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, x := range s {
		if x == "" {
			continue
		}
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	return out
}

func snippet(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}

func randomTokenHex(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// ---------- HTTP client utils ----------

func buildHTTPClient(timeout time.Duration, insecureTLS bool) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureTLS},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
}

func copyHeadersToMap(h http.Header) map[string]string {
	out := map[string]string{}
	for k, vals := range h {
		if len(vals) > 0 {
			out[k] = strings.Join(vals, "; ")
		}
	}
	return out
}

func fetchURL(client *http.Client, rawurl string, method string, maxBody int64, ua string) (body []byte, status int, headers map[string]string, redirects []string, tlsInfo *TLSInfo, err error) {
	req, err := http.NewRequest(method, rawurl, nil)
	if err != nil {
		return nil, 0, nil, nil, nil, err
	}
	if ua == "" {
		ua = "DirScan/1.0"
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	redirectChain := []string{}
	visited := make(map[string]struct{})
	clientCopy := *client
	clientCopy.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		u := req.URL.String()
		if _, ok := visited[u]; ok {
			return http.ErrUseLastResponse
		}
		redirectChain = append(redirectChain, u)
		visited[u] = struct{}{}
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	}
	resp, err := clientCopy.Do(req)
	if err != nil {
		return nil, 0, nil, redirectChain, nil, err
	}
	defer resp.Body.Close()
	status = resp.StatusCode
	headers = copyHeadersToMap(resp.Header)
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		c := resp.TLS.PeerCertificates[0]
		tlsInfo = &TLSInfo{Subject: c.Subject.CommonName, Issuer: c.Issuer.CommonName, ValidFrom: c.NotBefore, ValidTo: c.NotAfter}
	}
	if method == "HEAD" {
		return nil, status, headers, redirectChain, tlsInfo, nil
	}
	limited := io.LimitReader(resp.Body, maxBody)
	b, err := io.ReadAll(limited)
	if err != nil {
		return nil, status, headers, redirectChain, tlsInfo, err
	}
	return b, status, headers, redirectChain, tlsInfo, nil
}

// ---------- Baseline fingerprinting ----------

func computeBaseline(client *http.Client, target string, ua string) (*Finding, []byte, error) {
	base := target
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "https://" + strings.TrimSuffix(target, "/")
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, nil, err
	}
	token := randomTokenHex(16)
	u.Path = path.Join(u.Path, token)
	raw := u.String()
	body, status, headers, _, tlsInfo, err := fetchURL(client, raw, "GET", 128*1024, ua)
	if err != nil {
		_, status2, headers2, _, tls2, err2 := fetchURL(client, raw, "HEAD", 1, ua)
		if err2 != nil {
			return nil, nil, fmt.Errorf("baseline failed: %v / %v", err, err2)
		}
		f := &Finding{
			URL:             raw,
			Method:          "HEAD",
			Status:          status2,
			ContentLength:   0,
			ContentType:     headers2["Content-Type"],
			BodySnippet:     "",
			ResponseHeaders: headers2,
			TLS:             tls2,
			Timestamp:       time.Now().UTC().Format(time.RFC3339),
			Confidence:      "low",
			EvidenceType:    "baseline",
			Severity:        "info",
		}
		return f, nil, nil
	}
	f := &Finding{
		URL:             raw,
		Method:          "GET",
		Status:          status,
		ContentLength:   len(body),
		ContentType:     headers["Content-Type"],
		BodySnippet:     snippet(body, 400),
		ResponseHeaders: headers,
		TLS:             tlsInfo,
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		Confidence:      "low",
		EvidenceType:    "baseline",
		Severity:        "info",
	}
	return f, body, nil
}

// ---------- Wordlist loading & permutations ----------

func loadWordlist(pathFile string, extras []string) ([]string, error) {
	set := map[string]struct{}{}
	for _, w := range append(defaultAdmin, append(defaultConfig, append(defaultBackups, append(defaultSource, append(defaultJSAndAPI, defaultMisc...)...)...)...)...) {
		set[w] = struct{}{}
	}
	for _, e := range extras {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		set[e] = struct{}{}
	}
	if pathFile != "" {
		f, err := os.Open(pathFile)
		if err != nil {
			return nil, fmt.Errorf("open wordlist: %v", err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			set[line] = struct{}{}
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("read wordlist: %v", err)
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}

// ---------- JS extraction helpers (simple) ----------

var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src=['"]([^'"]+)['"]`)
var hrefRe = regexp.MustCompile(`(?i)<a[^>]+href=['"]([^'"]+)['"]`)
var sourceMapRe = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL\s*=\s*(.+)$`)
var jsURLRe = regexp.MustCompile(`(?i)(https?:\/\/[^\s'"]+\/[^\s'"]+|\/[a-z0-9\-_\/\.]+\.(js|map|json))`)

func extractScriptSrcsFromHTML(html []byte, base *url.URL) []string {
	out := []string{}
	matches := scriptSrcRe.FindAllSubmatch(html, -1)
	for _, m := range matches {
		if len(m) >= 2 {
			src := string(m[1])
			u, err := url.Parse(strings.TrimSpace(src))
			if err != nil {
				continue
			}
			out = append(out, base.ResolveReference(u).String())
		}
	}
	return dedupeStrings(out)
}

func extractLinksFromHTML(html []byte, base *url.URL) []string {
	out := []string{}
	matches := hrefRe.FindAllSubmatch(html, -1)
	for _, m := range matches {
		if len(m) >= 2 {
			h := string(m[1])
			u, err := url.Parse(strings.TrimSpace(h))
			if err != nil {
				continue
			}
			out = append(out, base.ResolveReference(u).String())
		}
	}
	return dedupeStrings(out)
}

func extractFromJS(jsb []byte, base *url.URL) []string {
	out := []string{}
	for _, sm := range sourceMapRe.FindAllSubmatch(jsb, -1) {
		if len(sm) >= 2 {
			smURL := strings.TrimSpace(string(sm[1]))
			u, err := url.Parse(smURL)
			if err == nil {
				out = append(out, base.ResolveReference(u).String())
			} else {
				out = append(out, smURL)
			}
		}
	}
	for _, m := range jsURLRe.FindAllSubmatch(jsb, -1) {
		if len(m) >= 1 {
			cand := string(m[0])
			if strings.HasPrefix(cand, "/") {
				out = append(out, base.ResolveReference(&url.URL{Path: cand}).String())
			} else {
				out = append(out, cand)
			}
		}
	}
	return dedupeStrings(out)
}

// ---------- Classification & scoring ----------

func mapEvidenceToCategory(evidence string, fullURL string, headers map[string]string, body string) string {
	l := strings.ToLower(fullURL)
	adminKeywords := []string{"admin", "dashboard", "manage", "console", "wp-login", "wp-admin", "login"}
	for _, k := range adminKeywords {
		if strings.Contains(l, k) {
			return "A"
		}
	}
	if strings.Contains(l, "/api") || strings.Contains(l, "graphql") || strings.Contains(l, "/v1") || strings.Contains(l, "/v2") {
		return "B"
	}
	if strings.HasSuffix(l, ".env") || strings.Contains(l, "config") || strings.Contains(l, ".credentials") || detectionRegexes["aws_access_key"].MatchString(body) {
		return "C"
	}
	if strings.Contains(l, ".git") || strings.Contains(l, "/node_modules") || strings.HasSuffix(l, ".map") {
		return "D"
	}
	if detectionRegexes["index_of"].MatchString(body) || (strings.Contains(strings.ToLower(headers["Content-Type"]), "text/plain") && strings.Contains(l, "/uploads")) {
		return "E"
	}
	if detectionRegexes["phpinfo"].MatchString(body) || strings.Contains(l, "phpinfo") || strings.Contains(l, "server-status") {
		return "F"
	}
	if strings.Contains(l, "/upload") || strings.Contains(l, "/uploads") || strings.HasPrefix(path.Base(l), "shell") {
		return "G"
	}
	if strings.Contains(l, "/artifacts") || detectionRegexes["aws_meta"].MatchString(body) {
		return "H"
	}
	if strings.Contains(l, "autodiscover") || strings.Contains(l, "owa") || strings.Contains(l, "exchange") || strings.Contains(l, "mail") {
		return "I"
	}
	if strings.Contains(l, "/flags") || strings.Contains(l, "/feature") || strings.Contains(l, "beta") {
		return "J"
	}
	if strings.Contains(l, "redirect") || strings.Contains(l, "next=") || strings.Contains(l, "url=") {
		return "K"
	}
	if strings.Contains(l, "/locales") || strings.Contains(l, "/i18n") || strings.HasSuffix(l, ".po") || strings.HasSuffix(l, ".po.json") {
		return "L"
	}
	if strings.Contains(l, ".well-known") || strings.HasSuffix(l, "robots.txt") || strings.HasSuffix(l, "sitemap.xml") {
		return "M"
	}
	return "M"
}

func sizeSimilarity(a []byte, b []byte) float64 {
	la := len(a)
	lb := len(b)
	if la == 0 && lb == 0 {
		return 1.0
	}
	maxlen := la
	if lb > maxlen {
		maxlen = lb
	}
	if maxlen == 0 {
		return 1.0
	}
	diff := la - lb
	if diff < 0 {
		diff = -diff
	}
	r := 1.0 - (float64(diff) / float64(maxlen))
	if r < 0 {
		r = 0
	}
	return r
}

func computeConfidenceAndSeverity(status int, contentType string, keywords []string, sizeSim float64) (string, string) {
	score := 0.0
	if status == 200 {
		score += 30
	} else if status == 401 || status == 403 {
		score += 20
	} else if status >= 300 && status < 400 {
		score += 10
	}
	lct := strings.ToLower(contentType)
	if strings.Contains(lct, "application/zip") || strings.Contains(lct, "application/x-gzip") || strings.Contains(lct, "application/sql") {
		score += 30
	}
	if strings.Contains(lct, "application/json") {
		score += 10
	}
	score += float64(len(keywords)) * 20.0
	if sizeSim < 0.6 {
		score += 10
	}
	if score >= 70 {
		return "high", "high"
	}
	if score >= 35 {
		return "medium", "medium"
	}
	if score >= 15 {
		return "low", "low"
	}
	return "low", "info"
}

func remediationForType(evidence string, category string) []string {
	out := []string{}
	switch evidence {
	case "backup", "backup_pattern":
		out = append(out, "Remove backup files from webroot; store backups in a secure location with restricted access; rotate credentials if exposed.")
	case "git_config", ".git", "git":
		out = append(out, "Restrict access to .git/.svn; if repository exposed, remove it from webroot; consider using git-dumper recovery to assess leak impact; rotate secrets found.")
	case "phpinfo":
		out = append(out, "Disable phpinfo in production; restrict access to debug endpoints; review server configuration.")
	case "index_of":
		out = append(out, "Disable directory listing in web server configuration; restrict directory access.")
	default:
		switch category {
		case "A":
			out = append(out, "Restrict admin interfaces by IP allowlists or VPN; enforce strong auth, MFA and rate-limiting.")
		case "B":
			out = append(out, "Harden APIs: require auth, implement rate-limiting and input validation; remove or restrict test endpoints.")
		case "C":
			out = append(out, "Move configuration and secrets out of webroot; use secret management; rotate exposed keys.")
		case "D":
			out = append(out, "Do not keep VCS metadata in webroot; remove and redeploy from clean artifacts.")
		case "E":
			out = append(out, "Disable directory listing; restrict access to uploads; sanitize filenames.")
		case "H":
			out = append(out, "Restrict artifact storage; avoid exposing cloud metadata via reverse proxies; secure CI/CD logs.")
		case "I":
			out = append(out, "Protect mail/autodiscover endpoints; ensure they require proper auth and rate-limiting.")
		default:
			out = append(out, "Review and remediate according to finding type: restrict access, remove sensitive files, rotate keys, and implement proper controls.")
		}
	}
	return out
}

// ---------- Probe worker ----------

type probeTask struct {
	FullURL     string
	WordlistKey string
}

func probeWorker(client *http.Client, ua string, maxBody int64, baselineBody []byte, tasks <-chan probeTask, out chan<- Finding, wg *sync.WaitGroup, maxProbesPerWorker int) {
	defer wg.Done()
	probes := 0
	for t := range tasks {
		if maxProbesPerWorker > 0 && probes >= maxProbesPerWorker {
			break
		}
		probes++
		_, status, headers, redirects, tlsInfo, err := fetchURL(client, t.FullURL, "HEAD", 1, ua)
		var body []byte
		if err != nil {
			body, status, headers, redirects, tlsInfo, err = fetchURL(client, t.FullURL, "GET", maxBody, ua)
			if err != nil {
				continue
			}
		} else {
			if status == 200 || status == 401 || status == 403 || (status >= 300 && status < 400) {
				body, status, headers, redirects, tlsInfo, _ = fetchURL(client, t.FullURL, "GET", maxBody, ua)
			}
		}
		ct := headers["Content-Type"]
		bodyStr := string(body)
		foundKeys := []string{}
		for name, rx := range detectionRegexes {
			if rx.MatchString(bodyStr) {
				foundKeys = append(foundKeys, name)
			}
		}
		eType, kws, _ := classifyPathAndHeuristics(t.FullURL, bodyStr, status, ct)
		foundKeys = append(foundKeys, kws...)
		sizeSim := 1.0
		if baselineBody != nil && len(baselineBody) > 0 && len(body) > 0 {
			sizeSim = sizeSimilarity(baselineBody, body)
		}
		confidence, severity := computeConfidenceAndSeverity(status, ct, foundKeys, sizeSim)
		category := mapEvidenceToCategory(eType, t.FullURL, headers, bodyStr)

		f := Finding{
			URL:                t.FullURL,
			Method:             "GET",
			Status:             status,
			ContentLength:      len(body),
			ContentType:        ct,
			BodySnippet:        snippet(body, 800),
			KeywordsFound:      dedupeStrings(foundKeys),
			Redirects:          redirects,
			ResponseHeaders:    headers,
			BaselineSimilarity: sizeSim,
			WordlistName:       t.WordlistKey,
			Timestamp:          time.Now().UTC().Format(time.RFC3339),
			Confidence:         confidence,
			Severity:           severity,
			EvidenceType:       eType,
			Category:           category,
		}
		if tlsInfo != nil {
			f.TLS = tlsInfo
		}
		f.Remediation = remediationForType(eType, category)
		if status == 200 && sizeSim > 0.98 {
			f.Notes = append(f.Notes, "Response highly similar to baseline 404; potential wildcard 200. Treat as low-confidence unless keywords present.")
			if f.Confidence != "high" {
				f.Confidence = "low"
				f.Severity = "info"
			}
		}
		if status == 404 {
			continue
		}
		if status == 200 && sizeSim > 0.995 && len(foundKeys) == 0 {
			continue
		}
		out <- f
	}
}

func classifyPathAndHeuristics(fullURL string, body string, status int, contentType string) (string, []string, []string) {
	lower := strings.ToLower(fullURL)
	found := []string{}
	evidence := ""
	notes := []string{}
	if strings.Contains(lower, ".git") {
		evidence = "git"
		found = append(found, ".git")
		notes = append(notes, "possible .git exposure")
	}
	if strings.HasSuffix(lower, ".env") || strings.Contains(lower, "/config") || strings.Contains(lower, "credentials") {
		if evidence == "" {
			evidence = "config"
		}
		found = append(found, "config")
	}
	if strings.Contains(lower, "backup") || strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".sql") || strings.HasSuffix(lower, ".gz") {
		if evidence == "" {
			evidence = "backup"
		}
		found = append(found, "backup")
	}
	if strings.Contains(lower, "admin") || strings.Contains(lower, "dashboard") {
		if evidence == "" {
			evidence = "admin"
		}
		found = append(found, "admin")
	}
	if strings.Contains(lower, "api") || strings.Contains(lower, "graphql") || strings.HasSuffix(lower, ".json") {
		if evidence == "" {
			evidence = "api"
		}
		found = append(found, "api")
	}
	for name, rx := range detectionRegexes {
		if rx.MatchString(body) {
			found = append(found, name)
			if evidence == "" {
				evidence = name
			}
		}
	}
	if evidence == "" {
		if strings.Contains(contentType, "application/zip") || strings.Contains(contentType, "application/octet-stream") {
			evidence = "backup"
			found = append(found, "binary")
		} else {
			evidence = "other"
		}
	}
	return evidence, dedupeStrings(found), notes
}

// ---------- robots.txt & sitemap parsing ----------

func parseRobots(client *http.Client, baseURL *url.URL, ua string) ([]string, []string) {
	u := *baseURL
	u.Path = path.Join(u.Path, "/robots.txt")
	body, status, _, _, _, err := fetchURL(client, u.String(), "GET", 512*1024, ua)
	if err != nil || status >= 400 {
		return nil, nil
	}
	lines := strings.Split(string(body), "\n")
	entries := []string{}
	sitemaps := []string{}
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		parts := strings.SplitN(l, ":", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(parts[0]))
		v := strings.TrimSpace(parts[1])
		if k == "disallow" || k == "allow" {
			entries = append(entries, fmt.Sprintf("%s: %s", k, v))
		}
		if k == "sitemap" {
			sitemaps = append(sitemaps, v)
		}
	}
	return dedupeStrings(entries), dedupeStrings(sitemaps)
}

func parseSitemap(client *http.Client, raw string, ua string) []string {
	body, status, _, _, _, err := fetchURL(client, raw, "GET", 2*1024*1024, ua)
	if err != nil || status >= 400 {
		return nil
	}
	locRe := regexp.MustCompile(`(?i)<loc>\s*([^<]+)\s*</loc>`)
	out := []string{}
	for _, m := range locRe.FindAllSubmatch(body, -1) {
		if len(m) >= 2 {
			out = append(out, strings.TrimSpace(string(m[1])))
		}
	}
	return dedupeStrings(out)
}

// ---------- Orchestrator ----------

func scanTargetWithOptions(opts ScanOptions) (*Report, error) {
	if opts.Target == "" {
		return nil, fmt.Errorf("target is required")
	}
	start := time.Now() // capture start early for parameters/duration

	ua := opts.UserAgent
	if ua == "" {
		ua = "ReconNio-Dir/1.0"
	}
	client := buildHTTPClient(opts.Timeout, true)

	report := &Report{
		Target:     opts.Target,
		ScannedAt:  time.Now().UTC().Format(time.RFC3339),
		Findings:   []Finding{},
		Stats:      map[string]int{},
		Parameters: map[string]string{},
	}
	report.Parameters["concurrency"] = fmt.Sprintf("%d", opts.Concurrency)
	report.Parameters["timeout_seconds"] = fmt.Sprintf("%d", int(opts.Timeout.Seconds()))
	report.Parameters["follow_sitemap"] = fmt.Sprintf("%v", opts.FollowSitemap)
	report.Parameters["fetch_js"] = fmt.Sprintf("%v", opts.FetchJS)

	fmt.Printf("[*] Computing baseline 404 for %s\n", opts.Target)
	baseline, baselineBody, err := computeBaseline(client, opts.Target, ua)
	if err != nil {
		return nil, fmt.Errorf("baseline failed: %v", err)
	}
	report.Baseline = baseline

	words, err := loadWordlist(opts.WordlistFile, opts.ExtraWords)
	if err != nil {
		return nil, err
	}
	report.Stats["wordlist_items"] = len(words)
	fmt.Printf("[*] Loaded %d wordlist items (incl. built-ins)\n", len(words))

	rawBase := opts.Target
	if !strings.HasPrefix(rawBase, "http://") && !strings.HasPrefix(rawBase, "https://") {
		rawBase = "https://" + strings.TrimSuffix(rawBase, "/")
	}
	baseURL, err := url.Parse(rawBase)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %v", err)
	}

	// parse robots & sitemap (seed augmentation)
	fmt.Printf("[*] Parsing robots.txt and sitemap for %s\n", baseURL.String())
	robotsEntries, sitemapRefs := parseRobots(client, baseURL, ua)
	report.Robots = robotsEntries
	report.Sitemap = []string{}
	if len(sitemapRefs) > 0 {
		for _, s := range sitemapRefs {
			if !strings.HasPrefix(s, "http") {
				if u, err := url.Parse(s); err == nil {
					s = baseURL.ResolveReference(u).String()
				}
			}
			report.Sitemap = append(report.Sitemap, s)
			if opts.FollowSitemap {
				ents := parseSitemap(client, s, ua)
				for _, e := range ents {
					report.Sitemap = append(report.Sitemap, e)
				}
			}
		}
	}
	report.Sitemap = dedupeStrings(report.Sitemap)

	// build seeds from base + wordlist + sitemap
	seeds := []string{baseURL.String()}
	for _, w := range words {
		u := *baseURL
		u.Path = path.Join(u.Path, w)
		seeds = append(seeds, u.String())
		if !strings.Contains(w, ".") {
			for _, ext := range []string{".php", ".html", ".bak", ".zip", ".tar.gz", ".sql", ".env"} {
				v := *baseURL
				v.Path = path.Join(v.Path, w+ext)
				seeds = append(seeds, v.String())
			}
		}
	}
	if opts.FollowSitemap {
		for _, s := range report.Sitemap {
			seeds = append(seeds, s)
		}
	}
	seeds = dedupeStrings(seeds)

	// JS extraction (if requested)
	jsCandidates := []string{}
	if opts.FetchJS {
		fmt.Printf("[*] Fetching root HTML for JS / link extraction: %s\n", baseURL.String())
		body, status, _, _, _, err := fetchURL(client, baseURL.String(), "GET", 512*1024, ua)
		if err == nil && status >= 200 && status < 400 {
			scripts := extractScriptSrcsFromHTML(body, baseURL)
			report.JSFiles = append(report.JSFiles, scripts...)
			links := extractLinksFromHTML(body, baseURL)
			for _, ln := range links {
				u, err := url.Parse(ln)
				if err == nil {
					if u.Host == baseURL.Host {
						seeds = append(seeds, ln)
					}
				}
			}
			for _, sc := range scripts {
				jsb, st, _, _, _, err2 := fetchURL(client, sc, "GET", 512*1024, ua)
				if err2 == nil && st >= 200 && st < 400 {
					cands := extractFromJS(jsb, baseURL)
					for _, c := range cands {
						jsCandidates = append(jsCandidates, c)
					}
				}
			}
		}
	}
	for _, jc := range dedupeStrings(jsCandidates) {
		seeds = append(seeds, jc)
	}
	seeds = dedupeStrings(seeds)

	report.Stats["seed_count"] = len(seeds)
	fmt.Printf("[*] Probing %d candidate URLs (concurrency=%d)\n", len(seeds), opts.Concurrency)

	// worker pool
	tasks := make(chan probeTask, len(seeds)+1024)
	results := make(chan Finding, 8192)
	wg := &sync.WaitGroup{}
	workers := opts.Concurrency
	if workers <= 0 {
		workers = 20
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go probeWorker(client, ua, 512*1024, baselineBody, tasks, results, wg, opts.MaxProbes)
	}
	for _, s := range seeds {
		tasks <- probeTask{FullURL: s, WordlistKey: "generated"}
	}
	close(tasks)
	go func() {
		wg.Wait()
		close(results)
	}()

	// collect findings
	findings := []Finding{}
	for f := range results {
		findings = append(findings, f)
		report.Stats["total_findings"] = len(findings)
		switch f.Severity {
		case "critical", "high":
			report.Stats["high_severity"]++
		case "medium":
			report.Stats["medium_severity"]++
		case "low":
			report.Stats["low_severity"]++
		default:
			report.Stats["info"]++
		}
	}

	// sort
	sort.Slice(findings, func(i, j int) bool {
		rank := map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
		ri := rank[findings[i].Severity]
		rj := rank[findings[j].Severity]
		if ri != rj {
			return ri > rj
		}
		cRank := map[string]int{"high": 3, "medium": 2, "low": 1}
		ci := cRank[findings[i].Confidence]
		cj := cRank[findings[j].Confidence]
		if ci != cj {
			return ci > cj
		}
		return findings[i].Status > findings[j].Status
	})

	if opts.OnlyHighValue {
		filtered := []Finding{}
		for _, f := range findings {
			if f.Severity == "high" || f.Severity == "critical" {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	report.Findings = findings

	// populate parameters now that seeds, jsCandidates and findings exist
	end := time.Now()
	PopulateDirParameters(report, opts, baseline, len(seeds), len(jsCandidates), start, end, "normal", opts.OutputJSON)

	return report, nil
}

// ---------- Pretty printing + JSON export ----------

func printPrettyReport(r *Report) {
	fmt.Printf("\nDirectory / Content Discovery — Report for %s\nScanned at: %s\n\n", r.Target, r.ScannedAt)
	fmt.Println("Baseline 404 fingerprint:")
	if r.Baseline != nil {
		fmt.Printf(" - URL: %s\n - Status: %d\n - Size: %d bytes\n - Snippet:\n%s\n\n", r.Baseline.URL, r.Baseline.Status, r.Baseline.ContentLength, r.Baseline.BodySnippet)
	}
	if len(r.Robots) > 0 {
		fmt.Println("robots.txt (parsed):")
		for _, e := range r.Robots {
			fmt.Printf(" - %s\n", e)
		}
		fmt.Println()
	}
	if len(r.Sitemap) > 0 {
		fmt.Printf("Sitemap entries: %d (showing up to 10)\n", len(r.Sitemap))
		for i, s := range r.Sitemap {
			if i >= 10 {
				fmt.Printf(" ... (+%d more)\n\n", len(r.Sitemap)-10)
				break
			}
			fmt.Printf(" - %s\n", s)
		}
	}
	if len(r.JSFiles) > 0 {
		fmt.Printf("JS files discovered (%d):\n", len(r.JSFiles))
		for _, j := range r.JSFiles {
			fmt.Printf(" - %s\n", j)
		}
		fmt.Println()
	}
	fmt.Printf("Findings: %d\n", len(r.Findings))
	for i, f := range r.Findings {
		fmt.Println("────────────────────────────────────────")
		fmt.Printf("[%d] URL: %s\n", i+1, f.URL)
		fmt.Printf("     Status: %d   Confidence: %s   Severity: %s   Category: %s (%s)\n",
			f.Status, f.Confidence, f.Severity, f.Category, checklistCategories[f.Category])
		if f.ContentType != "" {
			fmt.Printf("     Content-Type: %s   Size: %d\n", f.ContentType, f.ContentLength)
		}
		if len(f.KeywordsFound) > 0 {
			fmt.Printf("     Keywords/Detections: %s\n", strings.Join(f.KeywordsFound, ", "))
		}
		if len(f.Redirects) > 0 {
			fmt.Printf("     Redirect chain: %s\n", strings.Join(f.Redirects, " -> "))
		}
		if len(f.ResponseHeaders) > 0 {
			hints := []string{"Server", "Location", "WWW-Authenticate", "Set-Cookie", "Content-Security-Policy"}
			for _, h := range hints {
				if v, ok := f.ResponseHeaders[h]; ok {
					fmt.Printf("     Header: %s: %s\n", h, v)
				}
			}
		}
		if f.TLS != nil {
			fmt.Printf("     TLS: subject=%s issuer=%s valid_to=%s\n", f.TLS.Subject, f.TLS.Issuer, f.TLS.ValidTo.Format(time.RFC3339))
		}
		if len(f.Notes) > 0 {
			for _, n := range f.Notes {
				fmt.Printf("     Note: %s\n", n)
			}
		}
		if len(f.Remediation) > 0 {
			fmt.Printf("     Remediation (suggested):\n")
			for _, r := range f.Remediation {
				fmt.Printf("       - %s\n", r)
			}
		}
		if len(f.BodySnippet) > 0 {
			fmt.Printf("     Snippet:\n%s\n", f.BodySnippet)
		}
	}
	fmt.Println("\nSummary stats:")
	for k, v := range r.Stats {
		fmt.Printf(" - %s: %d\n", k, v)
	}
	// print parameters summary (organized)
	if r.Parameters != nil {
		fmt.Println("\nParameters snapshot:")
		// print key sorted
		keys := make([]string, 0, len(r.Parameters))
		for k := range r.Parameters {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf(" - %s: %s\n", k, r.Parameters[k])
		}
	}
	fmt.Println()
}

// ---------- CLI main ----------

func main() {
	var opts ScanOptions
	var timeoutSecs int
	var concurrency int
	var followSitemap bool
	var fetchJS bool
	var onlyHigh bool
	var outFile string
	var ua string
	var wordlist string
	var maxProbes int

	flag.StringVar(&opts.Target, "target", "", "Target domain or URL (e.g., https://example.com or example.com)")
	flag.StringVar(&wordlist, "wordlist", "", "Path to custom wordlist (one path per line). Built-in lists included if omitted.")
	flag.IntVar(&concurrency, "concurrency", 30, "Concurrency for HTTP probes")
	flag.IntVar(&timeoutSecs, "timeout", 8, "HTTP client timeout (seconds)")
	flag.BoolVar(&followSitemap, "follow-sitemap", false, "Parse sitemap.xml and include its URLs")
	// default false to make JS extraction opt-in
	flag.BoolVar(&fetchJS, "fetch-js", false, "Fetch root HTML and JS files to extract endpoints (default false)")
	flag.StringVar(&outFile, "out", "", "Write JSON report to file (optional)")
	flag.BoolVar(&onlyHigh, "only-high", false, "Only include high-severity findings in report")
	flag.StringVar(&ua, "ua", "ReconNio-Dir/1.0", "User-Agent string to use for probes")
	flag.IntVar(&maxProbes, "max-probes-per-worker", 0, "Optional per-worker probe limit (0 = unlimited)")

	flag.Parse()

	if opts.Target == "" {
		fmt.Println("target required. Use -target example.com")
		flag.Usage()
		os.Exit(1)
	}

	opts.WordlistFile = wordlist
	opts.Concurrency = concurrency
	opts.Timeout = time.Duration(timeoutSecs) * time.Second
	opts.FollowSitemap = followSitemap
	opts.FetchJS = fetchJS
	opts.OutputJSON = outFile
	opts.OnlyHighValue = onlyHigh
	opts.UserAgent = ua
	opts.MaxProbes = maxProbes
	opts.ExtraWords = []string{}

	fmt.Printf("[*] Starting Directory Discovery for %s\n", opts.Target)
	report, err := scanTargetWithOptions(opts)
	if err != nil {
		log.Fatalf("Scan error: %v\n", err)
	}

	printPrettyReport(report)

	if outFile != "" {
		f, err := os.Create(outFile)
		if err != nil {
			log.Fatalf("Failed to create output file: %v\n", err)
		}
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			log.Fatalf("Failed to encode JSON: %v\n", err)
		}
		fmt.Printf("[+] JSON report written to %s\n", outFile)
		f.Close()
	}
}
