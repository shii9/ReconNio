// main.go
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	stdnet "net"
	stdhttp "net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"

	// internal modules (keep all your existing internals)
	js "github.com/shii9/ReconNio/internal/JS"
	perameter "github.com/shii9/ReconNio/internal/Perameter"
	urlcollector "github.com/shii9/ReconNio/internal/Urls"
	dns "github.com/shii9/ReconNio/internal/dns"
	"github.com/shii9/ReconNio/internal/geolocation"
	reconhttp "github.com/shii9/ReconNio/internal/http"
	"github.com/shii9/ReconNio/internal/mail"
	"github.com/shii9/ReconNio/internal/metadata"
	"github.com/shii9/ReconNio/internal/ports"
	"github.com/shii9/ReconNio/internal/proxy"
	"github.com/shii9/ReconNio/internal/reverseip"
	"github.com/shii9/ReconNio/internal/social"
	"github.com/shii9/ReconNio/internal/whois"

	// fuzzing internal module
	"github.com/shii9/ReconNio/internal/fuzzing"

	// endpoint discovery module (new)
	ep "github.com/shii9/ReconNio/internal/endpoint"
)

// ---------- Config ----------
const (
	defaultConcurrency = 4
	maxIPTargets       = 3
)

// ---------- Global flags ----------
var outputFormat string
var outputFile string

// ---------- Rate limiter ----------
type RequestLimiter struct {
	tokens chan struct{}
	quit   chan struct{}
}

func NewRequestLimiter(reqPerSec int) *RequestLimiter {
	if reqPerSec <= 0 {
		return nil
	}
	rl := &RequestLimiter{
		tokens: make(chan struct{}, reqPerSec),
		quit:   make(chan struct{}),
	}
	for i := 0; i < reqPerSec; i++ {
		rl.tokens <- struct{}{}
	}
	go func() {
		t := time.NewTicker(time.Second / time.Duration(reqPerSec))
		defer t.Stop()
		for {
			select {
			case <-t.C:
				select {
				case rl.tokens <- struct{}{}:
				default:
				}
			case <-rl.quit:
				return
			}
		}
	}()
	return rl
}

func (r *RequestLimiter) Allow() {
	if r == nil {
		return
	}
	<-r.tokens
}

func (r *RequestLimiter) Stop() {
	if r == nil {
		return
	}
	close(r.quit)
}

// ---------- HTTP nested types for results ----------
type HTTPRequestInfo struct {
	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type HTTPResponseInfo struct {
	StatusCode      int                    `json:"status_code,omitempty"`
	Headers         map[string][]string    `json:"headers,omitempty"`
	Title           string                 `json:"title,omitempty"`
	Server          string                 `json:"server,omitempty"`
	XPoweredBy      string                 `json:"x_powered_by,omitempty"`
	SecurityHeaders map[string]string      `json:"security_headers,omitempty"`
	ResponseTimeMS  int64                  `json:"response_time_ms,omitempty"`
	Redirects       []string               `json:"redirects,omitempty"`
	TLS             *reconhttp.SSLInfo     `json:"tls,omitempty"`
	AllowedMethods  []string               `json:"allowed_methods,omitempty"`
	Cookies         []reconhttp.HTTPCookie `json:"cookies,omitempty"`
	MetaTags        map[string]string      `json:"meta_tags,omitempty"`
	JsFiles         []string               `json:"js_files,omitempty"`
	Comments        []string               `json:"comments,omitempty"`
	FaviconSHA1     string                 `json:"favicon_sha1,omitempty"`
	PageSize        int64                  `json:"page_size,omitempty"`
	Compressed      bool                   `json:"compressed,omitempty"`
	DirectoryHits   []string               `json:"directory_hits,omitempty"`
	OpenRedirects   []string               `json:"open_redirects,omitempty"`
	CORS            string                 `json:"cors,omitempty"`
	TechCMS         []string               `json:"tech_cms,omitempty"`
	TechFramework   []string               `json:"tech_framework,omitempty"`
	WAFs            []string               `json:"wafs,omitempty"`
	HTTP2           bool                   `json:"http2,omitempty"`
	HTTP3Hint       bool                   `json:"http3_hint,omitempty"`
	Protocols       []string               `json:"protocols,omitempty"`
}

// ----------------- Port-related helpers & custom scanner -----------------

type PortResult struct {
	Port       int    `json:"port"`
	Open       bool   `json:"-"`
	Service    string `json:"service,omitempty"`
	Banner     string `json:"banner,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	TLSVersion string `json:"tls_version,omitempty"`
	TLSCipher  string `json:"tls_cipher,omitempty"`
}

// JSReport (local simplified) holds results of JS reconnaissance
type JSReport struct {
	PageURL            string   `json:"page_url,omitempty"`
	Scripts            []string `json:"scripts,omitempty"`
	InlineScriptsCount int      `json:"inline_scripts_count,omitempty"`
	InlineSnippets     []string `json:"inline_snippets,omitempty"`
	SourceMaps         []string `json:"sourcemaps,omitempty"`
	Secrets            []string `json:"secrets,omitempty"`
	APIs               []string `json:"api_endpoints,omitempty"`
	GraphQLEndpoints   []string `json:"graphql_endpoints,omitempty"`
	WebSockets         []string `json:"websocket_endpoints,omitempty"`
	Trackers           []string `json:"trackers,omitempty"`
	Frameworks         []string `json:"frameworks,omitempty"`
	DangerousPatterns  []string `json:"dangerous_patterns,omitempty"`
	ObfuscationSigns   []string `json:"obfuscation_signs,omitempty"`
	StorageUsage       []string `json:"storage_usage,omitempty"`
	CryptoUsage        []string `json:"crypto_usage,omitempty"`
	RegexPatterns      []string `json:"regex_patterns,omitempty"`
	Dependencies       []string `json:"dependencies,omitempty"`
	ErrorsAndLogs      []string `json:"errors_and_logs,omitempty"`
	OSINT              []string `json:"osint,omitempty"`
	CommentsTodos      []string `json:"comments_todos,omitempty"`
	Notes              []string `json:"notes,omitempty"`
}

// ---------- Directory scan types ----------
type DirTLSInfo struct {
	Subject   string    `json:"subject,omitempty"`
	Issuer    string    `json:"issuer,omitempty"`
	ValidFrom time.Time `json:"valid_from,omitempty"`
	ValidTo   time.Time `json:"valid_to,omitempty"`
}

type DirFinding struct {
	URL                string            `json:"url"`
	Method             string            `json:"method"`
	Status             int               `json:"status"`
	ContentLength      int               `json:"content_length"`
	ContentType        string            `json:"content_type,omitempty"`
	BodySnippet        string            `json:"body_snippet,omitempty"`
	KeywordsFound      []string          `json:"keywords_found,omitempty"`
	Redirects          []string          `json:"redirect_chain,omitempty"`
	ResponseHeaders    map[string]string `json:"response_headers,omitempty"`
	TLS                *DirTLSInfo       `json:"tls_info,omitempty"`
	BaselineSimilarity float64           `json:"baseline_similarity,omitempty"`
	WordlistName       string            `json:"wordlist_name,omitempty"`
	Timestamp          string            `json:"probe_timestamp,omitempty"`
	Confidence         string            `json:"confidence,omitempty"`
	EvidenceType       string            `json:"evidence_type,omitempty"`
	Notes              []string          `json:"notes,omitempty"`
}

type DirectoryReport struct {
	Target    string         `json:"target"`
	Baseline  *DirFinding    `json:"baseline_404,omitempty"`
	Robots    []string       `json:"robots,omitempty"`
	Sitemap   []string       `json:"sitemap,omitempty"`
	JSFiles   []string       `json:"js_files,omitempty"`
	Findings  []DirFinding   `json:"findings,omitempty"`
	Stats     map[string]int `json:"stats,omitempty"`
	ScannedAt string         `json:"scanned_at,omitempty"`
}

// ---------- Results structure ----------
type ScanResults struct {
	Target     string   `json:"target"`
	Subdomains []string `json:"subdomains,omitempty"`
	Whois      string   `json:"whois,omitempty"`

	Headers map[string][]string `json:"headers,omitempty"`

	HTTPRequest  *HTTPRequestInfo  `json:"http_request,omitempty"`
	HTTPResponse *HTTPResponseInfo `json:"http_response,omitempty"`

	DNSRecords      map[string][]string      `json:"dns_records,omitempty"`
	OpenPorts       []int                    `json:"open_ports,omitempty"`
	PortDetails     []PortResult             `json:"ports,omitempty"`
	ReverseIP       []string                 `json:"reverse_ips,omitempty"`
	Proxies         []string                 `json:"proxies,omitempty"`
	URLs            []string                 `json:"urls,omitempty"`
	SocialProfiles  []social.SocialProfile   `json:"social_profiles,omitempty"`
	Metadata        *metadata.MetadataResult `json:"metadata,omitempty"`
	Mail            *mail.MailResult         `json:"mail,omitempty"`
	Geo             *geolocation.GeoResponse `json:"geolocation,omitempty"`
	JS              *JSReport                `json:"js_report,omitempty"`
	Directory       *DirectoryReport         `json:"directory,omitempty"`
	ParameterReport *perameter.Report        `json:"parameter_report,omitempty"`
	Endpoints       []ep.Endpoint            `json:"endpoints,omitempty"`
	Timestamp       string                   `json:"timestamp"`
}

// ---------- Output helpers ----------
func WriteToFile(results ScanResults, format, filePath string) error {
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	if strings.EqualFold(format, "json") {
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}

	_, err = f.WriteString(fmt.Sprintf("ReconNio Scan Results for %s\nGenerated: %s\n\n%+v\n",
		results.Target, results.Timestamp, results))
	return err
}

// PrintToConsole prints results only for sections requested by flags.
// JS section prints everything (no truncation). Mail section added here.
func PrintToConsole(results ScanResults, flags ScanFlags) {
	fmt.Printf("\nReconNio - Report for %s\nGenerated: %s\n\n", results.Target, results.Timestamp)

	// HTTPHeader / Web
	if flags.httpHeaders {
		fmt.Println("┌─ HTTPHeader / Web")
		fmt.Println("│  ┌─ Request")
		if results.HTTPRequest == nil {
			fmt.Println("│  │  Not collected")
		} else {
			fmt.Printf("│  │  Method: %s\n", results.HTTPRequest.Method)
			fmt.Printf("│  │  URL: %s\n", results.HTTPRequest.URL)
			if len(results.HTTPRequest.Headers) > 0 {
				fmt.Println("│  │  Request Headers:")
				for k, v := range results.HTTPRequest.Headers {
					fmt.Printf("│  │    %s: %s\n", k, v)
				}
			}
		}
		fmt.Println("│  │")
		fmt.Println("│  └────────────────────────────")

		fmt.Println("│  ┌─ Response")
		if results.HTTPResponse == nil {
			fmt.Println("│  │  Not collected")
		} else {
			r := results.HTTPResponse
			fmt.Printf("│  │  Status: %d\n", r.StatusCode)
			if r.Title != "" {
				fmt.Printf("│  │  Title: %s\n", r.Title)
			}
			if r.Server != "" {
				fmt.Printf("│  │  Server: %s\n", r.Server)
			}
			if r.ResponseTimeMS > 0 {
				fmt.Printf("│  │  Response time: %d ms\n", r.ResponseTimeMS)
			}
			if len(r.Redirects) > 0 {
				fmt.Println("│  │  Redirect chain:")
				for _, rr := range r.Redirects {
					fmt.Printf("│  │    - %s\n", rr)
				}
			}
			if len(r.SecurityHeaders) > 0 {
				fmt.Println("│  │  Security headers:")
				for k, v := range r.SecurityHeaders {
					fmt.Printf("│  │    %s: %s\n", k, v)
				}
			}
			if len(r.Headers) > 0 {
				fmt.Println("│  │  Raw headers:")
				for k, v := range r.Headers {
					fmt.Printf("│  │    %s: %s\n", k, strings.Join(v, ", "))
				}
			}
			if r.TLS != nil {
				fmt.Println("│  │  TLS:")
				fmt.Printf("│  │    Protocol: %s\n", r.TLS.Protocol)
				fmt.Printf("│  │    Cipher: %s\n", r.TLS.Cipher)
				fmt.Printf("│  │    Issuer: %s\n", r.TLS.Issuer)
				fmt.Printf("│  │    Subject: %s\n", r.TLS.Subject)
				fmt.Printf("│  │    Valid from: %s\n", r.TLS.ValidFrom.Format(time.RFC3339))
				fmt.Printf("│  │    Valid to: %s\n", r.TLS.ValidTo.Format(time.RFC3339))
				if r.TLS.IsExpired {
					fmt.Println("│  │    WARNING: Certificate expired")
				}
				if r.TLS.IsSelfSigned {
					fmt.Println("│  │    WARNING: Self-signed certificate")
				}
			}
		}
		fmt.Println("│  └────────────────────────────")
		fmt.Println("└────────────────────────────\n")
	}

	// Geolocation
	if flags.geoIP {
		fmt.Println("┌─ Geolocation & ISP")
		if results.Geo == nil {
			fmt.Println("│  Not collected")
		} else {
			geoJSON, _ := json.MarshalIndent(results.Geo, "│  ", "  ")
			fmt.Println("│  " + strings.ReplaceAll(string(geoJSON), "\n", "\n│  "))
		}
		fmt.Println("└────────────────────────────\n")
	}

	// Subdomains
	if flags.subdomains {
		fmt.Printf("┌─ Subdomains (%d)\n", len(results.Subdomains))
		if len(results.Subdomains) == 0 {
			fmt.Println("│  None found")
		} else {
			for _, s := range results.Subdomains {
				fmt.Printf("│  - %s\n", s)
			}
		}
		fmt.Println("└────────────────────────────\n")
	}

	// DNS Records
	if flags.dns {
		fmt.Printf("┌─ DNS Records (%d types)\n", len(results.DNSRecords))
		if len(results.DNSRecords) == 0 {
			fmt.Println("│  No DNS records collected")
		} else {
			for rt, vals := range results.DNSRecords {
				fmt.Printf("│  %s:\n", rt)
				for _, v := range vals {
					fmt.Printf("│    - %s\n", v)
				}
			}
		}
		fmt.Println("└────────────────────────────\n")
	}

	// Ports: print JSON array (pretty)
	if flags.ports {
		type portOutput struct {
			Port    int    `json:"port"`
			State   string `json:"state"`
			Service string `json:"service"`
			Banner  string `json:"banner"`
			Proto   string `json:"protocol"`
		}

		out := []portOutput{}
		if len(results.PortDetails) > 0 {
			for _, p := range results.PortDetails {
				state := "closed"
				if p.Open {
					state = "open"
				}
				proto := p.Protocol
				if proto == "" {
					proto = "tcp"
				}
				banner := p.Banner
				if banner == "" && p.TLSVersion != "" {
					banner = fmt.Sprintf("%s / %s", p.TLSVersion, p.TLSCipher)
				}
				out = append(out, portOutput{
					Port:    p.Port,
					State:   state,
					Service: p.Service,
					Banner:  banner,
					Proto:   proto,
				})
			}
		} else {
			for _, pnum := range results.OpenPorts {
				out = append(out, portOutput{
					Port:    pnum,
					State:   "open",
					Service: serviceByPort(pnum),
					Banner:  "",
					Proto:   "tcp",
				})
			}
		}

		blob, _ := json.MarshalIndent(out, " ", "  ")
		fmt.Println("┌─ Open Ports (detailed)")
		lines := strings.Split(string(blob), "\n")
		for _, l := range lines {
			fmt.Printf("│  %s\n", l)
		}
		fmt.Println("└────────────────────────────\n")
	}

	// Reverse IP
	if flags.reverseIP {
		fmt.Printf("┌─ Reverse IP (%d)\n", len(results.ReverseIP))
		if len(results.ReverseIP) == 0 {
			fmt.Println("│  None found")
		} else {
			for _, d := range results.ReverseIP {
				fmt.Printf("│  - %s\n", d)
			}
		}
		fmt.Println("└────────────────────────────\n")
	}

	// Metadata
	if flags.metadata {
		fmt.Println("┌─ Metadata")
		if results.Metadata == nil {
			fmt.Println("│  Not collected")
		} else {
			m := results.Metadata
			if m.FinalURL != "" {
				fmt.Printf("│  Final URL: %s\n", m.FinalURL)
			}
			if m.Status != 0 {
				fmt.Printf("│  Status: %d\n", m.Status)
			}
			if m.Server != "" {
				fmt.Printf("│  Server: %s\n", m.Server)
			}
			if m.ContentType != "" {
				fmt.Printf("│  Content-Type: %s\n", m.ContentType)
			}
			if len(m.SecurityHeaders) > 0 {
				fmt.Println("│  Security headers:")
				for k, v := range m.SecurityHeaders {
					fmt.Printf("│    %s: %s\n", k, v)
				}
			}
			if len(m.MetaTags) > 0 {
				fmt.Println("│  Meta tags (sample):")
				count := 0
				for k, v := range m.MetaTags {
					fmt.Printf("│    %s: %s\n", k, v)
					count++
					if count >= 8 {
						break
					}
				}
			}
			if len(m.Trackers) > 0 {
				fmt.Printf("│  Detected analytics/trackers: %s\n", strings.Join(m.Trackers, ", "))
			}
			if m.RobotsTxt != "" {
				firstLine := strings.SplitN(m.RobotsTxt, "\n", 2)[0]
				fmt.Printf("│  robots.txt: %s\n", strings.TrimSpace(firstLine))
			}
			if len(m.ResolvedIPs) > 0 {
				fmt.Printf("│  Resolved IPs: %s\n", strings.Join(m.ResolvedIPs, ", "))
			}
			if len(m.Notes) > 0 {
				fmt.Printf("│  Notes: %s\n", strings.Join(m.Notes, " | "))
			}
		}
		fmt.Println("└────────────────────────────\n")
	}

	// Directory / Content Discovery - new section
	if flagsDirEnabled(&flagsGlobal) {
		if results.Directory == nil {
			fmt.Println("┌─ Directory / Content Discovery")
			fmt.Println("│  Not collected")
			fmt.Println("└────────────────────────────\n")
		} else {
			dr := results.Directory
			fmt.Println("┌─ Directory / Content Discovery (detailed)")

			fmt.Println("│  Directory options used:")
			fmt.Printf("│    - fetch-js: %v\n", flags.dirFetchJS)
			fmt.Printf("│    - follow-sitemap: %v\n", flags.dirFollowSitemap)
			if flags.dirWordlist != "" {
				fmt.Printf("│    - wordlist: %s\n", flags.dirWordlist)
			} else {
				fmt.Printf("│    - wordlist: (built-in)\n")
			}
			fmt.Println("│")

			if dr.Baseline != nil {
				fmt.Printf("│  Baseline 404 URL: %s (status=%d, sample-size=%d)\n", dr.Baseline.URL, dr.Baseline.Status, dr.Baseline.ContentLength)
			}
			if len(dr.Robots) > 0 {
				fmt.Println("│  robots.txt entries:")
				for _, e := range dr.Robots {
					fmt.Printf("│    - %s\n", e)
				}
			}
			if len(dr.Sitemap) > 0 {
				fmt.Printf("│  Sitemap entries: %d (showing up to 8)\n", len(dr.Sitemap))
				for i, s := range dr.Sitemap {
					if i >= 8 {
						fmt.Printf("│    ... (+%d more)\n", len(dr.Sitemap)-8)
						break
					}
					fmt.Printf("│    - %s\n", s)
				}
			}
			if len(dr.JSFiles) > 0 {
				fmt.Printf("│  JS files discovered: %d\n", len(dr.JSFiles))
				for _, j := range dr.JSFiles {
					fmt.Printf("│    - %s\n", j)
				}
			}
			fmt.Printf("│  Findings (%d):\n", len(dr.Findings))
			for _, f := range dr.Findings {
				fmt.Println("│  ────────────────────────────────────────")
				fmt.Printf("│  URL: %s\n", f.URL)
				fmt.Printf("│    Status: %d   Confidence: %s   Type: %s\n", f.Status, f.Confidence, f.EvidenceType)
				if f.ContentType != "" {
					fmt.Printf("│    Content-Type: %s   Size: %d\n", f.ContentType, f.ContentLength)
				}
				if len(f.KeywordsFound) > 0 {
					fmt.Printf("│    Keywords: %s\n", strings.Join(f.KeywordsFound, ", "))
				}
				if len(f.Redirects) > 0 {
					fmt.Printf("│    Redirects: %s\n", strings.Join(f.Redirects, " -> "))
				}
				if f.TLS != nil {
					fmt.Printf("│    TLS: subject=%s issuer=%s valid_to=%s\n", f.TLS.Subject, f.TLS.Issuer, f.TLS.ValidTo.Format(time.RFC3339))
				}
				if len(f.Notes) > 0 {
					for _, n := range f.Notes {
						fmt.Printf("│    Note: %s\n", n)
					}
				}
				if len(f.BodySnippet) > 0 {
					first := strings.SplitN(f.BodySnippet, "\n", 2)[0]
					if len(first) > 200 {
						first = first[:200] + "..."
					}
					fmt.Printf("│    Snippet: %s\n", first)
				}
			}
			fmt.Println("└────────────────────────────\n")
		}
	}

	// Mail (detailed)
	if flags.mail {
		fmt.Println("┌─ Mail Recon (detailed)")
		if results.Mail == nil {
			fmt.Println("│  Not collected")
		} else {
			m := results.Mail
			fmt.Printf("│  Input: %s\n", m.Input)
			fmt.Printf("│  Domain: %s\n", m.Domain)

			if len(m.MXRecords) > 0 {
				fmt.Printf("│  MX records (%d):\n", len(m.MXRecords))
				for _, mx := range m.MXRecords {
					fmt.Printf("│    - %s (priority %d)\n", mx.Host, mx.Priority)
				}
			} else {
				fmt.Println("│  MX records: none")
			}

			if m.SPF != "" {
				fmt.Printf("│  SPF: %s\n", m.SPF)
			}
			if len(m.SPFParsed.Includes) > 0 || len(m.SPFParsed.IP4) > 0 || len(m.SPFParsed.IP6) > 0 || m.SPFParsed.All != "" {
				if len(m.SPFParsed.Includes) > 0 {
					fmt.Printf("│    SPF includes: %s\n", strings.Join(m.SPFParsed.Includes, ", "))
				}
				if len(m.SPFParsed.IP4) > 0 {
					fmt.Printf("│    SPF ip4: %s\n", strings.Join(m.SPFParsed.IP4, ", "))
				}
				if len(m.SPFParsed.IP6) > 0 {
					fmt.Printf("│    SPF ip6: %s\n", strings.Join(m.SPFParsed.IP6, ", "))
				}
				if m.SPFParsed.All != "" {
					fmt.Printf("│    SPF all directive: %s\n", m.SPFParsed.All)
				}
			}

			if m.DMARC != "" {
				fmt.Printf("│  DMARC: %s\n", m.DMARC)
				if len(m.DMARCTags) > 0 {
					fmt.Println("│  DMARC tags:")
					keys := make([]string, 0, len(m.DMARCTags))
					for k := range m.DMARCTags {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					for _, k := range keys {
						fmt.Printf("│    - %s = %s\n", k, m.DMARCTags[k])
					}
				}
			} else {
				fmt.Println("│  DMARC: none")
			}

			if len(m.DKIM) > 0 {
				fmt.Printf("│  DKIM selectors: %d\n", len(m.DKIM))
				for sel, txt := range m.DKIM {
					short := txt
					if len(short) > 160 {
						short = short[:160] + "..."
					}
					fmt.Printf("│    - %s => %s\n", sel, short)
				}
			} else {
				fmt.Println("│  DKIM: none found")
			}

			if m.MTASTS.TXT != "" || m.MTASTS.PolicyText != "" {
				fmt.Println("│  MTA-STS:")
				if m.MTASTS.TXT != "" {
					fmt.Printf("│    TXT: %s\n", m.MTASTS.TXT)
				}
				if m.MTASTS.PolicyURL != "" {
					fmt.Printf("│    Policy URL: %s\n", m.MTASTS.PolicyURL)
				}
				if m.MTASTS.PolicyText != "" {
					sn := m.MTASTS.PolicyText
					if len(sn) > 240 {
						sn = sn[:240] + "..."
					}
					fmt.Printf("│    Policy snippet: %s\n", sn)
				}
			} else {
				fmt.Println("│  MTA-STS: none")
			}

			if len(m.TLSRPT) > 0 {
				fmt.Printf("│  TLS-RPT: %s\n", strings.Join(m.TLSRPT, ", "))
			}
			if len(m.CAA) > 0 {
				fmt.Println("│  CAA records:")
				for _, c := range m.CAA {
					fmt.Printf("│    - %s\n", c)
				}
			}

			if len(m.ResolvedIPs) > 0 {
				fmt.Println("│  Resolved IPs / Details:")
				for host, ips := range m.ResolvedIPs {
					fmt.Printf("│    - %s -> %s\n", host, strings.Join(ips, ", "))
					for _, ip := range ips {
						if ptrs, ok := m.PTRs[ip]; ok && len(ptrs) > 0 {
							fmt.Printf("│      PTRs: %s\n", strings.Join(ptrs, ", "))
						}
						if asn, ok := m.ASN[ip]; ok {
							fmt.Printf("│      ASN: %s (%s) country=%s\n", asn.ASN, asn.ASName, asn.Country)
						}
						if rbls, ok := m.RBL[ip]; ok && len(rbls) > 0 {
							fmt.Printf("│      RBLs: %s\n", strings.Join(rbls, ", "))
						}
					}
				}
			}

			if len(m.WebmailEndpoints) > 0 {
				fmt.Println("│  Webmail / Autodiscover endpoints:")
				for _, w := range m.WebmailEndpoints {
					fmt.Printf("│    - %s\n", w)
				}
			}

			if len(m.SMTPProbes) > 0 {
				fmt.Println("│  SMTP probe results:")
				for _, p := range m.SMTPProbes {
					fmt.Printf("│    - %s:%d (mx=%s)\n", p.IP, p.Port, p.MXHost)
					fmt.Printf("│      Connected: %v\n", p.Connected)
					if p.Banner != "" {
						fmt.Printf("│      Banner: %.160s\n", p.Banner)
					}
					if len(p.EHLOLines) > 0 {
						fmt.Printf("│      EHLO lines (%d):\n", len(p.EHLOLines))
						for _, l := range p.EHLOLines {
							fmt.Printf("│        - %s\n", l)
						}
					}
					fmt.Printf("│      STARTTLS: %v\n", p.SupportsStartTLS)
					if len(p.AuthMechanisms) > 0 {
						fmt.Printf("│      Auth: %s\n", strings.Join(p.AuthMechanisms, ", "))
					}
					if p.TLSVersion != "" || p.Cipher != "" {
						fmt.Printf("│      TLS: %s / %s\n", p.TLSVersion, p.Cipher)
					}
					if p.VRFYResult != "" {
						fmt.Printf("│      VRFY: %s\n", p.VRFYResult)
					}
					if p.RCPTResult != "" {
						fmt.Printf("│      RCPT: %s\n", p.RCPTResult)
					}
					if p.Error != "" {
						fmt.Printf("│      Error: %s\n", p.Error)
					}
				}
			} else {
				fmt.Println("│  SMTP probes: none run")
			}

			if len(m.ProviderHeuristics) > 0 {
				fmt.Println("│  Provider heuristics:")
				for _, ph := range m.ProviderHeuristics {
					fmt.Printf("│    - %s\n", ph)
				}
			}
			fmt.Printf("│  Posture: SPF=%v DKIM=%v MTA-STS=%v STARTTLS_any=%v Score=%d\n",
				m.Posture.HasSPF, m.Posture.HasDKIM, m.Posture.HasMTASTS, m.Posture.AnyStartTLS, m.Posture.OverallScore)

			if len(m.Notes) > 0 {
				fmt.Println("│  Notes:")
				for _, n := range m.Notes {
					fmt.Printf("│    - %s\n", n)
				}
			}
		}
		fmt.Println("└────────────────────────────\n")
	}

	// JS Recon - single, full, non-truncated output
	if flags.js {
		fmt.Println("┌─ JavaScript Recon (detailed)")
		if results.JS == nil {
			fmt.Println("│  Not collected")
		} else {
			j := results.JS
			if j.PageURL != "" {
				fmt.Printf("│  Page: %s\n", j.PageURL)
			}

			fmt.Printf("│  External scripts: %d\n", len(j.Scripts))
			if len(j.Scripts) > 0 {
				for _, s := range j.Scripts {
					fmt.Printf("│    - %s\n", s)
				}
			}

			fmt.Printf("│  Inline scripts: %d\n", j.InlineScriptsCount)
			if len(j.InlineSnippets) > 0 {
				for i, sn := range j.InlineSnippets {
					fmt.Printf("│    snippet[%d]: %s\n", i+1, sn)
				}
			}

			fmt.Printf("│  SourceMaps: %d\n", len(j.SourceMaps))
			for _, sm := range j.SourceMaps {
				fmt.Printf("│    - %s\n", sm)
			}

			fmt.Printf("│  Framework markers: %d\n", len(j.Frameworks))
			for _, f := range j.Frameworks {
				fmt.Printf("│    - %s\n", f)
			}

			fmt.Printf("│  Trackers / Libraries: %d\n", len(j.Trackers))
			for _, t := range j.Trackers {
				fmt.Printf("│    - %s\n", t)
			}

			fmt.Printf("│  APIs discovered: %d\n", len(j.APIs))
			for _, a := range j.APIs {
				fmt.Printf("│    - %s\n", a)
			}

			fmt.Printf("│  GraphQL endpoints: %d\n", len(j.GraphQLEndpoints))
			for _, g := range j.GraphQLEndpoints {
				fmt.Printf("│    - %s\n", g)
			}

			fmt.Printf("│  WebSocket endpoints: %d\n", len(j.WebSockets))
			for _, w := range j.WebSockets {
				fmt.Printf("│    - %s\n", w)
			}

			fmt.Printf("│  Keys/Tokens: %d\n", len(j.Secrets))
			for _, k := range j.Secrets {
				fmt.Printf("│    - %s\n", k)
			}

			fmt.Printf("│  Dangerous patterns: %d\n", len(j.DangerousPatterns))
			for _, d := range j.DangerousPatterns {
				fmt.Printf("│    - %s\n", d)
			}

			fmt.Printf("│  Obfuscation signs: %d\n", len(j.ObfuscationSigns))
			for _, o := range j.ObfuscationSigns {
				fmt.Printf("│    - %s\n", o)
			}

			fmt.Printf("│  Storage usage: %d\n", len(j.StorageUsage))
			for _, s := range j.StorageUsage {
				fmt.Printf("│    - %s\n", s)
			}
			fmt.Printf("│  Crypto usage: %d\n", len(j.CryptoUsage))
			for _, c := range j.CryptoUsage {
				fmt.Printf("│    - %s\n", c)
			}

			fmt.Printf("│  Regex / validation patterns: %d\n", len(j.RegexPatterns))
			for _, r := range j.RegexPatterns {
				fmt.Printf("│    - %s\n", r)
			}

			fmt.Printf("│  Dependency hints: %d\n", len(j.Dependencies))
			for _, d := range j.Dependencies {
				fmt.Printf("│    - %s\n", d)
			}

			fmt.Printf("│  Errors & console logs: %d\n", len(j.ErrorsAndLogs))
			for _, e := range j.ErrorsAndLogs {
				fmt.Printf("│    - %s\n", e)
			}

			fmt.Printf("│  Comments / TODOs: %d\n", len(j.CommentsTodos))
			for _, c := range j.CommentsTodos {
				fmt.Printf("│    - %s\n", c)
			}

			fmt.Printf("│  OSINT (emails / hashes / ids): %d\n", len(j.OSINT))
			for _, o := range j.OSINT {
				fmt.Printf("│    - %s\n", o)
			}

			if len(j.Notes) > 0 {
				fmt.Println("│  Notes:")
				for _, n := range j.Notes {
					fmt.Printf("│    - %s\n", n)
				}
			}
		}
		fmt.Println("└────────────────────────────\n")
	}

	// Social profiles (detailed)
	if flags.social {
		fmt.Printf("┌─ Social Profiles (%d)\n", len(results.SocialProfiles))
		if len(results.SocialProfiles) == 0 {
			fmt.Println("│  None checked or no details available")
		} else {
			socialURLs := []string{}
			for _, sp := range results.SocialProfiles {
				fmt.Printf("│  - Platform: %s\n", sp.Platform)
				fmt.Printf("│    Username: %s\n", sp.Username)
				if sp.URL != "" {
					fmt.Printf("│    URL: %s\n", sp.URL)
				}
				fmt.Printf("│    Exists: %v\n", sp.Exists)
				if sp.DisplayName != "" {
					fmt.Printf("│    Name: %s\n", sp.DisplayName)
				}
				if sp.Bio != "" {
					fmt.Printf("│    Bio: %s\n", sp.Bio)
				}
				if sp.Avatar != "" {
					fmt.Printf("│    Avatar: %s\n", sp.Avatar)
				}
				if sp.Website != "" {
					fmt.Printf("│    Website: %s\n", sp.Website)
				}
				if sp.Followers != 0 {
					fmt.Printf("│    Followers: %d\n", sp.Followers)
				}
				if sp.PublicRepos != 0 {
					fmt.Printf("│    PublicRepos: %d\n", sp.PublicRepos)
				}
				if sp.Error != "" {
					fmt.Printf("│    Error: %s\n", sp.Error)
				}
				if sp.Exists && sp.URL != "" {
					socialURLs = append(socialURLs, fmt.Sprintf("%s -> %s", sp.Platform, sp.URL))
				}
			}
			if len(socialURLs) > 0 {
				fmt.Println("│")
				fmt.Printf("│  URLs discovered for social profiles (%d):\n", len(socialURLs))
				for _, u := range socialURLs {
					fmt.Printf("│    - %s\n", u)
				}
			}
		}
		fmt.Println("└────────────────────────────\n")
	}

	// Proxies
	if flags.proxy {
		fmt.Printf("┌─ Proxies (%d valid)\n", len(results.Proxies))
		if len(results.Proxies) == 0 {
			fmt.Println("│  None validated")
		} else {
			for _, p := range results.Proxies {
				fmt.Printf("│  - %s\n", p)
			}
		}
		fmt.Println("└────────────────────────────\n")
	}

	// URLs - only print general collected URLs when -url/collectURLs is used.
	if flags.collectURLs {
		fmt.Printf("┌─ URLs Found (%d)\n", len(results.URLs))
		if len(results.URLs) == 0 {
			fmt.Println("│  None found")
		} else {
			for _, u := range results.URLs {
				fmt.Printf("│  - %s\n", u)
			}
		}
		fmt.Println("└────────────────────────────\n")
	}

	// Endpoints (detailed)
	if flags.endpoints {
		fmt.Printf("┌─ Endpoints (%d)\n", len(results.Endpoints))
		if len(results.Endpoints) == 0 {
			fmt.Println("│  None found")
		} else {
			for _, epc := range results.Endpoints {
				fmt.Println("│  ────────────────────────────────────────")
				fmt.Printf("│  URL: %s\n", epc.URL)
				fmt.Printf("│    Discovered in: %s   Confidence: %s\n", epc.DiscoverySource, epc.Confidence)
				if len(epc.Tags) > 0 {
					fmt.Printf("│    Tags: %s\n", strings.Join(epc.Tags, ", "))
				}
				if len(epc.StatusCodes) > 0 {
					fmt.Printf("│    Status: %v\n", epc.StatusCodes)
				}
				if epc.ContentType != "" {
					fmt.Printf("│    Content-Type: %s   Size: %d\n", epc.ContentType, epc.ResponseSize)
				}
				if len(epc.AllowedMethods) > 0 {
					fmt.Printf("│    Allowed methods: %s\n", strings.Join(epc.AllowedMethods, ", "))
				}
				if len(epc.CORS) > 0 {
					fmt.Printf("│    CORS: %v\n", epc.CORS)
				}
				if epc.TLS != nil {
					fmt.Printf("│    TLS: %s / %s  issuer=%s\n", epc.TLS.Protocol, epc.TLS.Cipher, epc.TLS.Issuer)
				}
				if len(epc.Evidence) > 0 {
					fmt.Printf("│    Evidence: %s\n", strings.Join(epc.Evidence, " | "))
				}
				if len(epc.Notes) > 0 {
					for _, n := range epc.Notes {
						fmt.Printf("│    Note: %s\n", n)
					}
				}
				// show snippet first line if available
				if epc.ResponseSnippet != "" {
					first := strings.SplitN(epc.ResponseSnippet, "\n", 2)[0]
					if len(first) > 200 {
						first = first[:200] + "..."
					}
					fmt.Printf("│    Snippet: %s\n", first)
				}
			}
		}
		fmt.Println("└────────────────────────────\n")
	}

	// Parameter findings
	if flags.parameter {
		fmt.Println("┌─ Parameter Recon")
		if results.ParameterReport == nil || len(results.ParameterReport.Findings) == 0 {
			fmt.Println("│  None found")
		} else {
			for _, f := range results.ParameterReport.Findings {
				fmt.Printf("│  - %s (conf=%s sensitive=%v)\n", f.Name, f.Confidence, f.Sensitive)
				if len(f.ExampleValues) > 0 {
					fmt.Printf("│      examples: %s\n", strings.Join(f.ExampleValues, ", "))
				}
				if len(f.PotentialIssues) > 0 {
					fmt.Printf("│      issues: %s\n", strings.Join(f.PotentialIssues, ", "))
				}
				for _, loc := range f.Locations {
					fmt.Printf("│      location: %s %s field=%s\n", loc.Method, loc.URL, loc.Field)
				}
			}
		}
		fmt.Println("└────────────────────────────\n")
	}
}

// ---------- Helpers (subdomain sources & utilities) ----------
func normalizeHost(s, domain string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", false
	}
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimPrefix(s, "*.")
	if strings.Contains(s, " ") || strings.Contains(s, "@") {
		return "", false
	}
	if s == domain || strings.HasSuffix(s, "."+domain) {
		return s, true
	}
	if !strings.Contains(s, ".") && domain != "" {
		return s + "." + domain, true
	}
	return "", false
}

// ---------- globals for new features ----------
var globalLimiter *RequestLimiter
var randSrc = rand.New(rand.NewSource(time.Now().UnixNano()))

// buildStdClient with TLS skip and timeout
func buildStdClient(timeout time.Duration) *stdhttp.Client {
	tr := &stdhttp.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &stdhttp.Client{Timeout: timeout, Transport: tr}
}

// ---------- HTTP helper wrapper updated with rate-limit/jitter/retries ----------
func httpGet(client *stdhttp.Client, raw string) ([]byte, int, error) {
	req, err := stdhttp.NewRequest("GET", raw, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "ReconNio/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return b, resp.StatusCode, err
}

// fetchURLSimple does a request and returns body (truncated), status, headers and redirects
func fetchURLSimple(client *stdhttp.Client, rawurl string, method string, maxBody int64, ua string) ([]byte, int, map[string]string, []string, *DirTLSInfo, error) {
	if globalLimiter != nil {
		globalLimiter.Allow()
	}

	if flagsGlobal.Jitter > 0 {
		sleep := time.Duration(randSrc.Float64() * flagsGlobal.Jitter * float64(time.Second))
		time.Sleep(sleep)
	}

	attempts := flagsGlobal.Retries + 1
	var lastErr error
	for a := 0; a < attempts; a++ {
		req, err := stdhttp.NewRequest(method, rawurl, nil)
		if err != nil {
			return nil, 0, nil, nil, nil, err
		}
		if ua == "" {
			ua = "ReconNio/Dir/1.0"
		}
		if len(flagsGlobal.UAList) > 0 {
			ua = flagsGlobal.UAList[randSrc.Intn(len(flagsGlobal.UAList))]
		}
		req.Header.Set("User-Agent", ua)
		redirects := []string{}
		visited := map[string]struct{}{}
		cl := *client
		cl.CheckRedirect = func(req *stdhttp.Request, via []*stdhttp.Request) error {
			u := req.URL.String()
			if _, ok := visited[u]; ok {
				return stdhttp.ErrUseLastResponse
			}
			visited[u] = struct{}{}
			redirects = append(redirects, u)
			if len(via) >= 10 {
				return stdhttp.ErrUseLastResponse
			}
			return nil
		}
		resp, err := cl.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(200*(a+1)) * time.Millisecond)
			continue
		}
		defer resp.Body.Close()
		headers := map[string]string{}
		for k, v := range resp.Header {
			headers[k] = strings.Join(v, "; ")
		}
		var tlsInfo *DirTLSInfo
		if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			c := resp.TLS.PeerCertificates[0]
			tlsInfo = &DirTLSInfo{
				Subject:   c.Subject.CommonName,
				Issuer:    c.Issuer.CommonName,
				ValidFrom: c.NotBefore,
				ValidTo:   c.NotAfter,
			}
		}
		if method == "HEAD" {
			return nil, resp.StatusCode, headers, redirects, tlsInfo, nil
		}
		limited := io.LimitReader(resp.Body, maxBody)
		b, err := io.ReadAll(limited)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(100*(a+1)) * time.Millisecond)
			continue
		}
		return b, resp.StatusCode, headers, redirects, tlsInfo, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("unknown fetch error")
	}
	return nil, 0, nil, nil, nil, lastErr
}

// ---------- helper parse ports and atoi ----------
func parsePortsRangeOrList(s string) []int {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	set := map[int]struct{}{}
	parts := strings.Split(s, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			bounds := strings.SplitN(p, "-", 2)
			if len(bounds) != 2 {
				continue
			}
			start := atoi(bounds[0])
			end := atoi(bounds[1])
			if start <= 0 || end <= 0 || start > end {
				continue
			}
			if start < 1 {
				start = 1
			}
			if end > 65535 {
				end = 65535
			}
			for i := start; i <= end; i++ {
				set[i] = struct{}{}
			}
		} else {
			v := atoi(p)
			if v >= 1 && v <= 65535 {
				set[v] = struct{}{}
			}
		}
	}
	out := make([]int, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func atoi(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return v
}

// ---------- Directory scanning helpers & defaults ----------
var (
	dirDefaults = []string{
		"admin", "administrator", "login", "wp-admin", "wp-login.php", ".git/", ".git/config", ".env", "backup.zip", "db.sql", "phpinfo.php", "robots.txt", "sitemap.xml", "api", "graphql",
	}
	dirDetections = map[string]*regexp.Regexp{
		"private_key": regexp.MustCompile(`(?i)-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`),
		"aws_key_id":  regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"index_of":    regexp.MustCompile(`(?i)Index of /`),
		"phpinfo":     regexp.MustCompile(`(?i)<title>phpinfo\(`),
	}
)

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

func computeDirBaseline(client *stdhttp.Client, base string, ua string) (*DirFinding, []byte, error) {
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "https://" + strings.TrimSuffix(base, "/")
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, nil, err
	}
	randToken := fmt.Sprintf("noreallythisdoesntexist-%d", time.Now().UnixNano())
	u.Path = pathJoin(u.Path, randToken)
	raw := u.String()
	body, status, headers, redirects, tlsInfo, err := fetchURLSimple(client, raw, "GET", 128*1024, ua)
	if err != nil {
		_, status2, headers2, redirects2, tls2, err2 := fetchURLSimple(client, raw, "HEAD", 1, ua)
		if err2 != nil {
			return nil, nil, fmt.Errorf("baseline failed: %v / %v", err, err2)
		}
		bf := &DirFinding{
			URL:             raw,
			Method:          "HEAD",
			Status:          status2,
			ContentLength:   0,
			ContentType:     headers2["Content-Type"],
			BodySnippet:     "",
			Redirects:       redirects2,
			ResponseHeaders: headers2,
			TLS:             tls2,
			Timestamp:       time.Now().UTC().Format(time.RFC3339),
			Confidence:      "low",
			EvidenceType:    "baseline",
		}
		return bf, nil, nil
	}
	bf := &DirFinding{
		URL:             raw,
		Method:          "GET",
		Status:          status,
		ContentLength:   len(body),
		ContentType:     headers["Content-Type"],
		BodySnippet:     snippet(body, 400),
		Redirects:       redirects,
		ResponseHeaders: headers,
		TLS:             &DirTLSInfo{Subject: tlsInfo.Subject, Issuer: tlsInfo.Issuer, ValidFrom: tlsInfo.ValidFrom, ValidTo: tlsInfo.ValidTo},
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		Confidence:      "low",
		EvidenceType:    "baseline",
	}
	return bf, body, nil
}

func pathJoin(a, b string) string {
	if a == "" || a == "/" {
		return "/" + strings.TrimPrefix(b, "/")
	}
	return strings.TrimRight(a, "/") + "/" + strings.TrimPrefix(b, "/")
}

func snippet(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
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

func classifyDirPath(rawurl string, body []byte, status int, ctype string) (evidence string, keywords []string) {
	lower := strings.ToLower(rawurl)
	if strings.Contains(lower, ".git") {
		return "git", []string{".git"}
	}
	if strings.HasSuffix(lower, ".env") || (strings.Contains(lower, "env") && strings.Contains(lower, "config")) {
		return "config", []string{"env"}
	}
	if strings.Contains(lower, "backup") || strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".sql") {
		return "backup", []string{"backup"}
	}
	if strings.Contains(lower, "admin") || strings.Contains(lower, "dashboard") || strings.Contains(lower, "wp-") {
		return "admin", []string{"admin"}
	}
	if strings.Contains(lower, "api") || strings.Contains(lower, "graphql") {
		return "api", []string{"api"}
	}
	for k, rx := range dirDetections {
		if rx.Match(body) {
			return "secret", []string{k}
		}
	}
	if dirDetections["index_of"].Match(body) {
		return "directory_listing", []string{"index_of"}
	}
	return "other", nil
}

func loadDirWordlist(pathFile string, extras []string) ([]string, error) {
	set := map[string]struct{}{}
	for _, w := range dirDefaults {
		set[w] = struct{}{}
	}
	for _, e := range extras {
		set[e] = struct{}{}
	}
	if pathFile != "" {
		f, err := os.Open(pathFile)
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
			set[line] = struct{}{}
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}

func dirProbeWorker(client *stdhttp.Client, ua string, baselineBody []byte, tasks <-chan string, out chan<- DirFinding, wg *sync.WaitGroup) {
	defer wg.Done()
	for u := range tasks {
		_, status, headers, redirects, tlsInfo, err := fetchURLSimple(client, u, "HEAD", 1, ua)
		var body []byte
		if err != nil {
			body, status, headers, redirects, tlsInfo, err = fetchURLSimple(client, u, "GET", 512*1024, ua)
			if err != nil {
				continue
			}
		} else {
			if status == 200 || status == 401 || status == 403 || (status >= 300 && status < 400) {
				body, status, headers, redirects, tlsInfo, _ = fetchURLSimple(client, u, "GET", 512*1024, ua)
			}
		}
		ct := headers["Content-Type"]
		eType, kws := classifyDirPath(u, body, status, ct)
		foundKeys := []string{}
		for _, k := range kws {
			foundKeys = append(foundKeys, k)
		}
		for name, rx := range dirDetections {
			if rx.Match(body) {
				foundKeys = append(foundKeys, name)
			}
		}
		sizeSim := 0.0
		if baselineBody != nil && len(baselineBody) > 0 && len(body) > 0 {
			sizeSim = sizeSimilarity(baselineBody, body)
		}
		conf := "low"
		score := 0
		if status == 200 {
			score += 30
		} else if status == 401 || status == 403 {
			score += 20
		} else if status >= 300 && status < 400 {
			score += 10
		}
		if strings.Contains(strings.ToLower(ct), "zip") || strings.Contains(strings.ToLower(ct), "gzip") {
			score += 30
		}
		score += len(foundKeys) * 15
		if sizeSim < 0.6 {
			score += 10
		}
		if score >= 70 {
			conf = "high"
		} else if score >= 30 {
			conf = "medium"
		}
		if status == 200 && sizeSim > 0.98 {
			conf = "low"
		}
		var dtls *DirTLSInfo
		if tlsInfo != nil {
			dtls = tlsInfo
		}
		find := DirFinding{
			URL:                u,
			Method:             "GET",
			Status:             status,
			ContentLength:      len(body),
			ContentType:        ct,
			BodySnippet:        snippet(body, 600),
			KeywordsFound:      dedupeStrings(foundKeys),
			Redirects:          redirects,
			ResponseHeaders:    headers,
			TLS:                dtls,
			BaselineSimilarity: sizeSim,
			WordlistName:       "",
			Timestamp:          time.Now().UTC().Format(time.RFC3339),
			Confidence:         conf,
			EvidenceType:       eType,
		}
		if !(status == 404 || (status == 200 && sizeSim > 0.995)) {
			out <- find
		}
	}
}

var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src=['"]([^'"]+)['"]`)
var hrefRe = regexp.MustCompile(`(?i)<a[^>]+href=['"]([^'"]+)['"]`)
var sourceMapRe = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL\s*=\s*(.+)$`)

func extractScriptSrcs(html []byte, base *url.URL) []string {
	out := []string{}
	m := scriptSrcRe.FindAllSubmatch(html, -1)
	for _, mm := range m {
		if len(mm) >= 2 {
			src := string(mm[1])
			u, err := url.Parse(strings.TrimSpace(src))
			if err != nil {
				continue
			}
			out = append(out, base.ResolveReference(u).String())
		}
	}
	return dedupeStrings(out)
}

func extractLinks(html []byte, base *url.URL) []string {
	out := []string{}
	m := hrefRe.FindAllSubmatch(html, -1)
	for _, mm := range m {
		if len(mm) >= 2 {
			h := string(mm[1])
			u, err := url.Parse(strings.TrimSpace(h))
			if err != nil {
				continue
			}
			out = append(out, base.ResolveReference(u).String())
		}
	}
	return dedupeStrings(out)
}

func parseRobotsSimple(client *stdhttp.Client, base *url.URL, ua string) ([]string, []string) {
	u := *base
	u.Path = pathJoin(u.Path, "robots.txt")
	body, status, _, _, _, err := fetchURLSimple(client, u.String(), "GET", 256*1024, ua)
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
		} else if k == "sitemap" {
			sitemaps = append(sitemaps, v)
		}
	}
	return entries, sitemaps
}

func parseSitemapSimple(client *stdhttp.Client, raw string, ua string) []string {
	body, status, _, _, _, err := fetchURLSimple(client, raw, "GET", 2*1024*1024, ua)
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

// runDirectoryScan - orchestrates a directory/content-discovery scan
func runDirectoryScan(target string, wordlistPath string, concurrency int, timeoutSec int, followSitemap bool, fetchJS bool, ua string, dirExtensions []string, dirDepth int, obeyRobots bool) (*DirectoryReport, error) {
	report := &DirectoryReport{
		Target:    target,
		Stats:     map[string]int{},
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
	}
	client := buildStdClient(time.Duration(timeoutSec) * time.Second)

	baseline, baselineBody, err := computeDirBaseline(client, target, ua)
	if err != nil {
	} else {
		report.Baseline = baseline
	}

	words, _ := loadDirWordlist(wordlistPath, nil)
	report.Stats["wordlist_items"] = len(words)

	base := target
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "https://" + strings.TrimSuffix(base, "/")
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return nil, err
	}

	robotsEntries, sitemaps := parseRobotsSimple(client, baseURL, ua)
	report.Robots = robotsEntries
	report.Sitemap = sitemaps
	seedURLs := []string{baseURL.String()}

	obeyDisallows := map[string]struct{}{}
	if obeyRobots && len(robotsEntries) > 0 {
		for _, e := range robotsEntries {
			parts := strings.SplitN(e, ":", 2)
			if len(parts) == 2 {
				p := strings.TrimSpace(parts[1])
				if p != "" {
					obeyDisallows[p] = struct{}{}
				}
			}
		}
	}

	for _, w := range words {
		u := *baseURL
		u.Path = pathJoin(u.Path, w)
		seedURLs = append(seedURLs, u.String())
		if !strings.Contains(w, ".") {
			exts := []string{".php", ".html", ".zip", ".sql", ".env"}
			exts = append(exts, dirExtensions...)
			for _, ext := range exts {
				v := *baseURL
				v.Path = pathJoin(v.Path, w+ext)
				seedURLs = append(seedURLs, v.String())
			}
		}
	}

	if dirDepth >= 1 {
		limit := 60
		n := len(words)
		added := 0
		for i := 0; i < n && added < limit; i++ {
			for j := 0; j < n && added < limit; j++ {
				a := words[i]
				b := words[j]
				u := *baseURL
				u.Path = pathJoin(u.Path, a+"/"+b)
				seedURLs = append(seedURLs, u.String())
				added++
			}
		}
		report.Stats["depth_generated"] = added
	}

	if followSitemap && len(report.Sitemap) > 0 {
		for _, s := range report.Sitemap {
			if !strings.HasPrefix(s, "http") {
				if u, err := url.Parse(s); err == nil {
					s = baseURL.ResolveReference(u).String()
				}
			}
			entries := parseSitemapSimple(client, s, ua)
			for _, e := range entries {
				seedURLs = append(seedURLs, e)
			}
		}
	}

	jsCandidates := []string{}

	if fetchJS {
		body, status, _, _, _, err := fetchURLSimple(client, baseURL.String(), "GET", 512*1024, ua)
		if err == nil && status >= 200 && status < 400 {
			scripts := extractScriptSrcs(body, baseURL)
			report.JSFiles = scripts
			for _, sc := range scripts {
				jsCandidates = append(jsCandidates, sc)
			}
			links := extractLinks(body, baseURL)
			for _, ln := range links {
				if u, err := url.Parse(ln); err == nil {
					if u.Host == baseURL.Host {
						seedURLs = append(seedURLs, ln)
					}
				}
			}
		}
	}

	seedURLs = dedupeStrings(seedURLs)

	if obeyRobots && len(obeyDisallows) > 0 {
		filtered := []string{}
		for _, s := range seedURLs {
			u, err := url.Parse(s)
			if err != nil {
				continue
			}
			skip := false
			for d := range obeyDisallows {
				if strings.HasPrefix(u.Path, d) {
					skip = true
					break
				}
			}
			if !skip {
				filtered = append(filtered, s)
			}
		}
		seedURLs = filtered
	}

	tasks := make(chan string, len(seedURLs)+1000)
	results := make(chan DirFinding, 4096)
	wg := &sync.WaitGroup{}
	if concurrency <= 0 {
		concurrency = 20
	}
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go dirProbeWorker(client, ua, baselineBody, tasks, results, wg)
	}

	for _, s := range seedURLs {
		tasks <- s
	}
	for _, j := range jsCandidates {
		tasks <- j
	}

	close(tasks)

	go func() {
		wg.Wait()
		close(results)
	}()

	findings := []DirFinding{}
	for f := range results {
		findings = append(findings, f)
	}
	sort.Slice(findings, func(i, j int) bool {
		rank := map[string]int{"high": 3, "medium": 2, "low": 1}
		return rank[findings[i].Confidence] > rank[findings[j].Confidence]
	})
	report.Findings = findings
	report.Stats["total_findings"] = len(findings)
	return report, nil
}

// ---------- Scan flags type ----------
type ScanFlags struct {
	subdomains, whois, httpHeaders, dns, ports, geoIP, metadata, reverseIP, social, proxy, collectURLs, mail, js bool
	jsFetchSourcemaps                                                                                            bool
	proxyCheck                                                                                                   string
	portsTop                                                                                                     int
	portsRange                                                                                                   string
	portTimeout                                                                                                  int
	sni                                                                                                          string
	mailActive                                                                                                   bool
	mailAllowVerify                                                                                              bool
	mailSMTPTimeout                                                                                              int // seconds
	mailHTTPTimeout                                                                                              int // seconds
	mailRDAPTimeout                                                                                              int // seconds
	mailProbeConcurrency                                                                                         int
	mailInputsConcurrency                                                                                        int
	// directory flags
	dirEnabled       bool
	dirWordlist      string
	dirConcurrency   int
	dirTimeout       int
	dirFollowSitemap bool
	dirFetchJS       bool
	dirUserAgent     string

	// NEW flags
	RateLimit         int
	Jitter            float64
	Retries           int
	UA                string
	UAFile            string
	UAList            []string
	Modules           string // comma list
	Profile           string
	Exclude           string
	OutputDir         string
	DryRun            bool
	DisableActive     bool
	ObeyRobots        bool
	ModuleConcurrency int

	// dir extras
	DirExtensions string
	DirDepth      int

	// port tuning
	PortWorkers   int
	BannerTimeout int
	// severity filter
	IncludeSeverity string

	// Parameter / Dork / Fuzz flags (new)
	parameter        bool
	paramWordlist    string
	paramConcurrency int
	dork             bool
	dorkQuery        string
	fuzzing          bool
	fuzzWordlist     string
	fuzzConcurrency  int

	// Endpoint flags
	endpoints             bool
	endpointsConcurrency  int
	endpointsMaxBodyKB    int
	endpointsGraphQLProbe bool
}

// global flags holder so PrintToConsole can know dir flags
var flagsGlobal ScanFlags

// helper to check if dir printing enabled
func flagsDirEnabled(f *ScanFlags) bool {
	return f != nil && f.dirEnabled
}

// map internal js.JSReport -> local JSReport
func mapExternalToLocal(ext *js.JSReport) *JSReport {
	if ext == nil {
		return nil
	}
	out := &JSReport{PageURL: ext.PageURL}
	for _, es := range ext.ExternalScripts {
		if es.URL != "" {
			out.Scripts = append(out.Scripts, es.URL)
		}
	}
	out.InlineScriptsCount = len(ext.InlineScripts)
	for _, in := range ext.InlineScripts {
		if in.Snippet != "" {
			out.InlineSnippets = append(out.InlineSnippets, in.Snippet)
		}
	}
	for _, sm := range ext.SourceMaps {
		if sm.URL != "" {
			out.SourceMaps = append(out.SourceMaps, sm.URL)
		}
	}
	addEvidence := func(src []js.Evidence, dst *[]string) {
		for _, e := range src {
			line := ""
			if e.Context != "" {
				line = fmt.Sprintf("[%s] %s", e.Context, e.Snippet)
			} else {
				line = e.Snippet
			}
			*dst = append(*dst, line)
		}
	}
	addEvidence(ext.KeysTokens, &out.Secrets)
	addEvidence(ext.APIs, &out.APIs)
	addEvidence(ext.GraphQLEndpoints, &out.GraphQLEndpoints)
	addEvidence(ext.WebSockets, &out.WebSockets)
	addEvidence(ext.Trackers, &out.Trackers)
	addEvidence(ext.Frameworks, &out.Frameworks)
	addEvidence(ext.DangerousPatterns, &out.DangerousPatterns)
	addEvidence(ext.ObfuscationSigns, &out.ObfuscationSigns)
	addEvidence(ext.StorageUsage, &out.StorageUsage)
	addEvidence(ext.CryptoUsage, &out.CryptoUsage)
	addEvidence(ext.RegexPatterns, &out.RegexPatterns)
	addEvidence(ext.Dependencies, &out.Dependencies)
	addEvidence(ext.ErrorsAndLogs, &out.ErrorsAndLogs)
	addEvidence(ext.OSINT, &out.OSINT)
	addEvidence(ext.CommentsTodos, &out.CommentsTodos)
	if len(ext.Notes) > 0 {
		out.Notes = append(out.Notes, ext.Notes...)
	}
	return out
}

// helper to load UA list from file or single UA flag
func loadUAList(singleUA, file string) []string {
	out := []string{}
	if singleUA != "" {
		out = append(out, singleUA)
	}
	if file != "" {
		f, err := os.Open(file)
		if err == nil {
			defer f.Close()
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" {
					continue
				}
				out = append(out, line)
			}
		}
	}
	if len(out) == 0 {
		out = append(out, "ReconNio/1.0")
	}
	return out
}

func scanTarget(target string, flags ScanFlags) ScanResults {
	isIP := stdnet.ParseIP(target) != nil
	results := ScanResults{
		Target:     target,
		DNSRecords: map[string][]string{},
		Headers:    map[string][]string{},
		Timestamp:  time.Now().Format(time.RFC3339),
		JS:         &JSReport{},
	}

	if flags.DryRun {
		fmt.Printf("[dry-run] planned modules for %s: modules=%s\n", target, flags.Modules)
		planned := strings.Split(flags.Modules, ",")
		for _, m := range planned {
			m = strings.TrimSpace(m)
			if m == "" {
				continue
			}
			fmt.Printf("  - %s\n", m)
		}
		results.Timestamp = time.Now().Format(time.RFC3339)
		return results
	}

	// Subdomains (only for domains)
	if flags.subdomains && !isIP {
		fmt.Println("[*] Subdomain enumeration:", target)
		if flags.DisableActive {
			fmt.Println("  (active probes disabled)")
		}
		subs, _ := discoverSubdomains(target)
		results.Subdomains = subs
	}

	if flags.whois && !flags.DisableActive {
		fmt.Println("[*] WHOIS lookup:", target)
		whois.LookupDomain(target)
	}

	// HTTP headers (domain). Uses ReconHTTP for richer info.
	if flags.httpHeaders && !isIP {
		fmt.Println("[*] Fetching HTTP headers & page info:", target)
		if report, err := reconhttp.ReconHTTP(target); err == nil {
			results.Headers = report.Headers
			reqHeaders := map[string]string{}
			if report.RequestHeaders != nil {
				for k, vals := range report.RequestHeaders {
					reqHeaders[k] = strings.Join(vals, ", ")
				}
			}
			results.HTTPRequest = &HTTPRequestInfo{
				Method:  report.RequestMethod,
				URL:     report.RequestURL,
				Headers: reqHeaders,
			}
			results.HTTPResponse = &HTTPResponseInfo{
				StatusCode:      report.StatusCode,
				Headers:         report.Headers,
				Title:           report.Title,
				Server:          report.Server,
				XPoweredBy:      report.XPoweredBy,
				SecurityHeaders: report.SecurityHeaders,
				ResponseTimeMS:  report.ResponseTimeMS,
				Redirects:       report.Redirects,
				TLS:             report.TLS,
				AllowedMethods:  report.AllowedMethods,
				Cookies:         report.Cookies,
				MetaTags:        report.MetaTags,
				JsFiles:         report.JsFiles,
				Comments:        report.Comments,
				FaviconSHA1:     report.FaviconSHA1,
				PageSize:        report.PageSize,
				Compressed:      report.Compressed,
				DirectoryHits:   report.DirectoryHits,
				OpenRedirects:   report.OpenRedirects,
				CORS:            report.CORS,
				TechCMS:         report.TechCMS,
				TechFramework:   report.TechFramework,
				WAFs:            report.WAFs,
				HTTP2:           report.HTTP2,
				HTTP3Hint:       report.HTTP3Hint,
				Protocols:       report.Protocols,
			}
		} else {
			fmt.Println("  http headers error:", err)
		}
	}

	// DNS records (domain)
	if flags.dns && !isIP {
		fmt.Println("[*] Fetching DNS records:", target)
		if recs, err := dns.FetchRecords(target); err == nil {
			results.DNSRecords = recs
		} else {
			fmt.Println("  dns error:", err)
		}
	}

	// Port scan (domain or IP)
	if flags.ports {
		fmt.Println("[*] Port scanning:", target)
		timeout := time.Duration(flags.portTimeout) * time.Second
		var portsToScan []int

		if flags.portsRange != "" {
			portsToScan = parsePortsRangeOrList(flags.portsRange)
			if len(portsToScan) == 0 {
				fmt.Printf("  invalid ports-range: %s (falling back to default internal scanner)\n", flags.portsRange)
			}
		} else if flags.portsTop > 0 {
			n := flags.portsTop
			if n < 1 {
				n = 1
			}
			if n > 65535 {
				n = 65535
			}
			portsToScan = make([]int, 0, n)
			for i := 1; i <= n; i++ {
				portsToScan = append(portsToScan, i)
			}
		}

		if len(portsToScan) == 0 {
			open, err := ports.ScanPorts(target, timeout)
			if err != nil {
				fmt.Println("  ports error:", err)
			} else {
				results.OpenPorts = open
				for _, p := range open {
					results.PortDetails = append(results.PortDetails, PortResult{
						Port:     p,
						Open:     true,
						Service:  serviceByPort(p),
						Banner:   "",
						Protocol: "tcp",
					})
				}
			}
		} else {
			prResults, err := scanPortsCustom(target, portsToScan, timeout, flags.sni)
			if err != nil {
				fmt.Println("  ports error:", err)
				if open, err2 := ports.ScanPorts(target, timeout); err2 == nil {
					results.OpenPorts = open
					for _, p := range open {
						results.PortDetails = append(results.PortDetails, PortResult{
							Port:     p,
							Open:     true,
							Service:  serviceByPort(p),
							Banner:   "",
							Protocol: "tcp",
						})
					}
				}
			} else {
				for _, pr := range prResults {
					if pr.Open {
						results.OpenPorts = append(results.OpenPorts, pr.Port)
					}
					results.PortDetails = append(results.PortDetails, pr)
				}
				sort.Ints(results.OpenPorts)
			}
		}
	}

	// Geolocation (ISP registration) — domain or IP
	if flags.geoIP {
		fmt.Println("[*] Geolocation lookup (ISP registration):", target)
		if info, err := geolocation.LookupISPRegistrationLocation(target); err == nil {
			results.Geo = info
		} else {
			fmt.Println("  geolocation error:", err)
		}
	}

	// Reverse IP
	if flags.reverseIP {
		fmt.Println("[*] Reverse IP lookup:", target)
		if r, err := reverseip.Lookup(target); err == nil {
			results.ReverseIP = r
		} else {
			fmt.Println("  reverseip error:", err)
		}
	}

	// Social (detailed)
	if flags.social && !isIP {
		username := strings.Split(target, ".")[0]
		fmt.Println("[*] Social handles check for:", username)

		profiles, err := social.CheckHandlesAdvanced(username)
		if err != nil {
			fmt.Println("  social error (advanced):", err)
			if simple, err2 := social.CheckHandles(username); err2 == nil {
				for _, r := range simple {
					if r.Exists {
						results.URLs = append(results.URLs, fmt.Sprintf("%s -> %s", r.Platform, r.URL))
					}
				}
			}
		} else {
			results.SocialProfiles = profiles
			for _, p := range profiles {
				if p.Exists {
					results.URLs = append(results.URLs, fmt.Sprintf("%s -> %s", p.Platform, p.URL))
				}
			}
		}
	}

	// Proxy gathering & validation
	if flags.proxy {
		fmt.Println("[*] Fetching & validating proxies...")
		if proxies, err := proxy.GetValidProxies(); err == nil {
			results.Proxies = proxies
		} else {
			fmt.Println("  proxy error:", err)
		}
	}

	// Metadata extraction (best-effort)
	if flags.metadata && !isIP {
		fmt.Println("[*] Extracting metadata:", target)
		meta, err := metadata.FetchMetadata(target)
		if err == nil {
			results.Metadata = meta
		} else {
			fmt.Println("  metadata error:", err)
		}
	}

	// Proxy access check
	if flags.proxyCheck != "" {
		fmt.Println("[*] Checking proxy access to:", flags.proxyCheck)
		if ps, err := proxy.FastFetchProxies(); err == nil {
			_ = proxy.UltraFastValidate(ps)
		} else {
			fmt.Println("  proxy fetch error:", err)
		}
	}

	// URL collection (domain)
	if flags.collectURLs && !isIP {
		fmt.Println("[*] Collecting URLs:", target)
		if urls, err := urlcollector.CollectURLs(target); err == nil {
			results.URLs = urls
		} else {
			fmt.Println("  urlcollector error:", err)
		}
	}

	// Mail recon — run for domains, URLs and IPs
	if flags.mail && !flags.DisableActive {
		fmt.Println("[*] Mail reconnaissance:", target)
		opts := mail.MailOptions{
			Active:                 flags.mailActive,
			AllowMailboxValidation: flags.mailAllowVerify,
			SMTPTimeout:            time.Duration(flags.mailSMTPTimeout) * time.Second,
			SMTPPorts:              []int{25, 587},
			HTTPTimeout:            time.Duration(flags.mailHTTPTimeout) * time.Second,
			RDAPTimeout:            time.Duration(flags.mailRDAPTimeout) * time.Second,
			FetchMtaStsPolicy:      true,
			ProbeConcurrency:       flags.mailProbeConcurrency,
			InputsConcurrency:      flags.mailInputsConcurrency,
		}
		mr, err := mail.FetchMailInfo(target, opts)
		if err != nil {
			fmt.Println("  mail recon error:", err)
		} else {
			results.Mail = mr
		}
	} else if flags.mail && flags.DisableActive {
		fmt.Println("  mail recon skipped (active disabled).")
	}

	// Directory scan
	if flags.dirEnabled {
		fmt.Println("[*] Directory / content discovery:", target)
		exts := []string{}
		if flags.DirExtensions != "" {
			for _, e := range strings.Split(flags.DirExtensions, ",") {
				e = strings.TrimSpace(e)
				if e == "" {
					continue
				}
				if !strings.HasPrefix(e, ".") {
					e = "." + e
				}
				exts = append(exts, e)
			}
		}
		dr, err := runDirectoryScan(target, flags.dirWordlist, flags.dirConcurrency, flags.dirTimeout, flags.dirFollowSitemap, flags.dirFetchJS, flags.dirUserAgent, exts, flags.DirDepth, flags.ObeyRobots)
		if err != nil {
			fmt.Println("  directory scan error:", err)
		} else {
			results.Directory = dr
		}
	}

	// JS reconnaissance: use internal JS.FetchJSInfo once and map results to local JSReport.
	if flags.js {
		fmt.Println("[*] JavaScript reconnaissance:", target)
		inputForFetch := target
		if !strings.HasPrefix(inputForFetch, "http://") && !strings.HasPrefix(inputForFetch, "https://") {
			inputForFetch = "https://" + target
		}
		opts := js.DefaultJSOptions()
		opts.FetchSourceMaps = flags.jsFetchSourcemaps
		reportExt, err := js.FetchJSInfo(inputForFetch, &opts)
		if err != nil {
			fmt.Println("  js.FetchJSInfo error:", err)
		} else {
			jloc := mapExternalToLocal(reportExt)
			results.JS = jloc
		}
	}

	// Parameter fuzzing / discovery (real call to perameter module)
	if flags.parameter {
		fmt.Println("[*] Parameter reconnaissance:", target)
		opts := perameter.Options{
			UA:               flags.UA,
			Enable:           true,
			DisableActive:    flags.DisableActive,
			JS:               flags.js,
			ParamWordlist:    flags.paramWordlist,
			ParamConcurrency: flags.paramConcurrency,
			TimeoutSec:       flags.dirTimeout,
		}
		pr, err := perameter.Run(target, opts)
		if err != nil {
			fmt.Println("  parameter module error:", err)
		} else {
			results.ParameterReport = pr
		}
	}

	// Dorking / Google dorks (placeholder)
	if flags.dork {
		fmt.Println("[*] Dorking / search-based discovery enabled (placeholder):", target)
		if flags.dorkQuery != "" {
			fmt.Printf("    query: %s\n", flags.dorkQuery)
		}
	}

	// Fuzzing module - generate human-friendly guide & per-target commands (non-destructive)
	if flags.fuzzing {
		fmt.Printf("[*] Fuzzing enabled — generating guide and tailored commands: %s\n\n", target)

		var info fuzzing.FuzzingInfo
		func() {
			defer func() {
				if r := recover(); r != nil {
					// fallback info (basic)
					info = fuzzing.FuzzingInfo{
						OneLiner: "Fuzzing: automated input generation to find crashes, hangs, memory bugs or logic errors.",
						Tools:    []fuzzing.Tool{},
					}
				}
			}()
			info = fuzzing.GetFuzzingInfo()
		}()

		planCommands := map[string]string{}

		safeTarget := target
		if strings.HasPrefix(safeTarget, "http://") || strings.HasPrefix(safeTarget, "https://") {
		} else {
			// keep as-is
		}

		planCommands["ffuf_paths"] = fmt.Sprintf("ffuf -c -w wordlists/common_paths.txt -u %s/FUZZ -mc 200,401,403 -t 40", safeTarget)
		planCommands["ffuf_params"] = fmt.Sprintf("ffuf -c -w wordlists/params.txt:FUZZ -u \"%s?FUZZ=TEST\" -t 40", safeTarget)
		planCommands["ffuf_vhost"] = fmt.Sprintf("ffuf -c -w wordlists/vhosts.txt -u https://%s/ -H \"Host: FUZZ.%s\" -mc 200 -t 40", safeTarget, safeTarget)
		planCommands["ffuf_recursive"] = fmt.Sprintf("ffuf -c -w wordlists/common_paths.txt -u %s/FUZZ -recursion -recursion-depth 2 -t 40", safeTarget)
		planCommands["ffuf_json_body"] = fmt.Sprintf("cat json_templates/sample.json | ffuf -c -t 20 -w payloads/json_payloads.txt -d @- -u %s -H 'Content-Type: application/json' -X POST", safeTarget)
		planCommands["ffuf_quick"] = fmt.Sprintf("ffuf -w wordlists/common_paths.txt -u %s/FUZZ -t 40 -mc 200,201,202,301,302,403", safeTarget)
		planCommands["ffuf_exts"] = fmt.Sprintf("ffuf -w wordlists/common_paths.txt -u %s/FUZZ -e .php,.html,.bak -t 40 -mc 200,403", safeTarget)
		planCommands["curl_param_poc"] = fmt.Sprintf("curl -s -i \"%s?param=PAYLOAD\" -H 'User-Agent: ReconNio-Fuzzer/1.0'", safeTarget)
		planCommands["radamsa_pipe"] = fmt.Sprintf("radamsa seed.bin | timeout 30s %s", safeTarget)
		planCommands["boofuzz_hint"] = "Python boofuzz harness: create a stateful session using boofuzz, model the protocol, then session.fuzz()"
		planCommands["libfuzzer_hint"] = "libFuzzer: build an in-process target with -fsanitize=fuzzer,address,undefined and run the binary (example: ./my_fuzzer -runs=0)"
		planCommands["afl_hint"] = "AFL: instrument build (afl-clang-fast), then run: afl-fuzz -i seeds/ -o findings/ -- ./target @@"

		// Print A→Z organized (compact, professional)
		fmt.Println("ReconNio - Report for", target)
		fmt.Println("Generated:", time.Now().Format(time.RFC3339))
		fmt.Println()
		fmt.Println("┌─ Fuzzing — A → Z (organized)")
		if info.OneLiner != "" {
			fmt.Printf("│  One-liner: %s\n", info.OneLiner)
		} else {
			fmt.Printf("│  One-liner: %s\n", "Fuzzing: automated input generation to find crashes, hangs, memory bugs or logic errors by feeding unexpected/modified inputs into a target and monitoring behavior.")
		}
		fmt.Println("│")
		// Top tools
		fmt.Println("│  Top tools (6):")
		for i, t := range info.Tools {
			if i >= 6 {
				break
			}
			if t.Name == "" {
				continue
			}
			desc := t.Description
			if desc == "" {
				desc = "(no description)"
			}
			fmt.Printf("│    - %s: %s\n", t.Name, desc)
			if t.Homepage != "" {
				fmt.Printf("│       %s\n", t.Homepage)
			}
		}
		if len(info.Tools) == 0 {
			// fallback list
			fmt.Println("│    - AFL / AFL++: coverage-guided fuzzer for instrumented binaries")
			fmt.Println("│    - libFuzzer: in-process fuzzing for LLVM-built targets")
			fmt.Println("│    - honggfuzz: alternative coverage-guided fuzzer")
			fmt.Println("│    - boofuzz: protocol/stateful fuzzing (python)")
			fmt.Println("│    - radamsa: mutation engine")
			fmt.Println("│    - ffuf: fast web fuzzer (paths/params)")
		}
		fmt.Println("│")
		// Workflows
		if len(info.Workflows) > 0 {
			fmt.Println("│  Workflows (short):")
			for _, w := range info.Workflows {
				fmt.Printf("│    - %s\n", w)
			}
		} else {
			fmt.Println("│  Workflows (short):")
			fmt.Println("│    - Binary fuzz (instrument with ASan/UBSan, seed corpus, run libFuzzer/AFL)")
			fmt.Println("│    - Web/API fuzz (path & param mutation, session handling, monitor responses)")
			fmt.Println("│    - Protocol fuzz (boofuzz grammar/stateful approach)")
		}
		fmt.Println("│")
		fmt.Println("│  Generated command templates (tailored):")
		// print high-value template first if present
		if v, ok := planCommands["ffuf_paths"]; ok {
			fmt.Println("│    # Path fuzz (ffuf):")
			fmt.Printf("│    %s\n", v)
			fmt.Println("│")
		}
		// Print rest (sorted for readability)
		keys := make([]string, 0, len(planCommands))
		for k := range planCommands {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			// skip the ffuf_paths again (already printed)
			if k == "ffuf_paths" {
				continue
			}
			fmt.Printf("│    - %s: %s\n", k, planCommands[k])
		}

		// references if available
		if len(info.References) > 0 {
			fmt.Println("│")
			fmt.Println("│  References (short):")
			i := 0
			for k, v := range info.References {
				if i >= 8 {
					break
				}
				fmt.Printf("│    - %s: %s\n", k, v)
				i++
			}
		} else {
			fmt.Println("│")
			fmt.Println("│  References (short):")
			fmt.Println("│    - AFL Documentation")
			fmt.Println("│    - libFuzzer docs")
			fmt.Println("│    - honggfuzz repo")
			fmt.Println("│    - boofuzz docs")
			fmt.Println("│    - radamsa README")
		}
		fmt.Println("└────────────────────────────")
		fmt.Println()
	}

	// Endpoint discovery (new)
	if flags.endpoints && !isIP {
		fmt.Println("[*] Endpoint discovery:", target)
		// build a client (reuse directory timeout or default)
		timeoutSec := flags.dirTimeout
		if timeoutSec <= 0 {
			timeoutSec = 8
		}
		client := buildStdClient(time.Duration(timeoutSec) * time.Second)

		// base URL
		base := target
		if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
			base = "https://" + strings.TrimSuffix(base, "/")
		}

		// root HTML: try to use already fetched HTTP response if available, otherwise fetch
		var rootHTML []byte
		// If we previously fetched HTTP headers with a body accessible elsewhere, that module doesn't store the body,
		// so we perform a lightweight fetch here (respecting DisableActive).
		if !flags.DisableActive {
			b, _, _, _, _, err := fetchURLSimple(client, base, "GET", int64(flags.endpointsMaxBodyKB*1024), flags.dirUserAgent)
			if err == nil {
				rootHTML = b
			}
		}

		// assemble JS files from various places
		jsFiles := []string{}
		if results.JS != nil && len(results.JS.Scripts) > 0 {
			jsFiles = append(jsFiles, results.JS.Scripts...)
		}
		if results.HTTPResponse != nil && len(results.HTTPResponse.JsFiles) > 0 {
			jsFiles = append(jsFiles, results.HTTPResponse.JsFiles...)
		}
		if results.Directory != nil && len(results.Directory.JSFiles) > 0 {
			jsFiles = append(jsFiles, results.Directory.JSFiles...)
		}
		jsFiles = dedupeStrings(jsFiles)

		// build options for endpoint discovery
		endOpts := ep.EndpointOptions{
			DisableActive:           flags.DisableActive,
			Concurrency:             flags.endpointsConcurrency,
			Client:                  client,
			UAList:                  flags.UAList,
			Retries:                 flags.Retries,
			MaxBody:                 int64(flags.endpointsMaxBodyKB * 1024),
			EnableLightGraphQLProbe: flags.endpointsGraphQLProbe,
			Jitter:                  flags.Jitter,
			SNI:                     flags.sni,
		}

		// call the endpoint discovery implementation
		endpoints, err := ep.DiscoverEndpoints(client, base, rootHTML, jsFiles, endOpts)
		if err != nil {
			fmt.Println("  endpoints error:", err)
		} else {
			results.Endpoints = endpoints
			// append endpoint URLs into general results.URLs for convenience (dedupe after)
			for _, e := range endpoints {
				results.URLs = append(results.URLs, e.URL)
			}
			results.URLs = dedupeStrings(results.URLs)
		}
	}

	return results
}

// ---------- Target parsing ----------
func parseTargets(domainFlag, targetsFile string) ([]string, error) {
	remaining := flag.Args()
	inputs := []string{}

	if domainFlag != "" {
		for _, part := range strings.Split(domainFlag, ",") {
			p := strings.TrimSpace(part)
			if p != "" {
				inputs = append(inputs, p)
			}
		}
	}

	for _, a := range remaining {
		for _, part := range strings.Split(a, ",") {
			p := strings.TrimSpace(part)
			if p != "" {
				inputs = append(inputs, p)
			}
		}
	}

	if targetsFile != "" {
		f, err := os.Open(targetsFile)
		if err != nil {
			return nil, fmt.Errorf("failed to open targets file: %v", err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, "#") {
				continue
			}
			inputs = append(inputs, line)
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("reading targets file: %v", err)
		}
	}

	if len(inputs) == 0 {
		return nil, fmt.Errorf("no targets provided; use -domain, positional args, or -targets-file")
	}

	out := []string{}
	seen := map[string]struct{}{}
	for _, in := range inputs {
		n := normalizeTargetInput(in)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid targets after normalization")
	}
	return out, nil
}

func normalizeTargetInput(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		if u, err := url.Parse(s); err == nil {
			if h := u.Hostname(); h != "" {
				return h
			}
		}
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	if idx := strings.IndexByte(s, '/'); idx != -1 {
		s = s[:idx]
	}
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimSuffix(s, "/")
	if strings.Contains(s, "@") {
		parts := strings.Split(s, "@")
		s = parts[len(parts)-1]
	}
	if strings.HasPrefix(s, "[") {
		if idx := strings.Index(s, "]"); idx != -1 {
			inside := s[1:idx]
			return inside
		}
	}
	if strings.Contains(s, ":") {
		parts := strings.Split(s, ":")
		if len(parts) == 2 {
			s = parts[0]
		}
	}
	return strings.TrimSpace(s)
}

// ---------- Apply profile (quick/standard/full/stealth) ----------
func applyProfile(p string, f *ScanFlags) {
	switch strings.ToLower(p) {
	case "quick":
		f.Modules = "http,dns,subdomains"
		f.RateLimit = 0
		f.Retries = 1
		f.Jitter = 0
		f.dirConcurrency = 10
	case "stealth":
		f.Modules = "http,dir,js"
		f.RateLimit = 2
		f.Jitter = 0.5
		f.Retries = 2
		f.dirConcurrency = 5
		f.DirDepth = 0
		f.ObeyRobots = true
	case "full":
		f.Modules = "subdomains,http,dns,ports,dir,js,mail,social,metadata,proxy"
		f.RateLimit = 0
		f.Retries = 3
		f.Jitter = 0
		f.dirConcurrency = 30
		f.DirDepth = 1
	default:
	}
}

//
// ---------- Helpers (stubs kept) ----------
//

func generateAndResolve(domain string, count int) []string {
	out := []string{}
	cands := []string{"dev", "staging", "test", "uat", "beta", "api", "m", "cdn", "static", "admin"}
	n := 0
	for _, p := range cands {
		if n >= count {
			break
		}
		h := p + "." + domain
		if ips, err := stdnet.LookupHost(h); err == nil && len(ips) > 0 {
			out = append(out, h)
			n++
		}
	}
	return out
}

func filterResolvable(subs []string, timeout int) ([]string, []string) {
	resolved := []string{}
	non := []string{}
	for _, s := range subs {
		if stdnet.ParseIP(s) != nil {
			resolved = append(resolved, s)
			continue
		}
		_, err := stdnet.LookupHost(s)
		if err == nil {
			resolved = append(resolved, s)
		} else {
			non = append(non, s)
		}
	}
	return resolved, non
}

// tryZoneTransfer tries AXFR against the NS records for domain.
func tryZoneTransfer(domain string, timeout time.Duration) ([]string, error) {
	nsRecords, err := stdnet.LookupNS(domain)
	if err != nil {
		return nil, fmt.Errorf("lookup NS failed: %w", err)
	}

	found := map[string]struct{}{}
	msg := new(mdns.Msg)
	msg.SetAxfr(mdns.Fqdn(domain))

	for _, ns := range nsRecords {
		addr := ns.Host
		if !strings.Contains(addr, ":") {
			addr = strings.TrimSuffix(addr, ".")
			addr = fmt.Sprintf("%s:53", addr)
		}
		tr := &mdns.Transfer{}
		ch, err := tr.In(msg, addr)
		if err != nil {
			continue
		}
		for env := range ch {
			if env.Error != nil {
				continue
			}
			for _, rr := range env.RR {
				name := strings.TrimSuffix(rr.Header().Name, ".")
				if name == domain || strings.HasSuffix(name, "."+domain) {
					found[name] = struct{}{}
				}
			}
		}
		if len(found) > 0 {
			break
		}
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("zone transfer not allowed or returned no useful data")
	}
	out := make([]string, 0, len(found))
	for s := range found {
		out = append(out, s)
	}
	return out, nil
}

// fetchFromCrtSh queries crt.sh JSON output for subdomains.
func fetchFromCrtSh(client *stdhttp.Client, domain string) ([]string, error) {
	u := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", url.QueryEscape(domain))
	body, code, err := httpGet(client, u)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request failed: %w", err)
	}
	if code != 200 {
		return nil, fmt.Errorf("crt.sh HTTP %d", code)
	}
	var rows []map[string]any
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("crt.sh json parse failed: %w", err)
	}
	out := map[string]struct{}{}
	for _, r := range rows {
		if name, ok := r["name_value"].(string); ok {
			for _, p := range strings.Split(name, "\n") {
				if h, ok := normalizeHost(p, domain); ok {
					out[h] = struct{}{}
				}
			}
		}
	}
	res := make([]string, 0, len(out))
	for s := range out {
		res = append(res, s)
	}
	return res, nil
}

// fetchFromAlienVault uses OTX passive_dns API
func fetchFromAlienVault(client *stdhttp.Client, domain string) ([]string, error) {
	u := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", url.PathEscape(domain))
	body, code, err := httpGet(client, u)
	if err != nil {
		return nil, fmt.Errorf("alienvault request failed: %w", err)
	}
	if code != 200 {
		return nil, fmt.Errorf("alienvault HTTP %d", code)
	}
	var resp struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("alienvault json parse failed: %w", err)
	}
	set := map[string]struct{}{}
	for _, p := range resp.PassiveDNS {
		if h, ok := normalizeHost(p.Hostname, domain); ok {
			set[h] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	return out, nil
}

// fetchFromBufferOver queries dns.bufferover.run
func fetchFromBufferOver(client *stdhttp.Client, domain string) ([]string, error) {
	u := fmt.Sprintf("https://dns.bufferover.run/dns?q=.%s", url.QueryEscape(domain))
	body, code, err := httpGet(client, u)
	if err != nil {
		return nil, fmt.Errorf("bufferover request failed: %w", err)
	}
	if code != 200 {
		return nil, fmt.Errorf("bufferover HTTP %d", code)
	}
	var parsed struct {
		FDNSA []string `json:"FDNS_A"`
		FDNSC []string `json:"FDNS_CNAME"`
		RDNS  []string `json:"RDNS"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("bufferover json parse failed: %w", err)
	}
	set := map[string]struct{}{}
	extract := func(rows []string) {
		for _, line := range rows {
			parts := strings.Split(line, ",")
			if len(parts) == 2 {
				if h, ok := normalizeHost(parts[1], domain); ok {
					set[h] = struct{}{}
				}
			}
		}
	}
	extract(parsed.FDNSA)
	extract(parsed.FDNSC)
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	return out, nil
}

// fetchFromHackerTarget uses hackertarget hostsearch endpoint
func fetchFromHackerTarget(client *stdhttp.Client, domain string) ([]string, error) {
	u := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", url.QueryEscape(domain))
	body, code, err := httpGet(client, u)
	if err != nil {
		return nil, fmt.Errorf("hackertarget request failed: %w", err)
	}
	if code != 200 {
		return nil, fmt.Errorf("hackertarget HTTP %d", code)
	}
	set := map[string]struct{}{}
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.Contains(line, "error") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) >= 1 {
			if h, ok := normalizeHost(parts[0], domain); ok {
				set[h] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	return out, nil
}

// fetchFromWayback queries web.archive.org CDX API for hosts
func fetchFromWayback(client *stdhttp.Client, domain string) ([]string, error) {
	u := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey", url.QueryEscape(domain))
	body, code, err := httpGet(client, u)
	if err != nil {
		return nil, fmt.Errorf("wayback request failed: %w", err)
	}
	if code != 200 {
		return nil, fmt.Errorf("wayback HTTP %d", code)
	}
	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("wayback json parse failed: %w", err)
	}
	set := map[string]struct{}{}
	for i, r := range rows {
		if i == 0 {
			continue
		}
		if len(r) == 0 {
			continue
		}
		u := r[0]
		if !strings.HasPrefix(u, "http") {
			u = "http://" + u
		}
		if parsed, err := url.Parse(u); err == nil {
			if h, ok := normalizeHost(parsed.Hostname(), domain); ok {
				set[h] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	return out, nil
}

// discoverSubdomains - uses multiple public sources and a generator to build a list
func discoverSubdomains(domain string) ([]string, map[string]string) {
	stats := map[string]string{}
	all := map[string]struct{}{}
	httpClient := &stdhttp.Client{Timeout: 12 * time.Second}

	if axfrSubs, axfrErr := tryZoneTransfer(domain, 6*time.Second); axfrErr == nil && len(axfrSubs) > 0 {
		stats["axfr"] = fmt.Sprintf("AXFR succeeded: %d", len(axfrSubs))
		for _, s := range axfrSubs {
			all[s] = struct{}{}
		}
	} else if axfrErr != nil {
		stats["axfr_error"] = axfrErr.Error()
	} else {
		stats["axfr"] = "AXFR returned none"
	}

	if subs, err := fetchFromCrtSh(httpClient, domain); err == nil {
		stats["crtsh"] = fmt.Sprintf("crt.sh: %d", len(subs))
		for _, s := range subs {
			all[s] = struct{}{}
		}
	} else {
		stats["crtsh_error"] = err.Error()
	}

	if subs, err := fetchFromAlienVault(httpClient, domain); err == nil {
		stats["alienvault"] = fmt.Sprintf("OTX: %d", len(subs))
		for _, s := range subs {
			all[s] = struct{}{}
		}
	} else {
		stats["alienvault_error"] = err.Error()
	}

	if subs, err := fetchFromBufferOver(httpClient, domain); err == nil {
		stats["bufferover"] = fmt.Sprintf("BufferOver: %d", len(subs))
		for _, s := range subs {
			all[s] = struct{}{}
		}
	} else {
		stats["bufferover_error"] = err.Error()
	}

	if subs, err := fetchFromHackerTarget(httpClient, domain); err == nil {
		stats["hackertarget"] = fmt.Sprintf("HackerTarget: %d", len(subs))
		for _, s := range subs {
			all[s] = struct{}{}
		}
	} else {
		stats["hackertarget_error"] = err.Error()
	}

	if subs, err := fetchFromWayback(httpClient, domain); err == nil {
		stats["wayback"] = fmt.Sprintf("Wayback: %d", len(subs))
		for _, s := range subs {
			all[s] = struct{}{}
		}
	} else {
		stats["wayback_error"] = err.Error()
	}

	genSubs := generateAndResolve(domain, 40)
	if len(genSubs) > 0 {
		stats["generated"] = fmt.Sprintf("generated & resolved: %d", len(genSubs))
		for _, s := range genSubs {
			all[s] = struct{}{}
		}
	} else {
		stats["generated"] = "generated none resolved"
	}

	allSlice := make([]string, 0, len(all))
	for s := range all {
		allSlice = append(allSlice, s)
	}
	sort.Strings(allSlice)

	res, non := filterResolvable(allSlice, 60)
	stats["resolved"] = fmt.Sprintf("%d", len(res))
	if len(non) > 0 {
		stats["unresolved_dropped"] = fmt.Sprintf("%d", len(non))
	}
	return res, stats
}

// scanPortsCustom does a simple TCP connect + banner/TLS handshake probes.
func scanPortsCustom(host string, portsToScan []int, timeout time.Duration, sni string) ([]PortResult, error) {
	results := make([]PortResult, 0, len(portsToScan))
	hostOnly := host
	if strings.HasPrefix(hostOnly, "http://") || strings.HasPrefix(hostOnly, "https://") {
		if u, err := url.Parse(hostOnly); err == nil {
			hostOnly = u.Hostname()
		}
	}

	for _, p := range portsToScan {
		pr := PortResult{Port: p, Open: false, Service: serviceByPort(p)}
		addr := fmt.Sprintf("%s:%d", hostOnly, p)
		dialer := &stdnet.Dialer{Timeout: timeout}
		conn, err := dialer.Dial("tcp", addr)
		if err != nil {
			pr.Open = false
			pr.Protocol = "tcp"
			results = append(results, pr)
			continue
		}

		pr.Open = true
		_ = conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))

		if p == 443 || p == 8443 || p == 9443 || p == 10443 {
			cfg := &tls.Config{InsecureSkipVerify: true}
			if sni != "" {
				cfg.ServerName = sni
			} else {
				cfg.ServerName = hostOnly
			}

			tconn := tls.Client(conn, cfg)
			_ = conn.SetDeadline(time.Now().Add(timeout))
			if err := tconn.Handshake(); err == nil {
				state := tconn.ConnectionState()
				pr.Protocol = "tls"
				pr.TLSVersion = tlsVersionName(state.Version)
				pr.TLSCipher = tls.CipherSuiteName(state.CipherSuite)
				_ = tconn.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
				buf := make([]byte, 2048)
				n, _ := tconn.Read(buf)
				if n > 0 {
					pr.Banner = strings.TrimSpace(string(buf[:n]))
				}
				_ = tconn.Close()
			} else {
				buf := make([]byte, 1024)
				n, _ := conn.Read(buf)
				if n > 0 {
					pr.Banner = strings.TrimSpace(string(buf[:n]))
				}
				_ = conn.Close()
			}
		} else {
			if p == 80 || p == 8080 || p == 8000 || p == 8008 || p == 8888 {
				req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: ReconNio/1.0\r\nConnection: close\r\n\r\n", hostOnly)
				_, _ = conn.Write([]byte(req))
				reader := bufio.NewReader(conn)
				line, _ := reader.ReadString('\n')
				if len(line) > 0 {
					pr.Protocol = "http"
					pr.Banner = strings.TrimSpace(line)
				} else {
					pr.Protocol = "tcp"
				}
			} else {
				buf := make([]byte, 2048)
				n, _ := conn.Read(buf)
				if n > 0 {
					pr.Banner = strings.TrimSpace(string(buf[:n]))
				}
				pr.Protocol = "tcp"
			}
			_ = conn.Close()
		}

		results = append(results, pr)
	}

	return results, nil
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
	}
	if s, ok := common[p]; ok {
		return s
	}
	return ""
}

func anyDirFlagSet(setFlags map[string]bool) bool {
	dirRelated := []string{"dir", "dir-fetch-js", "dir-follow-sitemap", "dir-wordlist", "dir-ua", "dir-concurrency", "dir-timeout"}
	for _, k := range dirRelated {
		if setFlags[k] {
			return true
		}
	}
	return false
}

// ---------- main ----------
func main() {
	// Custom help output: only the specific "Target selection" and "Core modules & flags" block
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: reconnio [flags] target1,target2,...\n\n")
		fmt.Fprintf(os.Stderr, "ReconNio — flexible recon & information gathering tool\n\n")

		fmt.Fprintf(os.Stderr, "Target selection:\n")
		fmt.Fprintf(os.Stderr, "  -domain string\n\tTarget domain (comma-separated allowed). If omitted, positional args are used.\n")
		fmt.Fprintf(os.Stderr, "  -targets-file string\n\tFile with one target per line (domain, URL or IP)\n\n")

		fmt.Fprintf(os.Stderr, "Core modules & flags:\n")
		fmt.Fprintf(os.Stderr, "  -concurrency int\n\tNumber of concurrent targets to scan (default 4)\n")
		fmt.Fprintf(os.Stderr, "  -dir\n\tRun Directory / Content Discovery\n")
		fmt.Fprintf(os.Stderr, "  -dir-concurrency int\n\tDirectory scan concurrency (default 20)\n")
		fmt.Fprintf(os.Stderr, "  -dir-depth int\n\tDirectory discovery depth (0=no extra, 1=combine two words)\n")
		fmt.Fprintf(os.Stderr, "  -dir-extensions string\n\tComma list of extra extensions for directory discovery, e.g. .bak,.old\n")
		fmt.Fprintf(os.Stderr, "  -dir-fetch-js\n\tFetch root HTML and JS files to extract endpoints (default false)\n")
		fmt.Fprintf(os.Stderr, "  -dir-follow-sitemap\n\tFollow sitemap.xml entries\n")
		fmt.Fprintf(os.Stderr, "  -dir-timeout int\n\tDirectory scan HTTP timeout seconds (default 8)\n")
		fmt.Fprintf(os.Stderr, "  -dir-ua string\n\tUser-Agent for directory probes (default \"ReconNio/Dir/1.0\")\n")
		fmt.Fprintf(os.Stderr, "  -dir-wordlist string\n\tPath to directory wordlist (one entry per line)\n")
		fmt.Fprintf(os.Stderr, "  -disable-active\n\tDisable active/intrusive probes (AXFR, active SMTP, mailbox verify)\n")
		fmt.Fprintf(os.Stderr, "  -dns\n\tFetch DNS records\n")
		fmt.Fprintf(os.Stderr, "  -domain string\n\tTarget domain (comma-separated allowed). If omitted, positional args are used.\n")
		fmt.Fprintf(os.Stderr, "  -dork\n\tEnable dorking/search-based discovery\n")
		fmt.Fprintf(os.Stderr, "  -dork-query string\n\tDork / search query to use for discovery\n")
		fmt.Fprintf(os.Stderr, "  -dry-run\n\tPlan actions but do not perform network requests\n")
		fmt.Fprintf(os.Stderr, "  -format string\n\tOutput format: json or normal (default \"normal\")\n")
		fmt.Fprintf(os.Stderr, "  -fuzz-concurrency int\n\tFuzzing concurrency (default 10)\n")
		fmt.Fprintf(os.Stderr, "  -fuzz-wordlist string\n\tPath to fuzzing wordlist\n")
		fmt.Fprintf(os.Stderr, "  -fuzzing\n\tEnable fuzzing module (paths/params)\n")
		fmt.Fprintf(os.Stderr, "  -geoip\n\tPerform ISP geolocation lookup on a given IP address or domain\n")
		fmt.Fprintf(os.Stderr, "  -httpheaders\n\tFetch HTTP headers (rich recon)\n")
		fmt.Fprintf(os.Stderr, "  -include-severity string\n\tFilter printed findings by severity (low,medium,high,all) (default \"all\")\n")
		fmt.Fprintf(os.Stderr, "  -jitter float\n\tMax jitter in seconds between requests\n")
		fmt.Fprintf(os.Stderr, "  -js\n\tPerform passive JavaScript reconnaissance (scripts, sourcemaps, keys, endpoints)\n")
		fmt.Fprintf(os.Stderr, "  -js-fetch-sourcemaps\n\tAttempt to fetch referenced source maps (may reveal original sources)\n")
		fmt.Fprintf(os.Stderr, "  -mail\n\tCollect mail infrastructure info (MX/SPF/DMARC/DKIM/etc.)\n")
		fmt.Fprintf(os.Stderr, "  -mail-active\n\tEnable active SMTP probing (STARTTLS/banner) — use with caution\n")
		fmt.Fprintf(os.Stderr, "  -mail-allow-verify\n\tAllow VRFY/RCPT mailbox checks (intrusive) — requires mail-active\n")
		fmt.Fprintf(os.Stderr, "  -mail-http-timeout int\n\tHTTP timeout (seconds) for MTA-STS / web probes (default 8)\n")
		fmt.Fprintf(os.Stderr, "  -mail-inputs-concurrency int\n\tConcurrency when processing multiple mail inputs (default 8)\n")
		fmt.Fprintf(os.Stderr, "  -mail-probe-concurrency int\n\tConcurrent SMTP probe workers (default 6)\n")
		fmt.Fprintf(os.Stderr, "  -mail-rdap-timeout int\n\tRDAP timeout (seconds) (default 8)\n")
		fmt.Fprintf(os.Stderr, "  -mail-smtp-timeout int\n\tSMTP timeout (seconds) for active probes (default 8)\n")
		fmt.Fprintf(os.Stderr, "  -metadata\n\tExtract metadata from public documents\n")
		fmt.Fprintf(os.Stderr, "  -module-concurrency int\n\tPer-module worker concurrency default (default 20)\n")
		fmt.Fprintf(os.Stderr, "  -modules string\n\tComma list of modules to run (subdomains,http,dns,ports,dir,js,mail,social,metadata,proxy). Default from profile or flags.\n")
		fmt.Fprintf(os.Stderr, "  -obey-robots\n\tRespect robots.txt disallow rules for directory scanning\n")
		fmt.Fprintf(os.Stderr, "  -output string\n\tOutput file base name (per-target files will be created)\n")
		fmt.Fprintf(os.Stderr, "  -output-dir string\n\tOutput directory for per-target files\n")
		fmt.Fprintf(os.Stderr, "  -param-concurrency int\n\tConcurrency for parameter fuzzing workers (default 10)\n")
		fmt.Fprintf(os.Stderr, "  -param-wordlist string\n\tParameter wordlist path\n")
		fmt.Fprintf(os.Stderr, "  -parameter\n\tEnable parameter fuzzing / discovery\n")
		fmt.Fprintf(os.Stderr, "  -port-timeout int\n\tTimeout in seconds for each port connection attempt (default 1)\n")
		fmt.Fprintf(os.Stderr, "  -ports\n\tPerform port scan\n")
		fmt.Fprintf(os.Stderr, "  -ports-range string\n\tScan custom ports/ranges. Examples: '1-1000' or '22,80,443' or '22,80,1000-2000'\n")
		fmt.Fprintf(os.Stderr, "  -ports-top int\n\tScan first N ports (1..N). e.g. -ports-top=1000\n")
		fmt.Fprintf(os.Stderr, "  -profile string\n\tScan profile: quick|standard|full|stealth\n")
		fmt.Fprintf(os.Stderr, "  -proxy\n\tFetch public proxy lists and validate them\n")
		fmt.Fprintf(os.Stderr, "  -proxycheck string\n\tCheck proxies for access to a given domain\n")
		fmt.Fprintf(os.Stderr, "  -rate-limit int\n\tGlobal request rate limit (requests per second). 0 = unlimited\n")
		fmt.Fprintf(os.Stderr, "  -retries int\n\tRetry attempts for transient HTTP errors (default 1)\n")
		fmt.Fprintf(os.Stderr, "  -reverseip\n\tPerform reverse IP lookup\n")
		fmt.Fprintf(os.Stderr, "  -sni string\n\tOptional SNI hostname to use for TLS handshakes (useful when scanning IPs)\n")
		fmt.Fprintf(os.Stderr, "  -social\n\tCheck for username availability on social media platforms\n")
		fmt.Fprintf(os.Stderr, "  -subdomains\n\tFind subdomains (AXFR, crt.sh, generator)\n")
		fmt.Fprintf(os.Stderr, "  -targets-file string\n\tFile with one target per line (domain, URL or IP)\n")
		fmt.Fprintf(os.Stderr, "  -ua string\n\tUser-Agent string to use\n")
		fmt.Fprintf(os.Stderr, "  -ua-file string\n\tFile with user-agents, one per line (enables rotation)\n")
		fmt.Fprintf(os.Stderr, "  -ua-list string\n\talias of -ua-file (keeps compat)\n")
		fmt.Fprintf(os.Stderr, "  -url\n\tCollect all types of URLs from the target\n")
		fmt.Fprintf(os.Stderr, "  -whois\n\tPerform WHOIS lookup\n")
		// endpoints help
		fmt.Fprintf(os.Stderr, "  -endpoints\n\tDiscover and probe endpoints extracted from HTML, JS, sitemaps and directory findings\n")
		fmt.Fprintf(os.Stderr, "  -endpoints-concurrency int\n\tEndpoint probe concurrency (default 12)\n")
		fmt.Fprintf(os.Stderr, "  -endpoints-maxbody int\n\tMax body (KB) to read when probing endpoints (default 128 KB)\n")
		fmt.Fprintf(os.Stderr, "  -endpoints-graphql\n\tAttempt a light GraphQL introspection probe (active; use with caution)\n")
	}

	// CLI Flags
	domainFlag := flag.String("domain", "", "Target domain (comma-separated allowed). If omitted, positional args are used.")
	targetsFile := flag.String("targets-file", "", "File with one target per line (domain, URL or IP)")
	whoisFlag := flag.Bool("whois", false, "Perform WHOIS lookup")
	subdomainsFlag := flag.Bool("subdomains", false, "Find subdomains (AXFR, crt.sh, generator)")
	httpHeadersFlag := flag.Bool("httpheaders", false, "Fetch HTTP headers (rich recon)")
	dnsFlag := flag.Bool("dns", false, "Fetch DNS records")
	portsFlag := flag.Bool("ports", false, "Perform port scan")
	geoFlag := flag.Bool("geoip", false, "Perform ISP geolocation lookup on a given IP address or domain")
	metadataFlag := flag.Bool("metadata", false, "Extract metadata from public documents")
	reverseIPFlag := flag.Bool("reverseip", false, "Perform reverse IP lookup")
	socialFlag := flag.Bool("social", false, "Check for username availability on social media platforms")
	proxyFlag := flag.Bool("proxy", false, "Fetch public proxy lists and validate them")
	proxyCheck := flag.String("proxycheck", "", "Check proxies for access to a given domain")
	collectURLs := flag.Bool("url", false, "Collect all types of URLs from the target")
	mailFlag := flag.Bool("mail", false, "Collect mail infrastructure info (MX/SPF/DMARC/DKIM/etc.)")
	mailActive := flag.Bool("mail-active", false, "Enable active SMTP probing (STARTTLS/banner) — use with caution")
	mailAllowVerify := flag.Bool("mail-allow-verify", false, "Allow VRFY/RCPT mailbox checks (intrusive) — requires mail-active")
	mailSMTPTimeout := flag.Int("mail-smtp-timeout", 8, "SMTP timeout (seconds) for active probes")
	mailHTTPTimeout := flag.Int("mail-http-timeout", 8, "HTTP timeout (seconds) for MTA-STS / web probes")
	mailRDAPTimeout := flag.Int("mail-rdap-timeout", 8, "RDAP timeout (seconds)")
	mailProbeConcurrency := flag.Int("mail-probe-concurrency", 6, "Concurrent SMTP probe workers")
	mailInputsConcurrency := flag.Int("mail-inputs-concurrency", 8, "Concurrency when processing multiple mail inputs")
	jsFlag := flag.Bool("js", false, "Perform passive JavaScript reconnaissance (scripts, sourcemaps, keys, endpoints)")
	jsFetchSourcemaps := flag.Bool("js-fetch-sourcemaps", false, "Attempt to fetch referenced source maps (may reveal original sources)")
	flag.StringVar(&outputFormat, "format", "normal", "Output format: json or normal")
	flag.StringVar(&outputFile, "output", "", "Output file base name (per-target files will be created)")
	concurrency := flag.Int("concurrency", defaultConcurrency, "Number of concurrent targets to scan")
	portsTop := flag.Int("ports-top", 0, "Scan first N ports (1..N). e.g. -ports-top=1000")
	portsRange := flag.String("ports-range", "", "Scan custom ports/ranges. Examples: '1-1000' or '22,80,443' or '22,80,1000-2000'")
	portTimeout := flag.Int("port-timeout", 1, "Timeout in seconds for each port connection attempt")
	sniHost := flag.String("sni", "", "Optional SNI hostname to use for TLS handshakes (useful when scanning IPs)")

	// Directory flags
	dirFlag := flag.Bool("dir", false, "Run Directory / Content Discovery")
	dirWordlist := flag.String("dir-wordlist", "", "Path to directory wordlist (one entry per line)")
	dirConcurrency := flag.Int("dir-concurrency", 20, "Directory scan concurrency")
	dirTimeout := flag.Int("dir-timeout", 8, "Directory scan HTTP timeout seconds")
	dirFollowSitemap := flag.Bool("dir-follow-sitemap", false, "Follow sitemap.xml entries")
	dirFetchJS := flag.Bool("dir-fetch-js", false, "Fetch root HTML and JS files to extract endpoints (default false)")
	dirUA := flag.String("dir-ua", "ReconNio/Dir/1.0", "User-Agent for directory probes")

	// Endpoint flags
	endpointsFlag := flag.Bool("endpoints", false, "Discover and probe endpoints (HTML, JS, sitemaps, dir)")
	endpointsConcurrency := flag.Int("endpoints-concurrency", 12, "Endpoint probe concurrency")
	endpointsMaxBodyKB := flag.Int("endpoints-maxbody", 128, "Max body (KB) to read when probing endpoints")
	endpointsGraphQL := flag.Bool("endpoints-graphql", false, "Attempt light GraphQL introspection (active)")

	// NEW flags
	modules := flag.String("modules", "", "Comma list of modules to run (subdomains,http,dns,ports,dir,js,mail,social,metadata,proxy). Default from profile or flags.")
	profile := flag.String("profile", "", "Scan profile: quick|standard|full|stealth")
	rateLimit := flag.Int("rate-limit", 0, "Global request rate limit (requests per second). 0 = unlimited")
	jitter := flag.Float64("jitter", 0.0, "Max jitter in seconds between requests")
	retries := flag.Int("retries", 1, "Retry attempts for transient HTTP errors")
	ua := flag.String("ua", "", "User-Agent string to use")
	uaFile := flag.String("ua-file", "", "File with user-agents, one per line (enables rotation)")
	outputDir := flag.String("output-dir", "", "Output directory for per-target files")
	dryRun := flag.Bool("dry-run", false, "Plan actions but do not perform network requests")
	disableActive := flag.Bool("disable-active", false, "Disable active/intrusive probes (AXFR, active SMTP, mailbox verify)")
	obeyRobots := flag.Bool("obey-robots", false, "Respect robots.txt disallow rules for directory scanning")
	dirExtensions := flag.String("dir-extensions", "", "Comma list of extra extensions for directory discovery, e.g. .bak,.old")
	dirDepth := flag.Int("dir-depth", 0, "Directory discovery depth (0=no extra, 1=combine two words)")
	includeSeverity := flag.String("include-severity", "all", "Filter printed findings by severity (low,medium,high,all) (default \"all\")")
	rateLimitModuleConcurrency := flag.Int("module-concurrency", 20, "Per-module worker concurrency default")
	uaListFlag := flag.String("ua-list", "", "alias of -ua-file (keeps compat)")

	// Parameter / Dork / Fuzz flags
	parameterFlag := flag.Bool("parameter", false, "Enable parameter fuzzing / discovery")
	paramWordlist := flag.String("param-wordlist", "", "Parameter wordlist path")
	paramConcurrency := flag.Int("param-concurrency", 10, "Concurrency for parameter fuzzing workers")
	dorkFlag := flag.Bool("dork", false, "Enable dorking/search-based discovery")
	dorkQuery := flag.String("dork-query", "", "Dork / search query to use for discovery")
	fuzzingFlag := flag.Bool("fuzzing", false, "Enable fuzzing module (paths/params)")
	fuzzWordlist := flag.String("fuzz-wordlist", "", "Path to fuzzing wordlist")
	fuzzConcurrency := flag.Int("fuzz-concurrency", 10, "Fuzzing concurrency")

	flag.Parse()

	// detect which flags were explicitly set by the user
	setFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = true
	})

	// AUTO-ENABLE - only when user explicitly set a dir-related flag or -dir itself
	dirOptsUsed := anyDirFlagSet(setFlags)
	if dirOptsUsed {
		if !*dirFlag {
			*dirFlag = true
			fmt.Println("[*] Note: a directory-related flag was specified — auto-enabled -dir for this run")
		}
	}

	// build ScanFlags bundle
	flagBundle := ScanFlags{
		subdomains:            *subdomainsFlag,
		whois:                 *whoisFlag,
		httpHeaders:           *httpHeadersFlag,
		dns:                   *dnsFlag,
		ports:                 *portsFlag,
		geoIP:                 *geoFlag,
		metadata:              *metadataFlag,
		reverseIP:             *reverseIPFlag,
		social:                *socialFlag,
		proxy:                 *proxyFlag,
		collectURLs:           *collectURLs,
		proxyCheck:            *proxyCheck,
		portsTop:              *portsTop,
		portsRange:            *portsRange,
		portTimeout:           *portTimeout,
		sni:                   *sniHost,
		mail:                  *mailFlag,
		mailActive:            *mailActive,
		mailAllowVerify:       *mailAllowVerify,
		mailSMTPTimeout:       *mailSMTPTimeout,
		mailHTTPTimeout:       *mailHTTPTimeout,
		mailRDAPTimeout:       *mailRDAPTimeout,
		mailProbeConcurrency:  *mailProbeConcurrency,
		mailInputsConcurrency: *mailInputsConcurrency,
		js:                    *jsFlag,
		jsFetchSourcemaps:     *jsFetchSourcemaps,
		dirEnabled:            *dirFlag,
		dirWordlist:           *dirWordlist,
		dirConcurrency:        *dirConcurrency,
		dirTimeout:            *dirTimeout,
		dirFollowSitemap:      *dirFollowSitemap,
		dirFetchJS:            *dirFetchJS,
		dirUserAgent:          *dirUA,

		// NEW
		RateLimit:         *rateLimit,
		Jitter:            *jitter,
		Retries:           *retries,
		UA:                *ua,
		UAFile:            *uaFile,
		Modules:           *modules,
		Profile:           *profile,
		OutputDir:         *outputDir,
		DryRun:            *dryRun,
		DisableActive:     *disableActive,
		ObeyRobots:        *obeyRobots,
		DirExtensions:     *dirExtensions,
		DirDepth:          *dirDepth,
		IncludeSeverity:   *includeSeverity,
		ModuleConcurrency: *rateLimitModuleConcurrency,

		// Endpoint flags
		endpoints:             *endpointsFlag,
		endpointsConcurrency:  *endpointsConcurrency,
		endpointsMaxBodyKB:    *endpointsMaxBodyKB,
		endpointsGraphQLProbe: *endpointsGraphQL,
	}

	// UA list compatibility
	if *uaListFlag != "" && flagBundle.UAFile == "" {
		flagBundle.UAFile = *uaListFlag
	}

	// apply profile if set
	if flagBundle.Profile != "" {
		applyProfile(flagBundle.Profile, &flagBundle)
	}

	// if -modules specified, enable modules based on it (overrides some flags)
	if flagBundle.Modules != "" {
		m := strings.Split(flagBundle.Modules, ",")
		for _, mod := range m {
			switch strings.ToLower(strings.TrimSpace(mod)) {
			case "subdomains":
				flagBundle.subdomains = true
			case "http":
				flagBundle.httpHeaders = true
			case "dns":
				flagBundle.dns = true
			case "ports":
				flagBundle.ports = true
			case "dir":
				flagBundle.dirEnabled = true
			case "js":
				flagBundle.js = true
			case "mail":
				flagBundle.mail = true
			case "social":
				flagBundle.social = true
			case "metadata":
				flagBundle.metadata = true
			case "proxy":
				flagBundle.proxy = true
			case "url":
				flagBundle.collectURLs = true
			case "whois":
				flagBundle.whois = true
			}
		}
	}

	// Parameter/Dork/Fuzz flags copy into flagBundle
	flagBundle.parameter = *parameterFlag
	flagBundle.paramWordlist = *paramWordlist
	flagBundle.paramConcurrency = *paramConcurrency
	flagBundle.dork = *dorkFlag
	flagBundle.dorkQuery = *dorkQuery
	flagBundle.fuzzing = *fuzzingFlag
	flagBundle.fuzzWordlist = *fuzzWordlist
	flagBundle.fuzzConcurrency = *fuzzConcurrency

	// UA list loading
	flagBundle.UAList = loadUAList(flagBundle.UA, flagBundle.UAFile)

	// build global request limiter if requested
	if flagBundle.RateLimit > 0 {
		globalLimiter = NewRequestLimiter(flagBundle.RateLimit)
		defer globalLimiter.Stop()
	}

	if dirOptsUsed {
		fmt.Println("[*] Directory options summary:")
		fmt.Printf("     -dir: %v\n", flagBundle.dirEnabled)
		fmt.Printf("     -dir-fetch-js: %v\n", flagBundle.dirFetchJS)
		fmt.Printf("     -dir-follow-sitemap: %v\n", flagBundle.dirFollowSitemap)
		if flagBundle.dirWordlist != "" {
			fmt.Printf("     -dir-wordlist: %s\n", flagBundle.dirWordlist)
		} else {
			fmt.Printf("     -dir-wordlist: (built-in)\n")
		}
		fmt.Println()
	}

	// set global flags for printing
	flagsGlobal = flagBundle

	// parse targets
	targets, err := parseTargets(*domainFlag, *targetsFile)
	if err != nil {
		fmt.Println("Error:", err)
		flag.Usage()
		os.Exit(1)
	}

	// If all targets are IPs, enforce maxIPTargets
	allIPs := true
	for _, t := range targets {
		if stdnet.ParseIP(t) == nil {
			allIPs = false
			break
		}
	}
	if allIPs && len(targets) > maxIPTargets {
		fmt.Printf("Warning: %d IP targets provided; limiting to first %d.\n", len(targets), maxIPTargets)
		targets = targets[:maxIPTargets]
	}

	// concurrency control per-target
	sem := make(chan struct{}, *concurrency)
	var wg sync.WaitGroup
	resultsCh := make(chan ScanResults, len(targets))

	for _, target := range targets {
		target := target
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			fmt.Printf("[*] Scanning target: %s\n", target)
			res := scanTarget(target, flagBundle)
			resultsCh <- res
		}()
	}

	wg.Wait()
	close(resultsCh)

	resultsMap := map[string]ScanResults{}
	for r := range resultsCh {
		resultsMap[r.Target] = r
	}

	for _, t := range targets {
		if res, ok := resultsMap[t]; ok {
			if outputFile != "" || flagBundle.OutputDir != "" {
				safeTarget := strings.ReplaceAll(t, "/", "_")
				filePath := outputFile
				if filePath == "" {
					filePath = "reconnio"
				}
				if flagBundle.OutputDir != "" {
					os.MkdirAll(flagBundle.OutputDir, 0755)
					filePath = strings.TrimRight(flagBundle.OutputDir, "/") + "/" + filePath
				}
				if strings.EqualFold(outputFormat, "json") {
					if strings.HasSuffix(filePath, ".json") {
						filePath = strings.TrimSuffix(filePath, ".json") + "-" + safeTarget + ".json"
					} else {
						filePath = filePath + "-" + safeTarget + ".json"
					}
				} else {
					filePath = filePath + "-" + safeTarget + ".txt"
				}
				if err := WriteToFile(res, outputFormat, filePath); err != nil {
					log.Printf("[-] Failed to write %s: %v", filePath, err)
				} else {
					log.Printf("[+] Wrote %s", filePath)
				}
			} else {
				PrintToConsole(res, flagBundle)
			}
		} else {
			fmt.Printf("No results for target %s\n", t)
		}
	}

	fmt.Println("✅ ReconNio scan completed.")
}
