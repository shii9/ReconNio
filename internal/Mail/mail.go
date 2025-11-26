package mail

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
)

// ---------- Public types ----------

// MailOptions controls behavior of FetchMailInfo (active vs passive, timeouts, etc).
type MailOptions struct {
	Active                 bool          // enable active SMTP probing (banner, EHLO, STARTTLS)
	AllowMailboxValidation bool          // allow VRFY/RCPT mailbox checks (intrusive)
	SMTPTimeout            time.Duration // timeout used for SMTP connections
	SMTPPorts              []int         // ports to try for SMTP active probing (defaults 25,587)
	DKIMSelectors          []string      // additional DKIM selectors to try (besides common ones)
	RBLs                   []string      // RBL domains to check (reverse-IP.rbl)
	RDAPTimeout            time.Duration // RDAP HTTP timeout
	HTTPTimeout            time.Duration // generic HTTP timeout for MTA-STS fetching and web probes
	FetchMtaStsPolicy      bool          // fetch policy file when _mta-sts TXT present
	PreferIPv6             bool          // prefer IPv6 addresses when resolving MX
	ProbeConcurrency       int           // concurrent SMTP probe workers
	InputsConcurrency      int           // concurrency when processing many inputs
}

// MailResult aggregates everything we can learn about mail for a domain.
type MailResult struct {
	Input              string              `json:"input"` // original input (domain/url/ip)
	Domain             string              `json:"domain"`
	MXRecords          []MXRecord          `json:"mx_records"`
	SPF                string              `json:"spf,omitempty"`
	SPFParsed          SPFParsed           `json:"spf_parsed,omitempty"`
	DMARC              string              `json:"dmarc,omitempty"`
	DMARCTags          map[string]string   `json:"dmarc_tags,omitempty"`
	DKIM               map[string]string   `json:"dkim_records,omitempty"` // selector -> raw TXT
	DKIMInfo           map[string]DKIMInfo `json:"dkim_info,omitempty"`    // selector -> parsed info
	MTASTS             MTASTSResult        `json:"mta_sts,omitempty"`
	TLSRPT             []string            `json:"tls_rpt,omitempty"`
	CAA                []string            `json:"caa_records,omitempty"`
	ResolvedIPs        map[string][]string `json:"resolved_ips,omitempty"` // mx host -> ips
	PTRs               map[string][]string `json:"ptrs,omitempty"`         // ip -> ptrs
	ASN                map[string]ASNInfo  `json:"asn_by_ip,omitempty"`    // ip -> asn info
	RBL                map[string][]string `json:"rbl_listings,omitempty"` // ip -> rbls that listed it
	SMTPProbes         []SMTPProbeResult   `json:"smtp_probes,omitempty"`  // results per mx/ip/port attempt
	ProviderHeuristics []string            `json:"provider_inference,omitempty"`
	WebmailEndpoints   []string            `json:"webmail_endpoints,omitempty"`
	Posture            MailPosture         `json:"posture,omitempty"`
	Notes              []string            `json:"notes,omitempty"`
	Timestamp          string              `json:"timestamp,omitempty"`
}

// MXRecord holds MX record + priority
type MXRecord struct {
	Host     string `json:"host"`
	Priority uint16 `json:"priority"`
}

// MTASTSResult contains TXT and optionally fetched policy
type MTASTSResult struct {
	TXT        string            `json:"txt,omitempty"`
	PolicyURL  string            `json:"policy_url,omitempty"`
	PolicyText string            `json:"policy_text,omitempty"`
	Parsed     map[string]string `json:"parsed,omitempty"`
}

// ASNInfo is a minimal RDAP / ASN result
type ASNInfo struct {
	CIDR       string `json:"cidr,omitempty"`
	ASN        string `json:"asn,omitempty"`
	ASName     string `json:"as_name,omitempty"`
	Country    string `json:"country,omitempty"`
	Handle     string `json:"handle,omitempty"`
	AbuseEmail string `json:"abuse_contact,omitempty"`
	Raw        string `json:"raw,omitempty"`
}

// SMTPProbeResult holds the result of connecting to an MX host/IP on a particular port
type SMTPProbeResult struct {
	MXHost           string   `json:"mx_host"`
	IP               string   `json:"ip"`
	Port             int      `json:"port"`
	Connected        bool     `json:"connected"`
	Banner           string   `json:"banner,omitempty"`
	EHLOLines        []string `json:"ehlo_lines,omitempty"`
	SupportsStartTLS bool     `json:"supports_starttls,omitempty"`
	AuthMechanisms   []string `json:"auth_mechanisms,omitempty"`
	TLSVersion       string   `json:"tls_version,omitempty"`
	Cipher           string   `json:"cipher,omitempty"`
	CertSubjects     []string `json:"cert_subjects,omitempty"`
	CertSANs         []string `json:"cert_sans,omitempty"`
	CertIssuer       string   `json:"cert_issuer,omitempty"`
	CertNotBefore    string   `json:"cert_not_before,omitempty"`
	CertNotAfter     string   `json:"cert_not_after,omitempty"`
	CertExpired      bool     `json:"cert_expired,omitempty"`
	VRFYResult       string   `json:"vrfy_result,omitempty"` // server response text (if run)
	RCPTResult       string   `json:"rcpt_result,omitempty"` // server response text (if run)
	Error            string   `json:"error,omitempty"`
}

// DKIMInfo holds small parsed bits from a DKIM record
type DKIMInfo struct {
	Selector string `json:"selector,omitempty"`
	Domain   string `json:"domain,omitempty"`
	KeyAlgo  string `json:"k,omitempty"`
	KeyLen   int    `json:"p_key_bits,omitempty"` // approximate bits (if p value decodes)
	Raw      string `json:"raw,omitempty"`
}

// SPFParsed holds extracted mechanisms from a v=spf1 record
type SPFParsed struct {
	Includes []string `json:"includes,omitempty"`
	IP4      []string `json:"ip4,omitempty"`
	IP6      []string `json:"ip6,omitempty"`
	All      string   `json:"all_directive,omitempty"`
	Raw      string   `json:"raw,omitempty"`
}

// MailPosture is a short summary
type MailPosture struct {
	HasSPF       bool   `json:"has_spf"`
	HasDKIM      bool   `json:"has_dkim"`
	DMARCPolicy  string `json:"dmarc_policy,omitempty"` // none/quarantine/reject
	HasMTASTS    bool   `json:"has_mta_sts"`
	HasTLSRPT    bool   `json:"has_tls_rpt"`
	AnyStartTLS  bool   `json:"any_starttls_supported"`
	OverallScore int    `json:"overall_score"` // 0..100
}

// ---------- Defaults ----------
var defaultRBLs = []string{
	"zen.spamhaus.org",
	"bl.spamcop.net",
	"b.barracudacentral.org",
}

// ---------- Entrypoints ----------

// FetchMailInfo accepts domain, URL, or IP and returns a single MailResult.
func FetchMailInfo(input string, opts MailOptions) (*MailResult, error) {
	return fetchMailInfoInternal(input, opts)
}

// FetchMailInfoMultiple accepts multiple inputs (domain/url/ip) and returns results concurrently.
// Concurrency is controlled by opts.InputsConcurrency (defaults to 8).
func FetchMailInfoMultiple(inputs []string, opts MailOptions) ([]*MailResult, error) {
	if opts.InputsConcurrency <= 0 {
		opts.InputsConcurrency = 8
	}
	sem := make(chan struct{}, opts.InputsConcurrency)
	var wg sync.WaitGroup
	out := make([]*MailResult, len(inputs))
	errs := make([]error, len(inputs))

	for i, in := range inputs {
		i, in := i, in
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			res, err := fetchMailInfoInternal(in, opts)
			out[i] = res
			errs[i] = err
		}()
	}
	wg.Wait()

	// Aggregate errors (if any)
	var firstErr error
	for _, e := range errs {
		if e != nil && firstErr == nil {
			firstErr = e
		}
	}
	return out, firstErr
}

// FetchMailInfoFromFile reads newline separated inputs from a file and runs FetchMailInfoMultiple.
func FetchMailInfoFromFile(path string, opts MailOptions) ([]*MailResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	inputs := []string{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// skip comments
		if strings.HasPrefix(line, "#") {
			continue
		}
		inputs = append(inputs, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return FetchMailInfoMultiple(inputs, opts)
}

// ---------- internal implementation (single input) ----------

func fetchMailInfoInternal(input string, opts MailOptions) (*MailResult, error) {
	domain := normalizeToHost(input)
	if domain == "" {
		return nil, errors.New("empty input")
	}
	isIP := net.ParseIP(domain) != nil

	// defaults
	if opts.SMTPTimeout == 0 {
		opts.SMTPTimeout = 8 * time.Second
	}
	if opts.RDAPTimeout == 0 {
		opts.RDAPTimeout = 8 * time.Second
	}
	if opts.HTTPTimeout == 0 {
		opts.HTTPTimeout = 8 * time.Second
	}
	if len(opts.SMTPPorts) == 0 {
		opts.SMTPPorts = []int{25, 587}
	}
	if opts.ProbeConcurrency <= 0 {
		opts.ProbeConcurrency = 6
	}
	if len(opts.RBLs) == 0 {
		opts.RBLs = defaultRBLs
	}

	now := time.Now().UTC().Format(time.RFC3339)
	mr := &MailResult{
		Input:            input,
		Domain:           domain,
		DKIM:             map[string]string{},
		DKIMInfo:         map[string]DKIMInfo{},
		ResolvedIPs:      map[string][]string{},
		PTRs:             map[string][]string{},
		ASN:              map[string]ASNInfo{},
		RBL:              map[string][]string{},
		Notes:            []string{},
		Timestamp:        now,
		WebmailEndpoints: []string{},
	}

	// If input is not an IP, do the name-based passive checks
	if !isIP {
		// 1) MX
		mxs, err := net.LookupMX(domain)
		if err != nil {
			mr.Notes = append(mr.Notes, fmt.Sprintf("LookupMX: %v", err))
		} else {
			for _, x := range mxs {
				mr.MXRecords = append(mr.MXRecords, MXRecord{Host: strings.TrimSuffix(x.Host, "."), Priority: x.Pref})
			}
			sort.Slice(mr.MXRecords, func(i, j int) bool { return mr.MXRecords[i].Priority < mr.MXRecords[j].Priority })
		}

		// 2) SPF
		spf := lookupTXTFirstPrefix(domain, "v=spf1")
		if spf != "" {
			mr.SPF = spf
			mr.SPFParsed = parseSPF(spf)
		}

		// 3) DMARC
		dmarc := lookupTXTFirstPrefix("_dmarc."+domain, "v=dmarc1")
		if dmarc != "" {
			mr.DMARC = dmarc
			mr.DMARCTags = parseTagList(dmarc)
		}

		// 4) DKIM selectors
		commonSelectors := []string{"default", "google", "selector1", "s1", "s1024", "s2048", "mail", "selector", "smtp"}
		allSelectors := append(commonSelectors, opts.DKIMSelectors...)
		selSeen := map[string]struct{}{}
		for _, sel := range allSelectors {
			sel = strings.TrimSpace(sel)
			if sel == "" {
				continue
			}
			if _, ok := selSeen[sel]; ok {
				continue
			}
			selSeen[sel] = struct{}{}
			name := fmt.Sprintf("%s._domainkey.%s", sel, domain)
			if txt := lookupTXTRaw(name); txt != "" {
				mr.DKIM[sel] = txt
				info := DKIMInfo{Selector: sel, Domain: domain, Raw: txt}
				if k := regexp.MustCompile(`\bk=([^;]+)`).FindStringSubmatch(txt); len(k) >= 2 {
					info.KeyAlgo = k[1]
				}
				if p := regexp.MustCompile(`\bp=([^;]+)`).FindStringSubmatch(txt); len(p) >= 2 {
					decoded, err := base64.StdEncoding.DecodeString(p[1])
					if err == nil && len(decoded) > 0 {
						info.KeyLen = len(decoded) * 8
					}
				}
				mr.DKIMInfo[sel] = info
			}
		}

		// 5) MTA-STS
		mtaTxt := lookupTXTRaw("_mta-sts." + domain)
		if mtaTxt != "" {
			mr.MTASTS.TXT = mtaTxt
			pURL := fmt.Sprintf("https://mta-sts.%s/.well-known/mta-sts.txt", domain)
			mr.MTASTS.PolicyURL = pURL
			if opts.FetchMtaStsPolicy {
				client := &http.Client{Timeout: opts.HTTPTimeout}
				if resp, err := client.Get(pURL); err == nil && resp != nil {
					body, _ := ioReadAllLimit(resp.Body, 256*1024)
					if len(body) > 0 {
						mr.MTASTS.PolicyText = string(body)
						mr.MTASTS.Parsed = parseMtaSts(string(body))
					}
				} else if err != nil {
					mr.Notes = append(mr.Notes, fmt.Sprintf("mta-sts fetch: %v", err))
				}
			}
		}

		// 6) TLS-RPT
		tlsRpt := lookupTXTRaw("_smtp._tls." + domain)
		if tlsRpt != "" {
			mr.TLSRPT = append(mr.TLSRPT, tlsRpt)
		}

		// 7) CAA
		if caa, err := lookupCAA(domain); err == nil && len(caa) > 0 {
			mr.CAA = caa
		}
	}

	// 8) Resolve hosts -> IPs (MX hosts or domain or raw IP)
	resolveTargets := []string{}
	if !isIP {
		if len(mr.MXRecords) == 0 {
			resolveTargets = append(resolveTargets, domain)
		} else {
			for _, mx := range mr.MXRecords {
				resolveTargets = append(resolveTargets, mx.Host)
			}
		}
	} else {
		resolveTargets = append(resolveTargets, domain) // domain is the raw IP here
	}

	for _, host := range resolveTargets {
		if ip := net.ParseIP(host); ip != nil {
			// host already IP
			mr.ResolvedIPs[host] = []string{ip.String()}
			if ptrs, err := net.LookupAddr(ip.String()); err == nil && len(ptrs) > 0 {
				clean := []string{}
				for _, p := range ptrs {
					clean = append(clean, strings.TrimSuffix(p, "."))
				}
				mr.PTRs[ip.String()] = dedupeStrings(clean)
			}
			if asn, raw, err := rdapLookup(ip.String(), opts.RDAPTimeout); err == nil && asn != nil {
				asn.Raw = raw
				mr.ASN[ip.String()] = *asn
			} else if err != nil {
				mr.Notes = append(mr.Notes, fmt.Sprintf("rdap %s: %v", ip.String(), err))
			}
			for _, rbl := range opts.RBLs {
				if listed, _ := checkRBL(ip.String(), rbl); listed {
					mr.RBL[ip.String()] = append(mr.RBL[ip.String()], rbl)
				}
			}
			continue
		}

		ips, err := net.LookupIP(host)
		if err != nil {
			mr.Notes = append(mr.Notes, fmt.Sprintf("LookupIP %s: %v", host, err))
			continue
		}
		ipStrs := []string{}
		for _, ip := range ips {
			ipStrs = append(ipStrs, ip.String())
		}
		mr.ResolvedIPs[host] = dedupeStrings(ipStrs)
		for _, ip := range ips {
			ipS := ip.String()
			if ptrs, err := net.LookupAddr(ipS); err == nil && len(ptrs) > 0 {
				clean := []string{}
				for _, p := range ptrs {
					clean = append(clean, strings.TrimSuffix(p, "."))
				}
				mr.PTRs[ipS] = dedupeStrings(clean)
			}
			if asn, raw, err := rdapLookup(ipS, opts.RDAPTimeout); err == nil && asn != nil {
				asn.Raw = raw
				mr.ASN[ipS] = *asn
			} else if err != nil {
				mr.Notes = append(mr.Notes, fmt.Sprintf("rdap %s: %v", ipS, err))
			}
			for _, rbl := range opts.RBLs {
				if listed, _ := checkRBL(ipS, rbl); listed {
					mr.RBL[ipS] = append(mr.RBL[ipS], rbl)
				}
			}
		}
	}

	// 9) probe webmail endpoints (hostnames only)
	if !isIP {
		if endpoints := probeWebmailEndpoints(domain, opts.HTTPTimeout); len(endpoints) > 0 {
			mr.WebmailEndpoints = endpoints
		}
	}

	// 10) Active SMTP probing if requested (concurrent)
	if opts.Active {
		tasks := []probeTask{}

		// prefer MX hosts (if any)
		if !isIP && len(mr.MXRecords) > 0 {
			for _, mx := range mr.MXRecords {
				host := mx.Host
				ipList := mr.ResolvedIPs[host]
				if len(ipList) == 0 {
					tmp, _ := net.LookupIP(host)
					for _, ip := range tmp {
						ipList = append(ipList, ip.String())
					}
				}
				for _, ip := range ipList {
					for _, port := range opts.SMTPPorts {
						tasks = append(tasks, probeTask{MXHost: host, IP: ip, Port: port})
					}
				}
			}
		}

		// if input was IP, probe directly
		if isIP {
			for _, port := range opts.SMTPPorts {
				tasks = append(tasks, probeTask{MXHost: domain, IP: domain, Port: port})
			}
		}

		// fallback: domain A/AAAA
		if len(tasks) == 0 && !isIP {
			tmp, _ := net.LookupIP(domain)
			ipList := []string{}
			for _, ip := range tmp {
				ipList = append(ipList, ip.String())
			}
			for _, ip := range ipList {
				for _, port := range opts.SMTPPorts {
					tasks = append(tasks, probeTask{MXHost: domain, IP: ip, Port: port})
				}
			}
		}

		probeResults := make([]SMTPProbeResult, 0, len(tasks))
		var mu sync.Mutex
		wg := sync.WaitGroup{}
		tch := make(chan probeTask, len(tasks))
		if opts.ProbeConcurrency <= 0 {
			opts.ProbeConcurrency = 6
		}
		for w := 0; w < opts.ProbeConcurrency; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for t := range tch {
					res := doSMTPProbe(t.MXHost, t.IP, t.Port, opts)
					mu.Lock()
					probeResults = append(probeResults, *res)
					mu.Unlock()
				}
			}()
		}
		for _, t := range tasks {
			tch <- t
		}
		close(tch)
		wg.Wait()
		mr.SMTPProbes = probeResults
	}

	// provider inference and posture
	mr.ProviderHeuristics = inferProvider(mr.MXRecords)
	mr.Posture = computePosture(mr)

	// dedupe lists
	for k := range mr.RBL {
		mr.RBL[k] = dedupeStrings(mr.RBL[k])
	}
	for k := range mr.PTRs {
		mr.PTRs[k] = dedupeStrings(mr.PTRs[k])
	}

	return mr, nil
}

// ---------- Helpers & parsing ----------

func lookupTXTRaw(name string) string {
	txts, err := net.LookupTXT(name)
	if err != nil || len(txts) == 0 {
		return ""
	}
	return strings.Join(txts, " ")
}

func lookupTXTFirstPrefix(name, prefix string) string {
	txts, err := net.LookupTXT(name)
	if err != nil {
		return ""
	}
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), strings.ToLower(prefix)) {
			return t
		}
	}
	return ""
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

// parseSPF extracts include/ip4/ip6/all directives (basic)
func parseSPF(spf string) SPFParsed {
	out := SPFParsed{Raw: spf}
	parts := strings.Fields(spf)
	for _, p := range parts {
		if strings.HasPrefix(p, "include:") {
			out.Includes = append(out.Includes, strings.TrimPrefix(p, "include:"))
		}
		if strings.HasPrefix(p, "ip4:") {
			out.IP4 = append(out.IP4, strings.TrimPrefix(p, "ip4:"))
		}
		if strings.HasPrefix(p, "ip6:") {
			out.IP6 = append(out.IP6, strings.TrimPrefix(p, "ip6:"))
		}
		if p == "-all" || p == "~all" || p == "?all" || p == "+all" {
			out.All = p
		}
	}
	out.Includes = dedupeStrings(out.Includes)
	out.IP4 = dedupeStrings(out.IP4)
	out.IP6 = dedupeStrings(out.IP6)
	return out
}

// parseTagList parse key=value; pairs separated by ;
func parseTagList(s string) map[string]string {
	out := map[string]string{}
	parts := strings.Split(s, ";")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		if len(kv) == 2 {
			out[strings.ToLower(strings.TrimSpace(kv[0]))] = strings.TrimSpace(kv[1])
		} else {
			out[strings.ToLower(p)] = ""
		}
	}
	return out
}

// parseMtaSts reads simple key: value lines
func parseMtaSts(body string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			out[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return out
}

// ---------- RDAP, CAA, RBL ----------

func rdapLookup(ip string, timeout time.Duration) (*ASNInfo, string, error) {
	endpoints := []string{
		"https://rdap.arin.net/registry/ip/%s",
		"https://rdap.db.ripe.net/ip/%s",
		"https://rdap.apnic.net/ip/%s",
		"https://rdap.lacnic.net/rdap/ip/%s",
		"https://rdap.afrinic.net/rdap/ip/%s",
	}
	client := &http.Client{Timeout: timeout}
	var lastErr error
	for _, tmpl := range endpoints {
		u := fmt.Sprintf(tmpl, url.PathEscape(ip))
		resp, err := client.Get(u)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := ioReadAllLimit(resp.Body, 256*1024)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("rdap %s -> %s", u, resp.Status)
			continue
		}
		var parsed map[string]interface{}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, string(body), nil
		}
		asn := &ASNInfo{Raw: string(body)}
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
		// entities -> abuse email (best-effort)
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
		return asn, string(body), nil
	}
	return nil, "", lastErr
}

func lookupCAA(domain string) ([]string, error) {
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(domain), mdns.TypeCAA)
	c := mdns.Client{Timeout: 6 * time.Second}
	in, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return nil, err
	}
	out := []string{}
	if in == nil || in.Answer == nil {
		return out, nil
	}
	for _, ans := range in.Answer {
		if rr, ok := ans.(*mdns.CAA); ok {
			out = append(out, fmt.Sprintf("%d %s %q", rr.Flag, rr.Tag, rr.Value))
		}
	}
	return dedupeStrings(out), nil
}

func checkRBL(ipStr, rbl string) (bool, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, fmt.Errorf("invalid ip")
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false, nil
	}
	o := strings.Split(ip4.String(), ".")
	if len(o) != 4 {
		return false, nil
	}
	query := fmt.Sprintf("%s.%s.%s.%s.%s", o[3], o[2], o[1], o[0], rbl)
	_, err := net.LookupHost(query)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return false, nil
		}
		return false, nil
	}
	return true, nil
}

// ---------- SMTP active probing (concurrent-safe) ----------

type probeTask struct {
	MXHost string
	IP     string
	Port   int
}

func doSMTPProbe(mxHost, ip string, port int, opts MailOptions) *SMTPProbeResult {
	res := &SMTPProbeResult{MXHost: mxHost, IP: ip, Port: port}
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	ctx, cancel := context.WithTimeout(context.Background(), opts.SMTPTimeout)
	defer cancel()
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		res.Error = fmt.Sprintf("dial: %v", err)
		return res
	}
	res.Connected = true
	// ensure close
	defer conn.Close()

	tp := textproto.NewConn(conn)
	_ = conn.SetDeadline(time.Now().Add(opts.SMTPTimeout))

	// initial banner
	line, err := tp.ReadLine()
	if err != nil {
		res.Error = fmt.Sprintf("read banner: %v", err)
		return res
	}
	res.Banner = strings.TrimSpace(line)

	// EHLO
	helloDomain := "reconnio.local"
	_ = tp.PrintfLine("EHLO %s", helloDomain)
	ehlo := readSMTPMultiline(tp)
	res.EHLOLines = ehlo

	// parse EHLO
	for _, l := range ehlo {
		ll := strings.ToLower(l)
		if strings.Contains(ll, "starttls") {
			res.SupportsStartTLS = true
		}
		if strings.Contains(ll, "auth ") || strings.Contains(ll, "auth=") {
			t := strings.TrimPrefix(l, "250-")
			t = strings.TrimPrefix(t, "250 ")
			if strings.Contains(strings.ToLower(t), "auth") {
				parts := strings.Fields(t)
				for _, p := range parts {
					p = strings.Trim(p, ",;:")
					if strings.EqualFold(p, "auth") {
						continue
					}
					if p != "" {
						res.AuthMechanisms = append(res.AuthMechanisms, p)
					}
				}
			}
		}
	}
	res.AuthMechanisms = dedupeStrings(res.AuthMechanisms)

	// STARTTLS
	tpConn := tp
	if res.SupportsStartTLS {
		_ = tp.PrintfLine("STARTTLS")
		respLine, err := tp.ReadLine()
		if err != nil {
			res.Error = fmt.Sprintf("STARTTLS read: %v", err)
			return res
		}
		if !strings.HasPrefix(respLine, "220") {
			res.Error = fmt.Sprintf("STARTTLS not accepted: %s", respLine)
		} else {
			cfg := &tls.Config{InsecureSkipVerify: true, ServerName: mxHost}
			tlsConn := tls.Client(conn, cfg)
			_ = tlsConn.SetDeadline(time.Now().Add(opts.SMTPTimeout))
			if err := tlsConn.Handshake(); err != nil {
				res.Error = fmt.Sprintf("tls handshake: %v", err)
				return res
			}
			state := tlsConn.ConnectionState()
			res.TLSVersion = tlsVersionString(state.Version)
			res.Cipher = fmt.Sprintf("0x%x", state.CipherSuite)
			for _, c := range state.PeerCertificates {
				if c.Subject.CommonName != "" {
					res.CertSubjects = append(res.CertSubjects, c.Subject.CommonName)
				}
				for _, san := range c.DNSNames {
					res.CertSANs = append(res.CertSANs, san)
				}
				if c.Issuer.CommonName != "" {
					res.CertIssuer = c.Issuer.CommonName
				}
				res.CertNotBefore = c.NotBefore.UTC().Format(time.RFC3339)
				res.CertNotAfter = c.NotAfter.UTC().Format(time.RFC3339)
				if time.Now().After(c.NotAfter.UTC()) {
					res.CertExpired = true
				}
			}
			res.CertSANs = dedupeStrings(res.CertSANs)
			tpConn = textproto.NewConn(tlsConn)
			_ = tpConn.PrintfLine("EHLO %s", helloDomain)
			newEhlo := readSMTPMultiline(tpConn)
			res.EHLOLines = append(res.EHLOLines, newEhlo...)
		}
	}

	// VRFY / RCPT if allowed
	if opts.AllowMailboxValidation {
		_ = tpConn.PrintfLine("VRFY postmaster")
		if l, err := tpConn.ReadLine(); err == nil {
			res.VRFYResult = l
		}
		_ = tpConn.PrintfLine("MAIL FROM:<reconnio@local.invalid>")
		if _, err := tpConn.ReadLine(); err == nil {
			_ = tpConn.PrintfLine("RCPT TO:<postmaster@%s>", strings.TrimSuffix(mxHost, "."))
			if l2, err2 := tpConn.ReadLine(); err2 == nil {
				res.RCPTResult = l2
			}
		}
		_ = tpConn.PrintfLine("RSET")
		_, _ = tpConn.ReadLine()
	}

	// QUIT
	_ = tpConn.PrintfLine("QUIT")
	_, _ = tpConn.ReadLine()

	return res
}

func readSMTPMultiline(tp *textproto.Conn) []string {
	out := []string{}
	for i := 0; i < 256; i++ {
		l, err := tp.ReadLine()
		if err != nil {
			break
		}
		out = append(out, l)
		if strings.HasPrefix(l, "250 ") || !strings.HasPrefix(l, "250-") {
			break
		}
	}
	return out
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

// ---------- small utilities ----------

func ioReadAllLimit(r io.ReadCloser, limit int64) ([]byte, error) {
	defer r.Close()
	lr := io.LimitReader(r, limit)
	return io.ReadAll(lr)
}

func inferProvider(mxs []MXRecord) []string {
	out := []string{}
	for _, m := range mxs {
		h := strings.ToLower(m.Host)
		switch {
		case strings.Contains(h, "google") || strings.Contains(h, "aspmx.l.google.com"):
			out = append(out, "Google Workspace")
		case strings.Contains(h, "outlook") || strings.Contains(h, "mail.protection.outlook.com"):
			out = append(out, "Microsoft 365 / Exchange Online")
		case strings.Contains(h, "protonmail"):
			out = append(out, "ProtonMail")
		case strings.Contains(h, "zoho"):
			out = append(out, "Zoho Mail")
		case strings.Contains(h, "sendgrid") || strings.Contains(h, "smtp.sendgrid"):
			out = append(out, "SendGrid (transactional)")
		case strings.Contains(h, "amazonses") || strings.Contains(h, "amazonses.com"):
			out = append(out, "Amazon SES")
		}
	}
	return dedupeStrings(out)
}

// normalizeToHost accepts a domain or URL and returns just the hostname part.
func normalizeToHost(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return input
	}

	// Try parse as URL
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		if u, err := url.Parse(input); err == nil {
			host := u.Hostname()
			if host != "" {
				return host
			}
		}
		// fallback strip scheme and trailing slashes
		input = strings.TrimPrefix(strings.TrimPrefix(input, "http://"), "https://")
		input = strings.TrimSuffix(input, "/")
	}

	// If contains a slash, cut at first '/'
	if idx := strings.IndexByte(input, '/'); idx != -1 {
		input = input[:idx]
	}

	// If contains @ (user@host), keep host part
	if strings.Contains(input, "@") {
		parts := strings.Split(input, "@")
		input = parts[len(parts)-1]
	}

	// Remove port if present (naive; supports common cases)
	if strings.Contains(input, ":") && !strings.Contains(input, "]") {
		input = strings.Split(input, ":")[0]
	}

	// bracketed IPv6 [::1]:port
	if strings.HasPrefix(input, "[") {
		if idx := strings.Index(input, "]"); idx != -1 {
			inside := strings.TrimPrefix(strings.TrimSuffix(input[:idx+1], "]"), "[")
			if net.ParseIP(inside) != nil {
				return inside
			}
		}
	}

	return strings.TrimSpace(input)
}

// probeWebmailEndpoints checks common mail/webmail endpoints.
func probeWebmailEndpoints(domain string, timeout time.Duration) []string {
	client := &http.Client{Timeout: timeout}
	candidates := []string{
		"webmail." + domain,
		"mail." + domain,
		"owa." + domain,
		"autodiscover." + domain,
		"imap." + domain,
		"smtp." + domain,
		"mailhost." + domain,
		"m." + domain,
	}
	found := []string{}
	for _, h := range candidates {
		try := []string{"https://" + h + "/", "http://" + h + "/"}
		for _, u := range try {
			req, _ := http.NewRequest("HEAD", u, nil)
			req.Header.Set("User-Agent", "ReconNio/1.0")
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			_ = resp.Body.Close()
			if (resp.StatusCode >= 200 && resp.StatusCode < 400) || resp.StatusCode == 401 || resp.StatusCode == 403 {
				found = append(found, u)
				break
			}
		}
	}
	return dedupeStrings(found)
}

// computePosture now accepts pointer to MailResult
func computePosture(m *MailResult) MailPosture {
	p := MailPosture{}
	if m == nil {
		return p
	}
	p.HasSPF = m.SPF != ""
	p.HasDKIM = len(m.DKIM) > 0
	if tags := m.DMARCTags; tags != nil {
		if v, ok := tags["p"]; ok {
			p.DMARCPolicy = strings.Trim(v, "\"")
		}
	}
	p.HasMTASTS = (m.MTASTS.TXT != "")
	p.HasTLSRPT = (len(m.TLSRPT) > 0)
	anyStartTLS := false
	for _, pr := range m.SMTPProbes {
		if pr.SupportsStartTLS {
			anyStartTLS = true
			break
		}
	}
	p.AnyStartTLS = anyStartTLS

	score := 0
	if p.HasSPF {
		score += 20
	}
	if p.HasDKIM {
		score += 20
	}
	switch strings.ToLower(p.DMARCPolicy) {
	case "reject":
		score += 30
	case "quarantine":
		score += 20
	case "none":
		score += 5
	}
	if p.HasMTASTS {
		score += 15
	}
	if p.AnyStartTLS {
		score += 10
	}
	if p.HasTLSRPT {
		score += 5
	}
	if score > 100 {
		score = 100
	}
	p.OverallScore = score
	return p
}
