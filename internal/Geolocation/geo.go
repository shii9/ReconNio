package geolocation

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/likexian/whois"
)

// GeoResponse holds enriched ISP registration and geolocation data.
type GeoResponse struct {
	IP              string   `json:"ip"`
	ISP             string   `json:"isp"`          // Human friendly ISP name (e.g. "Google LLC")
	Org             string   `json:"organization"` // Organization string returned by services
	ASN             string   `json:"asn"`          // ASN (e.g. "AS15169")
	ASNOrg          string   `json:"asn_org"`      // ASN organization (from RDAP/ipinfo)
	City            string   `json:"city"`         // City (from IP geolocation)
	Region          string   `json:"region"`       // Region/State (from IP geolocation)
	Country         string   `json:"country"`      // Country (2-letter)
	CountryFull     string   `json:"country_full"` // Country full name (best-effort)
	Timezone        string   `json:"timezone"`     // Timezone (from IP geolocation)
	Latitude        float64  `json:"latitude,omitempty"`
	Longitude       float64  `json:"longitude,omitempty"`
	Network         string   `json:"network"`           // e.g. 8.8.8.0/24 or start-end
	Registry        string   `json:"registry"`          // RIR (arin, ripe, apnic...)
	AllocationDate  string   `json:"allocation_date"`   // if available from RDAP/events
	AbuseContacts   []string `json:"abuse_contacts"`    // emails/phones extracted
	RawWhoisExcerpt string   `json:"raw_whois_excerpt"` // short excerpt for provenance/debug
	Source          string   `json:"source"`            // which primary source provided most of the info
	Warnings        string   `json:"warnings,omitempty"`
}

// LookupISPRegistrationLocation returns ISP/ASN and registration location for
// an IP address or domain. It prefers structured APIs (ipinfo/ip-api) and
// falls back to RDAP and raw whois parsing if needed.
func LookupISPRegistrationLocation(ipOrDomain string) (*GeoResponse, error) {
	ipOrDomain = strings.TrimSpace(ipOrDomain)
	if ipOrDomain == "" {
		return nil, fmt.Errorf("empty ipOrDomain")
	}

	// 1) Resolve domain -> IP (prefer IPv4)
	ip := ipOrDomain
	if net.ParseIP(ipOrDomain) == nil {
		ips, err := net.LookupIP(ipOrDomain)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("failed to resolve %q: %v", ipOrDomain, err)
		}
		// prefer IPv4
		found := ""
		for _, cand := range ips {
			if cand.To4() != nil {
				found = cand.String()
				break
			}
		}
		if found == "" {
			found = ips[0].String()
		}
		ip = found
	}

	resp := &GeoResponse{IP: ip}

	// Query multiple sources (best-effort, non-blocking order)
	ipinfoRes, ipinfoErr := queryIPInfo(ip)
	ipapiRes, ipapiErr := queryIPAPI(ip)
	rdapRes, rdapErr := queryRDAP(ip)
	whoisRaw, whoisErr := whoisLookup(ip)

	var warnings []string
	if ipinfoErr != nil {
		warnings = append(warnings, "ipinfo: "+ipinfoErr.Error())
	}
	if ipapiErr != nil {
		warnings = append(warnings, "ip-api: "+ipapiErr.Error())
	}
	if rdapErr != nil {
		warnings = append(warnings, "rdap: "+rdapErr.Error())
	}
	if whoisErr != nil {
		warnings = append(warnings, "whois: "+whoisErr.Error())
	}

	// Merge data: ipinfo -> ip-api -> rdap -> whois
	if ipinfoRes != nil {
		// Org field contains "AS###### Organization" often; parse it
		if ipinfoRes.Org != "" {
			resp.Org = ipinfoRes.Org
			asn, ispName := parseOrgField(ipinfoRes.Org)
			if asn != "" {
				resp.ASN = asn
			}
			if ispName != "" {
				resp.ISP = ispName
			} else if resp.ISP == "" {
				// if no split, use full org for ISP
				resp.ISP = ipinfoRes.Org
			}
		}
		if ipinfoRes.City != "" {
			resp.City = ipinfoRes.City
		}
		if ipinfoRes.Region != "" {
			resp.Region = ipinfoRes.Region
		}
		if ipinfoRes.Country != "" {
			resp.Country = ipinfoRes.Country
		}
		if ipinfoRes.Timezone != "" {
			resp.Timezone = ipinfoRes.Timezone
		}
		// parse Loc "lat,lon"
		if ipinfoRes.Loc != "" {
			parts := strings.Split(ipinfoRes.Loc, ",")
			if len(parts) == 2 {
				if lat, err := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64); err == nil {
					resp.Latitude = lat
				}
				if lon, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64); err == nil {
					resp.Longitude = lon
				}
			}
		}
		if resp.ASN != "" && resp.Source == "" {
			resp.Source = "ipinfo"
		}
	}

	// Fill missing fields from ip-api
	if ipapiRes != nil {
		if resp.ASN == "" && ipapiRes.AS != "" {
			// ip-api returns "AS#### ISP"
			asn, ispName := parseOrgField(ipapiRes.AS)
			if asn != "" {
				resp.ASN = asn
			}
			if ispName != "" && resp.ISP == "" {
				resp.ISP = ispName
			}
			if resp.Source == "" {
				resp.Source = "ip-api"
			}
		}
		if resp.ISP == "" && ipapiRes.ISP != "" {
			resp.ISP = ipapiRes.ISP
		}
		if resp.Org == "" && ipapiRes.Org != "" {
			resp.Org = ipapiRes.Org
		}
		if resp.City == "" && ipapiRes.City != "" {
			resp.City = ipapiRes.City
		}
		if resp.Region == "" && ipapiRes.Region != "" {
			resp.Region = ipapiRes.Region
		}
		if resp.Country == "" && ipapiRes.CountryCode != "" {
			resp.Country = ipapiRes.CountryCode
		}
		if resp.Timezone == "" && ipapiRes.Timezone != "" {
			resp.Timezone = ipapiRes.Timezone
		}
		if resp.Latitude == 0 && ipapiRes.Lat != 0 {
			resp.Latitude = ipapiRes.Lat
			resp.Longitude = ipapiRes.Lon
		}
	}

	// RDAP -- network/prefix, registry, allocation date, abuse contacts
	if rdapRes != nil {
		if resp.Network == "" && rdapRes.Network != "" {
			resp.Network = rdapRes.Network
		}
		if resp.Registry == "" && rdapRes.Registry != "" {
			resp.Registry = rdapRes.Registry
		}
		if resp.AllocationDate == "" && rdapRes.AllocationDate != "" {
			resp.AllocationDate = rdapRes.AllocationDate
		}
		if resp.ASNOrg == "" && rdapRes.ASNOrg != "" {
			resp.ASNOrg = rdapRes.ASNOrg
		}
		if len(rdapRes.AbuseContacts) > 0 {
			resp.AbuseContacts = append(resp.AbuseContacts, rdapRes.AbuseContacts...)
		}
		// fill country/city from rdap if missing
		if resp.Country == "" && rdapRes.Country != "" {
			resp.Country = rdapRes.Country
		}
		if resp.City == "" && rdapRes.City != "" {
			resp.City = rdapRes.City
		}
	}

	// WHOIS fallback (raw parse)
	if whoisRaw != "" {
		resp.RawWhoisExcerpt = excerpt(whoisRaw, 5)
		parsed := parseWhoisRaw(whoisRaw)
		if resp.ISP == "" && parsed["netname"] != "" {
			resp.ISP = parsed["netname"]
		}
		if resp.Org == "" && parsed["org"] != "" {
			resp.Org = parsed["org"]
		}
		if resp.Country == "" && parsed["country"] != "" {
			resp.Country = parsed["country"]
		}
		if resp.City == "" && parsed["city"] != "" {
			resp.City = parsed["city"]
		}
		if resp.ASN == "" {
			if v := parsed["origin"]; v != "" {
				if asn := firstAS(v); asn != "" {
					resp.ASN = asn
				}
			}
		}
		// abuse contacts
		if parsed["abuse-mail"] != "" {
			resp.AbuseContacts = append(resp.AbuseContacts, parsed["abuse-mail"])
		}
		if parsed["abuse"] != "" {
			resp.AbuseContacts = append(resp.AbuseContacts, parsed["abuse"])
		}
	}

	resp.CountryFull = countryNameFromCode(resp.Country)
	if resp.Source == "" {
		resp.Source = "whois/rdap"
	}
	if len(warnings) > 0 {
		resp.Warnings = strings.Join(warnings, " | ")
	}
	return resp, nil
}

/* ---------------------- helper & query implementations ---------------------- */

// ipinfo partial result
type ipinfoResult struct {
	IP       string `json:"ip"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Loc      string `json:"loc"` // "lat,lon"
	Org      string `json:"org"` // usually "AS15169 Google LLC"
	Hostname string `json:"hostname"`
	Postal   string `json:"postal"`
	Timezone string `json:"timezone"`
}

func queryIPInfo(ip string) (*ipinfoResult, error) {
	client := &http.Client{Timeout: 6 * time.Second}
	url := "https://ipinfo.io/" + ip + "/json"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "ReconNio-Geolocation/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ipinfo request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ipinfo HTTP %d", resp.StatusCode)
	}
	var r ipinfoResult
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("ipinfo json parse failed: %v", err)
	}
	return &r, nil
}

// ip-api result
type ipapiResult struct {
	Status      string  `json:"status"`
	Message     string  `json:"message,omitempty"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"regionName"`
	City        string  `json:"city"`
	Zip         string  `json:"zip"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"` // "AS15169 Google LLC"
	Query       string  `json:"query"`
}

func queryIPAPI(ip string) (*ipapiResult, error) {
	client := &http.Client{Timeout: 6 * time.Second}
	url := "http://ip-api.com/json/" + ip + "?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "ReconNio-Geolocation/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ip-api request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var r ipapiResult
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("ip-api json parse failed: %v", err)
	}
	if r.Status != "success" {
		return &r, fmt.Errorf("ip-api status=%s message=%s", r.Status, r.Message)
	}
	return &r, nil
}

/* ---------------------- RDAP (lightweight) ---------------------- */

type rdapResult struct {
	Network        string
	Registry       string
	AllocationDate string
	Country        string
	City           string
	ASNOrg         string
	AbuseContacts  []string
}

func queryRDAP(ip string) (*rdapResult, error) {
	client := &http.Client{Timeout: 8 * time.Second}
	rdapURL := "https://rdap.arin.net/registry/ip/" + ip
	req, _ := http.NewRequest("GET", rdapURL, nil)
	req.Header.Set("User-Agent", "ReconNio-RDAP/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rdap request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("rdap HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	body, _ := io.ReadAll(resp.Body)
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("rdap parse failed: %v", err)
	}

	out := &rdapResult{}

	// network cidr hints
	if netObj, ok := data["network"].(map[string]interface{}); ok {
		if v, ok := netObj["cidr"].([]interface{}); ok && len(v) > 0 {
			if s, ok := v[0].(string); ok {
				out.Network = s
			}
		}
		if s, ok := netObj["startAddress"].(string); ok {
			if e, ok2 := netObj["endAddress"].(string); ok2 {
				out.Network = fmt.Sprintf("%s-%s", s, e)
			}
		}
	}

	// name or handle
	if name, ok := data["name"].(string); ok && out.Network == "" {
		out.Network = name
	}
	if h, ok := data["handle"].(string); ok && out.Network == "" {
		out.Network = h
	}

	// events -> allocation date
	if evs, ok := data["events"].([]interface{}); ok {
		for _, e := range evs {
			if em, ok2 := e.(map[string]interface{}); ok2 {
				if kind, ok3 := em["eventAction"].(string); ok3 && (strings.EqualFold(kind, "registration") || strings.EqualFold(kind, "allocation")) {
					if dateStr, ok4 := em["eventDate"].(string); ok4 {
						out.AllocationDate = dateStr
						break
					}
				}
			}
		}
	}

	// country
	if c, ok := data["country"].(string); ok {
		out.Country = c
	}

	// entities -> abuse contacts (vcardArray parsing)
	if entities, ok := data["entities"].([]interface{}); ok {
		for _, en := range entities {
			if emap, ok2 := en.(map[string]interface{}); ok2 {
				if vca, ok3 := emap["vcardArray"]; ok3 {
					if vals, err := parseVCardArray(vca); err == nil {
						if len(vals.Emails) > 0 {
							out.AbuseContacts = append(out.AbuseContacts, vals.Emails...)
						}
						if len(vals.Tels) > 0 {
							out.AbuseContacts = append(out.AbuseContacts, vals.Tels...)
						}
					}
				}
			}
		}
	}

	// registry detection
	if _, ok := data["rdapConformance"]; ok {
		out.Registry = "rdap"
	}

	// try to set ASNOrg from name
	if n, ok := data["name"].(string); ok {
		out.ASNOrg = n
	}
	return out, nil
}

type vcardParsed struct {
	Emails []string
	Tels   []string
	Other  map[string]string
}

func parseVCardArray(v interface{}) (*vcardParsed, error) {
	parsed := &vcardParsed{Emails: []string{}, Tels: []string{}, Other: map[string]string{}}
	arr, ok := v.([]interface{})
	if !ok || len(arr) < 2 {
		return parsed, fmt.Errorf("invalid vcard array")
	}
	props, ok := arr[1].([]interface{})
	if !ok {
		return parsed, fmt.Errorf("invalid vcard props")
	}
	for _, p := range props {
		if prop, ok := p.([]interface{}); ok && len(prop) >= 4 {
			name, _ := prop[0].(string)
			val, _ := prop[3].(string)
			name = strings.ToLower(strings.TrimSpace(name))
			val = strings.TrimSpace(val)
			if name == "email" && val != "" {
				parsed.Emails = append(parsed.Emails, val)
			} else if name == "tel" && val != "" {
				parsed.Tels = append(parsed.Tels, val)
			} else if val != "" {
				parsed.Other[name] = val
			}
		}
	}
	return parsed, nil
}

// whoisLookup returns raw whois string using likexian/whois
func whoisLookup(q string) (string, error) {
	raw, err := whois.Whois(q)
	if err != nil {
		return "", fmt.Errorf("whois failed: %v", err)
	}
	return raw, nil
}

// parseWhoisRaw does a tolerant line-based parse of common WHOIS keys.
func parseWhoisRaw(raw string) map[string]string {
	out := map[string]string{}
	lines := strings.Split(raw, "\n")
	keyRe := regexp.MustCompile(`^\s*([A-Za-z0-9\-\_ ]{2,40}?)\s*[:=]\s*(.+)$`)
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "%") || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, "NOTICE:") {
			continue
		}
		if m := keyRe.FindStringSubmatch(ln); m != nil && len(m) >= 3 {
			k := strings.ToLower(strings.TrimSpace(m[1]))
			v := strings.TrimSpace(m[2])
			switch {
			case strings.Contains(k, "org") && out["org"] == "":
				out["org"] = v
			case strings.Contains(k, "netname") && out["netname"] == "":
				out["netname"] = v
			case strings.Contains(k, "country") && out["country"] == "":
				out["country"] = v
			case strings.Contains(k, "city") && out["city"] == "":
				out["city"] = v
			case strings.Contains(k, "origin") && out["origin"] == "":
				out["origin"] = v
			case strings.Contains(k, "abuse-mailbox") && out["abuse-mail"] == "":
				out["abuse-mail"] = v
			case strings.Contains(k, "abuse") && out["abuse"] == "":
				out["abuse"] = v
			default:
				if _, exists := out[k]; !exists {
					out[k] = v
				}
			}
		}
	}
	return out
}

func firstAS(s string) string {
	re := regexp.MustCompile(`(?i)AS\d+`)
	if m := re.FindString(s); m != "" {
		return strings.ToUpper(m)
	}
	return ""
}

func excerpt(s string, n int) string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, n)
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		out = append(out, ln)
		if len(out) >= n {
			break
		}
	}
	return strings.Join(out, " | ")
}

func parseOrgField(s string) (asn, isp string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	parts := strings.Fields(s)
	if len(parts) == 0 {
		return "", s
	}
	first := parts[0]
	if matched, _ := regexp.MatchString(`(?i)^AS\d+`, first); matched {
		asn = strings.ToUpper(first)
		if len(parts) > 1 {
			isp = strings.Join(parts[1:], " ")
		}
	} else {
		isp = s
	}
	return asn, strings.TrimSpace(isp)
}

func countryNameFromCode(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return ""
	}
	countries := map[string]string{
		"US": "United States",
		"GB": "United Kingdom",
		"DE": "Germany",
		"FR": "France",
		"BD": "Bangladesh",
		"IN": "India",
		"CN": "China",
		"JP": "Japan",
		"RU": "Russia",
		"SG": "Singapore",
		"NL": "Netherlands",
		"BR": "Brazil",
		"AU": "Australia",
	}
	if name, ok := countries[code]; ok {
		return name
	}
	return code
}
