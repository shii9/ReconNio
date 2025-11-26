package subdomain

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func fetchURL(url string) ([]byte, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func fromCrtSh(domain string) []string {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	body, err := fetchURL(url)
	if err != nil {
		return nil
	}
	var data []map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}
	results := []string{}
	for _, entry := range data {
		if name, ok := entry["name_value"].(string); ok {
			for _, sub := range strings.Split(name, "\n") {
				results = append(results, strings.TrimSpace(sub))
			}
		}
	}
	return results
}

func fromHackerTarget(domain string) []string {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	body, err := fetchURL(url)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(body), "\n")
	subs := []string{}
	for _, line := range lines {
		parts := strings.Split(line, ",")
		if len(parts) > 0 {
			subs = append(subs, strings.TrimSpace(parts[0]))
		}
	}
	return subs
}

func fromThreatCrowd(domain string) []string {
	url := fmt.Sprintf("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", domain)
	body, err := fetchURL(url)
	if err != nil {
		return nil
	}
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}
	results := []string{}
	if subs, ok := data["subdomains"].([]interface{}); ok {
		for _, sub := range subs {
			if s, ok := sub.(string); ok {
				results = append(results, strings.TrimSpace(s))
			}
		}
	}
	return results
}

func fromAlienVault(domain string) []string {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
	body, err := fetchURL(url)
	if err != nil {
		return nil
	}
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}
	results := []string{}
	if records, ok := data["passive_dns"].([]interface{}); ok {
		for _, r := range records {
			if rec, ok := r.(map[string]interface{}); ok {
				if hostname, ok := rec["hostname"].(string); ok {
					results = append(results, strings.TrimSpace(hostname))
				}
			}
		}
	}
	return results
}

func fromCertSpotter(domain string) []string {
	url := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)
	body, err := fetchURL(url)
	if err != nil {
		return nil
	}
	var data []map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}
	results := []string{}
	for _, entry := range data {
		if dnsNames, ok := entry["dns_names"].([]interface{}); ok {
			for _, d := range dnsNames {
				if s, ok := d.(string); ok {
					results = append(results, strings.TrimSpace(s))
				}
			}
		}
	}
	return results
}

func fromAnubis(domain string) []string {
	url := fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain)
	body, err := fetchURL(url)
	if err != nil {
		return nil
	}
	var subs []string
	if err := json.Unmarshal(body, &subs); err != nil {
		return nil
	}
	return subs
}

func unique(slice []string) []string {
	seen := make(map[string]struct{})
	uniqueList := []string{}
	for _, item := range slice {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		if _, ok := seen[item]; !ok {
			seen[item] = struct{}{}
			uniqueList = append(uniqueList, item)
		}
	}
	return uniqueList
}

// GetAllSubdomains queries multiple sources and returns unique subdomains
func GetAllSubdomains(domain string) []string {
	all := []string{}
	all = append(all, fromCrtSh(domain)...)
	all = append(all, fromHackerTarget(domain)...)
	all = append(all, fromThreatCrowd(domain)...)
	all = append(all, fromAlienVault(domain)...)
	all = append(all, fromCertSpotter(domain)...)
	all = append(all, fromAnubis(domain)...)
	return unique(all)
}
