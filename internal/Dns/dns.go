package dns

import (
	"fmt"
	"net"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
)

// FetchRecords fetches all DNS records for a domain, including advanced types
func FetchRecords(domain string) (map[string][]string, error) {
	results := make(map[string][]string)
	var errs []string

	// Standard lookups
	results["A"], errs = lookupA(domain, errs)
	results["AAAA"], errs = lookupAAAA(domain, errs)
	results["CNAME"], errs = lookupCNAME(domain, errs)
	results["MX"], errs = lookupMX(domain, errs)
	results["NS"], errs = lookupNS(domain, errs)
	results["TXT"], errs = lookupTXT(domain, errs)
	results["SOA"], errs = lookupSOA(domain, errs)
	results["SRV"], errs = lookupSRV(domain, errs)
	results["PTR"], errs = lookupPTR(results["A"], errs)

	// Parse SPF, DMARC, DKIM from TXT
	spf, dmarc, dkim := parseTXTRecords(results["TXT"])
	results["SPF"] = spf
	// Try querying DMARC subdomain if not found in TXT
	if len(dmarc) == 0 {
		dmarc = lookupDMARC(domain, &errs)
	}
	results["DMARC"] = dmarc
	// Try common DKIM selectors if not found
	if len(dkim) == 0 {
		selectors := []string{"google", "mail", "default"}
		for _, sel := range selectors {
			dkim = append(dkim, lookupDKIM(domain, sel, &errs)...)
		}
	}
	results["DKIM"] = dkim

	// Attempt Zone Transfer
	axfrDomains, err := tryZoneTransfer(domain)
	if err == nil && len(axfrDomains) > 0 {
		results["AXFR"] = axfrDomains
	}

	if len(errs) > 0 {
		results["Errors"] = errs
	}

	return results, nil
}

// -------------------- Individual Record Lookups --------------------

func lookupA(domain string, errs []string) ([]string, []string) {
	aRecords, err := net.LookupHost(domain)
	if err != nil {
		errs = append(errs, fmt.Sprintf("A record lookup failed: %v", err))
		return nil, errs
	}
	return filterIPv4(aRecords), errs
}

func lookupAAAA(domain string, errs []string) ([]string, []string) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		errs = append(errs, fmt.Sprintf("AAAA lookup failed: %v", err))
		return nil, errs
	}
	var out []string
	for _, ip := range ips {
		if ip.To16() != nil && ip.To4() == nil {
			out = append(out, ip.String())
		}
	}
	return out, errs
}

func lookupCNAME(domain string, errs []string) ([]string, []string) {
	cname, err := net.LookupCNAME(domain)
	if err != nil {
		errs = append(errs, fmt.Sprintf("CNAME lookup failed: %v", err))
		return nil, errs
	}
	if cname != "" && cname != domain {
		return []string{cname}, errs
	}
	return nil, errs
}

func lookupMX(domain string, errs []string) ([]string, []string) {
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		errs = append(errs, fmt.Sprintf("MX lookup failed: %v", err))
		return nil, errs
	}
	var mxList []string
	for _, mx := range mxRecords {
		mxList = append(mxList, fmt.Sprintf("%s (Priority: %d)", mx.Host, mx.Pref))
	}
	return mxList, errs
}

func lookupNS(domain string, errs []string) ([]string, []string) {
	nsRecords, err := net.LookupNS(domain)
	if err != nil {
		errs = append(errs, fmt.Sprintf("NS lookup failed: %v", err))
		return nil, errs
	}
	var nsList []string
	for _, ns := range nsRecords {
		nsList = append(nsList, ns.Host)
	}
	return nsList, errs
}

func lookupTXT(domain string, errs []string) ([]string, []string) {
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		errs = append(errs, fmt.Sprintf("TXT lookup failed: %v", err))
		return nil, errs
	}
	return txtRecords, errs
}

func lookupSOA(domain string, errs []string) ([]string, []string) {
	nsRecords, err := net.LookupNS(domain)
	if err != nil || len(nsRecords) == 0 {
		errs = append(errs, fmt.Sprintf("SOA lookup failed: %v", err))
		return nil, errs
	}

	var out []string
	for _, ns := range nsRecords {
		c := new(mdns.Client)
		c.Timeout = 5 * time.Second
		msg := new(mdns.Msg)
		msg.SetQuestion(mdns.Fqdn(domain), mdns.TypeSOA)
		r, _, err := c.Exchange(msg, ns.Host+":53")
		if err != nil {
			errs = append(errs, fmt.Sprintf("SOA lookup failed for %s: %v", ns.Host, err))
			continue
		}
		for _, ans := range r.Answer {
			if soa, ok := ans.(*mdns.SOA); ok {
				out = append(out, fmt.Sprintf("MName: %s, RName: %s, Serial: %d, Refresh: %d, Retry: %d, Expire: %d, Minimum: %d",
					soa.Ns, soa.Mbox, soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minttl))
			}
		}
	}
	return out, errs
}

func lookupSRV(domain string, errs []string) ([]string, []string) {
	services := []string{"_sip._tcp", "_ldap._tcp", "_xmpp-server._tcp", "_http._tcp", "_imaps._tcp", "_submission._tcp", "_pop3._tcp", "_caldav._tcp"}
	var out []string

	for _, svc := range services {
		_, addrs, err := net.LookupSRV("", "", svc+"."+domain)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			out = append(out, fmt.Sprintf("Target: %s, Port: %d, Priority: %d, Weight: %d",
				a.Target, a.Port, a.Priority, a.Weight))
		}
	}

	if len(out) == 0 {
		errs = append(errs, "No SRV records found for common services")
	}

	return out, errs
}

func lookupPTR(ips []string, errs []string) ([]string, []string) {
	var ptrs []string
	for _, ip := range ips {
		names, err := net.LookupAddr(ip)
		if err == nil && len(names) > 0 {
			for _, n := range names {
				ptrs = append(ptrs, strings.TrimSuffix(n, "."))
			}
		}
	}
	return ptrs, errs
}

// Parse SPF, DMARC, DKIM from TXT records
func parseTXTRecords(txt []string) (spf, dmarc, dkim []string) {
	for _, t := range txt {
		tLow := strings.ToLower(t)
		if strings.HasPrefix(tLow, "v=spf1") {
			spf = append(spf, t)
		} else if strings.HasPrefix(tLow, "v=dmarc1") {
			dmarc = append(dmarc, t)
		} else if strings.Contains(tLow, "dkim") {
			dkim = append(dkim, t)
		}
	}
	return
}

// Lookup DMARC from _dmarc subdomain
func lookupDMARC(domain string, errs *[]string) []string {
	records, err := net.LookupTXT("_dmarc." + domain)
	if err != nil {
		*errs = append(*errs, fmt.Sprintf("DMARC lookup failed: %v", err))
		return nil
	}
	return records
}

// Lookup DKIM from selector._domainkey subdomain
func lookupDKIM(domain string, selector string, errs *[]string) []string {
	txtDomain := selector + "._domainkey." + domain
	records, err := net.LookupTXT(txtDomain)
	if err != nil {
		*errs = append(*errs, fmt.Sprintf("DKIM lookup failed: %v", err))
		return nil
	}
	return records
}

// Extract SPF from TXT
func parseSPF(txt []string) []string {
	var spf []string
	for _, t := range txt {
		if strings.HasPrefix(t, "v=spf") {
			spf = append(spf, t)
		}
	}
	return spf
}

// IPv4 / IPv6 helpers
func filterIPv4(ips []string) []string {
	var out []string
	for _, ip := range ips {
		if strings.Count(ip, ":") == 0 {
			out = append(out, ip)
		}
	}
	return out
}

func filterIPv6(ips []string) []string {
	var out []string
	for _, ip := range ips {
		if strings.Count(ip, ":") > 0 {
			out = append(out, ip)
		}
	}
	return out
}

// -------------------- Zone Transfer --------------------

func tryZoneTransfer(domain string) ([]string, error) {
	nsRecords, err := net.LookupNS(domain)
	if err != nil {
		return nil, fmt.Errorf("NS lookup failed for AXFR: %v", err)
	}

	found := map[string]struct{}{}
	msg := new(mdns.Msg)
	msg.SetAxfr(domain + ".")

	for _, ns := range nsRecords {
		addr := ns.Host
		if !strings.Contains(addr, ":") {
			addr = fmt.Sprintf("%s:53", strings.TrimSuffix(addr, "."))
		}

		tr := &mdns.Transfer{}
		ch, err := tr.In(msg, addr)
		if err != nil {
			continue
		}

		timeout := time.After(5 * time.Second)
	loop:
		for {
			select {
			case env, ok := <-ch:
				if !ok {
					break loop
				}
				if env.Error != nil {
					continue
				}
				for _, rr := range env.RR {
					name := strings.TrimSuffix(rr.Header().Name, ".")
					if strings.HasSuffix(name, domain) {
						found[name] = struct{}{}
					}
				}
			case <-timeout:
				fmt.Println("AXFR timed out for", addr)
				break loop
			}
		}
		if len(found) > 0 {
			break
		}
	}

	if len(found) == 0 {
		return nil, fmt.Errorf("AXFR not allowed or returned no data")
	}

	out := make([]string, 0, len(found))
	for s := range found {
		out = append(out, s)
	}
	return out, nil
}
