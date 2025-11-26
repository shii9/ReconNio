package whois

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	whois "github.com/likexian/whois"
)

// LookupDomain performs a WHOIS lookup and prints a rich, organized set of
// extracted information for both domains and IPs. Signature kept for backward compatibility.
func LookupDomain(target string) {
	fmt.Println("[*] Running WHOIS lookup...")

	raw, err := whois.Whois(target)
	if err != nil {
		fmt.Println("Error performing WHOIS lookup:", err)
		return
	}

	// normalize newlines
	text := strings.ReplaceAll(raw, "\r\n", "\n")

	if net.ParseIP(target) != nil {
		printIPWhois(text)
	} else {
		printDomainWhois(target, text)
	}
}

// ---------- helpers ----------

func findFirst(pattern, text string) string {
	re := regexp.MustCompile("(?im)" + pattern)
	if m := re.FindStringSubmatch(text); len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func findAll(pattern, text string) []string {
	re := regexp.MustCompile("(?im)" + pattern)
	matches := re.FindAllStringSubmatch(text, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) >= 2 {
			v := strings.TrimSpace(m[1])
			if v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, s := range in {
		s = strings.TrimSpace(s)
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

func emptyIfNil(s string) string {
	if strings.TrimSpace(s) == "" {
		return "<not available>"
	}
	return s
}

func parseDateTry(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"02-Jan-2006",
		"2006.01.02 15:04:05",
		"2006/01/02 15:04:05",
		"Mon Jan 02 15:04:05 MST 2006",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t, true
		}
	}
	// try trimming timezone
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	return time.Time{}, false
}

func yearsBetween(a, b time.Time) int {
	if a.IsZero() || b.IsZero() {
		return 0
	}
	years := b.Year() - a.Year()
	if b.YearDay() < a.YearDay() {
		years--
	}
	return years
}

func sortedNonEmpty(parts ...string) []string {
	set := map[string]struct{}{}
	for _, p := range parts {
		if p == "" {
			continue
		}
		for _, s := range strings.Split(p, ",") {
			v := strings.TrimSpace(s)
			if v != "" {
				set[v] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func detectRIR(text string) string {
	l := strings.ToLower(text)
	switch {
	case strings.Contains(l, "arin") || strings.Contains(l, "whois.arin.net"):
		return "ARIN"
	case strings.Contains(l, "ripe") || strings.Contains(l, "whois.ripe.net"):
		return "RIPE"
	case strings.Contains(l, "apnic") || strings.Contains(l, "whois.apnic.net"):
		return "APNIC"
	case strings.Contains(l, "lacnic") || strings.Contains(l, "whois.lacnic.net"):
		return "LACNIC"
	case strings.Contains(l, "afrinic") || strings.Contains(l, "whois.afrinic.net"):
		return "AFRINIC"
	default:
		return "<unknown>"
	}
}

// ---------- Domain WHOIS printing ----------

func printDomainWhois(domain, text string) {
	fmt.Println("┌─ WHOIS (Domain)")

	registrar := firstAny(text,
		`Registrar:\s*(.+)`,
		`Registrar Name:\s*(.+)`,
		`Sponsoring Registrar:\s*(.+)`,
	)
	fmt.Printf("│  Registrar: %s\n", emptyIfNil(registrar))

	iana := firstAny(text,
		`Registrar IANA ID:\s*(.+)`,
		`Registrar IANA:\s*(.+)`,
	)
	fmt.Printf("│  Registrar IANA ID: %s\n", emptyIfNil(iana))

	registryID := firstAny(text,
		`Registry Domain ID:\s*(.+)`,
		`Domain ID:\s*(.+)`,
	)
	fmt.Printf("│  Registry / Domain ID: %s\n", emptyIfNil(registryID))

	whoisServer := firstAny(text,
		`Whois Server:\s*(.+)`,
		`WHOIS Server:\s*(.+)`,
	)
	fmt.Printf("│  WHOIS Server: %s\n", emptyIfNil(whoisServer))

	registrarURL := firstAny(text,
		`Registrar URL:\s*(.+)`,
		`Registrar Url:\s*(.+)`,
	)
	fmt.Printf("│  Registrar URL: %s\n", emptyIfNil(registrarURL))

	abuseEmail := firstAny(text,
		`Registrar Abuse Contact Email:\s*(.+)`,
		`Registrar Abuse Email:\s*(.+)`,
		`Registrar AbusE Contact Email:\s*(.+)`,
	)
	abusePhone := firstAny(text,
		`Registrar Abuse Contact Phone:\s*(.+)`,
		`Registrar Abuse Phone:\s*(.+)`,
	)
	fmt.Printf("│  Registrar Abuse Email: %s\n", emptyIfNil(abuseEmail))
	fmt.Printf("│  Registrar Abuse Phone: %s\n", emptyIfNil(abusePhone))

	// Registrant information (many registrars redact this; we attempt many variants)
	regName := firstAny(text,
		`Registrant Name:\s*(.+)`,
		`Registrant:\s*(.+)`,
		`Registrant Contact Name:\s*(.+)`,
	)
	regOrg := firstAny(text,
		`Registrant Organization:\s*(.+)`,
		`Registrant Org:\s*(.+)`,
		`Organization:\s*(.+)`,
	)
	regEmail := firstAny(text,
		`Registrant Email:\s*(.+)`,
		`Registrant E-mail:\s*(.+)`,
		`Registrant Contact Email:\s*(.+)`,
	)
	regPhone := firstAny(text,
		`Registrant Phone:\s*(.+)`,
		`Registrant Telephone:\s*(.+)`,
	)

	// Address parts - try collect from common field names
	street := firstAny(text,
		`Registrant Street:\s*(.+)`,
		`Registrant Address:\s*(.+)`,
	)
	city := firstAny(text, `Registrant City:\s*(.+)`)
	postal := firstAny(text, `Registrant Postal Code:\s*(.+)`)
	country := firstAny(text, `Registrant Country:\s*(.+)`)
	address := strings.Join(sortedNonEmpty(street, city, postal, country), ", ")

	fmt.Printf("│  Registrant Name: %s\n", emptyIfNil(regName))
	fmt.Printf("│  Registrant Organization: %s\n", emptyIfNil(regOrg))
	fmt.Printf("│  Registrant Email: %s\n", emptyIfNil(regEmail))
	fmt.Printf("│  Registrant Phone: %s\n", emptyIfNil(regPhone))
	if address != "" {
		fmt.Printf("│  Registrant Address: %s\n", address)
	}

	// Admin / Technical / Billing contacts
	adminName := firstAny(text,
		`Admin Name:\s*(.+)`,
		`Administrative Contact:\s*(.+)`,
		`Admin Contact:\s*(.+)`,
	)
	adminEmail := firstAny(text,
		`Admin Email:\s*(.+)`,
		`Admin E-mail:\s*(.+)`,
	)
	techName := firstAny(text,
		`Tech Name:\s*(.+)`,
		`Technical Contact:\s*(.+)`,
	)
	techEmail := firstAny(text,
		`Tech Email:\s*(.+)`,
		`Tech E-mail:\s*(.+)`,
	)
	billingName := firstAny(text,
		`Billing Name:\s*(.+)`,
		`Billing Contact:\s*(.+)`,
	)
	billingEmail := firstAny(text,
		`Billing Email:\s*(.+)`,
	)

	if adminName != "" || adminEmail != "" {
		fmt.Println("│  Administrative Contact:")
		if adminName != "" {
			fmt.Printf("│    Name: %s\n", adminName)
		}
		if adminEmail != "" {
			fmt.Printf("│    Email: %s\n", adminEmail)
		}
	}

	if techName != "" || techEmail != "" {
		fmt.Println("│  Technical Contact:")
		if techName != "" {
			fmt.Printf("│    Name: %s\n", techName)
		}
		if techEmail != "" {
			fmt.Printf("│    Email: %s\n", techEmail)
		}
	}

	if billingName != "" || billingEmail != "" {
		fmt.Println("│  Billing Contact:")
		if billingName != "" {
			fmt.Printf("│    Name: %s\n", billingName)
		}
		if billingEmail != "" {
			fmt.Printf("│    Email: %s\n", billingEmail)
		}
	}

	// Dates
	created := firstAny(text,
		`Creation Date:\s*(.+)`,
		`Created On:\s*(.+)`,
		`Registered On:\s*(.+)`,
		`Domain Registration Date:\s*(.+)`,
	)
	updated := firstAny(text,
		`Updated Date:\s*(.+)`,
		`Last Updated On:\s*(.+)`,
		`Last updated:\s*(.+)`,
	)
	expires := firstAny(text,
		`Registry Expiry Date:\s*(.+)`,
		`Registrar Registration Expiration Date:\s*(.+)`,
		`Expiration Date:\s*(.+)`,
		`Expires On:\s*(.+)`,
	)

	fmt.Printf("│  Created: %s\n", emptyIfNil(created))
	fmt.Printf("│  Updated: %s\n", emptyIfNil(updated))
	fmt.Printf("│  Expires: %s\n", emptyIfNil(expires))

	if t, ok := parseDateTry(created); ok {
		age := yearsBetween(t, time.Now().UTC())
		fmt.Printf("│  Domain age: %d year(s)\n", age)
	}

	// Statuses
	statuses := uniqueStrings(findAll(`Status:\s*([^\n\r]+)`, text))
	if len(statuses) == 0 {
		statuses = uniqueStrings(findAll(`Domain Status:\s*([^\n\r]+)`, text))
	}
	if len(statuses) > 0 {
		fmt.Println("│  Statuses:")
		for _, s := range statuses {
			fmt.Printf("│    - %s\n", s)
		}
	} else {
		fmt.Println("│  Statuses: <not available>")
	}

	// Nameservers (and resolve them)
	ns := uniqueStrings(findAll(`Name Server:\s*(.+)`, text))
	if len(ns) == 0 {
		ns = uniqueStrings(findAll(`Nameserver:\s*(.+)`, text))
	}
	if len(ns) > 0 {
		fmt.Println("│  Name Servers:")
		for _, n := range ns {
			fmt.Printf("│    - %s", n)
			ips, _ := net.LookupHost(n)
			if len(ips) > 0 {
				fmt.Printf("  (IP: %s)", strings.Join(ips, ", "))
			}
			fmt.Println()
		}
	} else {
		fmt.Println("│  Name Servers: <not available>")
	}

	// DNSSEC
	dnssec := firstAny(text, `DNSSEC:\s*(.+)`)
	if dnssec == "" {
		dnssec = firstAny(text, `dnssec:\s*(.+)`)
	}
	fmt.Printf("│  DNSSEC: %s\n", emptyIfNil(dnssec))

	// Referral / reseller
	referral := firstAny(text, `Referral URL:\s*(.+)`, `ReferralServer:\s*(.+)`)
	reseller := firstAny(text, `Reseller:\s*(.+)`)
	fmt.Printf("│  Referral URL: %s\n", emptyIfNil(referral))
	fmt.Printf("│  Reseller: %s\n", emptyIfNil(reseller))

	// extract emails and phones as pivot data
	emails := uniqueStrings(findAll(`([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})`, text))
	phones := uniqueStrings(findAll(`(\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{2,4}[-.\s]?\d{0,4})`, text))

	if len(emails) > 0 {
		fmt.Println("│  Emails found in WHOIS:")
		for _, e := range emails {
			fmt.Printf("│    - %s\n", e)
		}
	}
	if len(phones) > 0 {
		fmt.Println("│  Phones found in WHOIS:")
		for _, p := range phones {
			fmt.Printf("│    - %s\n", p)
		}
	}

	// if very sparse, show short raw snippet
	if registrar == "" && regOrg == "" && len(ns) == 0 {
		fmt.Println("│  (WHOIS content sparse — raw snippet follows)")
		lines := strings.Split(strings.TrimSpace(text), "\n")
		limit := 12
		if len(lines) < limit {
			limit = len(lines)
		}
		for i := 0; i < limit; i++ {
			fmt.Printf("│    %s\n", lines[i])
		}
	}

	fmt.Println("└────────────────────────────")
}

// ---------- IP WHOIS printing ----------

func printIPWhois(text string) {
	fmt.Println("┌─ WHOIS (IP / ASN)")

	inet := firstAny(text,
		`inetnum:\s*(.+)`,
		`NetRange:\s*(.+)`,
		`inet6num:\s*(.+)`,
	)
	fmt.Printf("│  IP Range (inetnum/NetRange): %s\n", emptyIfNil(inet))

	cidr := firstAny(text, `CIDR:\s*(.+)`, `route:\s*(.+)`, `route6:\s*(.+)`)
	fmt.Printf("│  CIDR / Route: %s\n", emptyIfNil(cidr))

	netname := firstAny(text, `NetName:\s*(.+)`, `netname:\s*(.+)`, `NetHandle:\s*(.+)`)
	fmt.Printf("│  NetName / Handle: %s\n", emptyIfNil(netname))

	org := firstAny(text,
		`OrgName:\s*(.+)`,
		`org-name:\s*(.+)`,
		`organization:\s*(.+)`,
		`descr:\s*(.+)`,
	)
	fmt.Printf("│  Organization: %s\n", emptyIfNil(org))

	country := firstAny(text, `Country:\s*(.+)`)
	fmt.Printf("│  Country: %s\n", emptyIfNil(country))

	asn := firstAny(text,
		`origin:\s*(.+)`,
		`OriginAS:\s*(.+)`,
		`originas:\s*(.+)`,
		`aut-num:\s*(.+)`,
	)
	fmt.Printf("│  ASN / Origin: %s\n", emptyIfNil(asn))

	abuse := firstAny(text,
		`abuse-mailbox:\s*(.+)`,
		`abuse-c:\s*(.+)`,
		`abuse:\s*(.+)`,
		`OrgAbuseEmail:\s*(.+)`,
	)
	fmt.Printf("│  Abuse Contact: %s\n", emptyIfNil(abuse))

	admin := firstAny(text, `admin-c:\s*(.+)`, `AdminContact:\s*(.+)`)
	tech := firstAny(text, `tech-c:\s*(.+)`, `TechContact:\s*(.+)`)
	fmt.Printf("│  Admin Contact: %s\n", emptyIfNil(admin))
	fmt.Printf("│  Tech Contact: %s\n", emptyIfNil(tech))

	created := firstAny(text, `created:\s*(.+)`, `Creation Date:\s*(.+)`)
	updated := firstAny(text, `last-modified:\s*(.+)`, `changed:\s*(.+)`)
	fmt.Printf("│  Created: %s\n", emptyIfNil(created))
	fmt.Printf("│  Updated: %s\n", emptyIfNil(updated))

	rir := detectRIR(text)
	fmt.Printf("│  RIR: %s\n", emptyIfNil(rir))

	fmt.Println("└────────────────────────────")
}

// firstAny checks multiple regex patterns and returns first match
func firstAny(text string, patterns ...string) string {
	for _, p := range patterns {
		if v := findFirst(p, text); v != "" {
			return v
		}
	}
	return ""
}
