package social

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	xhtml "golang.org/x/net/html"
)

// SocialCheckResult keeps the simple compatibility struct (platform + url + exists)
type SocialCheckResult struct {
	Platform string
	URL      string
	Exists   bool
}

// SocialProfile contains richer profile data (best-effort)
type SocialProfile struct {
	Platform    string `json:"platform"`
	Username    string `json:"username"`
	URL         string `json:"url"`
	Exists      bool   `json:"exists"`
	DisplayName string `json:"display_name,omitempty"`
	Bio         string `json:"bio,omitempty"`
	Location    string `json:"location,omitempty"`
	Website     string `json:"website,omitempty"`
	Avatar      string `json:"avatar,omitempty"`
	Followers   int64  `json:"followers,omitempty"`
	Following   int64  `json:"following,omitempty"`
	Posts       int64  `json:"posts,omitempty"`
	PublicRepos int64  `json:"public_repos,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
	Raw         string `json:"raw,omitempty"` // raw JSON or HTML snippet (truncated)
	Error       string `json:"error,omitempty"`
}

// platform -> URL format (use %s for username)
var platformURLs = map[string]string{
	"Twitter":   "https://twitter.com/%s",
	"Facebook":  "https://www.facebook.com/%s",
	"GitHub":    "https://github.com/%s",
	"Instagram": "https://www.instagram.com/%s",
	"Reddit":    "https://www.reddit.com/user/%s",
	"LinkedIn":  "https://www.linkedin.com/in/%s",
	// add more platforms if desired
}

// CheckHandles: backward-compatible simple existence check (HTTP 200 -> exists)
func CheckHandles(username string) ([]SocialCheckResult, error) {
	clients := createClients()
	var wg sync.WaitGroup
	mu := sync.Mutex{}
	out := make([]SocialCheckResult, 0, len(platformURLs))

	// bounded concurrency
	sem := make(chan struct{}, 6)
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()

	for platform, fmtURL := range platformURLs {
		platform := platform
		fmtURL := fmtURL
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			u := fmt.Sprintf(fmtURL, username)
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			req.Header.Set("User-Agent", "ReconNio/1.0 (+https://github.com/shii9/ReconNio)")
			resp, err := clients.http.Do(req)
			exists := false
			if err == nil && resp != nil {
				if resp.StatusCode == http.StatusOK {
					exists = true
				}
				_ = resp.Body.Close()
			} else if err != nil {
				// network error -> non-fatal, treat as not existing
				_ = err
			}
			mu.Lock()
			out = append(out, SocialCheckResult{
				Platform: platform,
				URL:      u,
				Exists:   exists,
			})
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out, nil
}

// CheckHandlesAdvanced: returns richer SocialProfile entries (best-effort)
func CheckHandlesAdvanced(username string) ([]SocialProfile, error) {
	clients := createClients()
	var wg sync.WaitGroup
	mu := sync.Mutex{}
	results := make([]SocialProfile, 0, len(platformURLs))

	// Use a slightly longer timeout for advanced checks
	ctx, cancel := context.WithTimeout(context.Background(), 36*time.Second)
	defer cancel()
	sem := make(chan struct{}, 6)

	for platform, fmtURL := range platformURLs {
		platform := platform
		fmtURL := fmtURL
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			url := fmt.Sprintf(fmtURL, username)
			p := SocialProfile{
				Platform: platform,
				Username: username,
				URL:      url,
			}

			switch platform {
			case "GitHub":
				gh, raw, err := fetchGitHubProfile(ctx, clients, username)
				if err != nil {
					p.Error = err.Error()
					// fallback to basic probe
					exists, rawHTML := probeExistenceHTML(ctx, clients, url)
					p.Exists = exists
					p.Raw = rawHTML
				} else {
					p.Exists = true
					p.DisplayName = gh.Name
					p.Bio = gh.Bio
					p.Avatar = gh.AvatarURL
					p.Website = gh.Blog
					p.Followers = gh.Followers
					p.Following = gh.Following
					p.PublicRepos = gh.PublicRepos
					p.CreatedAt = gh.CreatedAt
					p.Raw = raw
				}

			case "Reddit":
				rd, raw, err := fetchRedditProfile(ctx, clients, username)
				if err != nil {
					p.Error = err.Error()
					exists, rawHTML := probeExistenceHTML(ctx, clients, url)
					p.Exists = exists
					p.Raw = rawHTML
				} else {
					p.Exists = true
					p.DisplayName = rd.DisplayName
					p.Bio = rd.SubredditPublicDescription
					p.Avatar = rd.IconImg
					p.Followers = rd.TotalKarma
					p.Raw = raw
				}

			default:
				// Generic meta extraction for the remaining platforms
				exists, raw, meta := fetchHTMLMeta(ctx, clients, url)
				p.Exists = exists
				if raw != "" {
					p.Raw = raw
				}
				// fill common fields from meta tags
				if t, ok := meta["og:title"]; ok && p.DisplayName == "" {
					p.DisplayName = t
				}
				if d, ok := meta["og:description"]; ok && p.Bio == "" {
					p.Bio = d
				}
				if img, ok := meta["og:image"]; ok && p.Avatar == "" {
					p.Avatar = img
				}
				if site, ok := meta["og:site_name"]; ok && p.Website == "" {
					p.Website = site
				}
				if p.DisplayName == "" {
					if t, ok := meta["title"]; ok {
						p.DisplayName = t
					}
				}
			}

			mu.Lock()
			results = append(results, p)
			mu.Unlock()
		}()
	}

	wg.Wait()
	return results, nil
}

//
// ---- helpers and platform-specific fetchers ----
//

type httpClients struct {
	http *http.Client
}

func createClients() *httpClients {
	return &httpClients{
		http: &http.Client{
			Timeout: 14 * time.Second,
		},
	}
}

// fetchHTMLMeta fetches page and extracts common meta tags (og:*, twitter:*, title).
// Returns (exists bool, rawSnippet string limited, mapMeta)
func fetchHTMLMeta(ctx context.Context, clients *httpClients, urlStr string) (bool, string, map[string]string) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	req.Header.Set("User-Agent", "ReconNio/1.0 (+https://github.com/shii9/ReconNio)")
	resp, err := clients.http.Do(req)
	if err != nil {
		return false, "", nil
	}
	defer resp.Body.Close()

	// treat 200 as exists
	if resp.StatusCode != http.StatusOK {
		rawb, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return false, string(rawb), nil
	}

	meta := map[string]string{}
	z := xhtml.NewTokenizer(resp.Body)
	titleCaptured := false
	for {
		tt := z.Next()
		switch tt {
		case xhtml.ErrorToken:
			// EOF or error
			rawb := "" // avoid storing huge HTML; keep raw empty here
			return true, rawb, meta
		case xhtml.StartTagToken, xhtml.SelfClosingTagToken:
			t := z.Token()
			if t.Data == "meta" {
				var key, val string
				for _, a := range t.Attr {
					switch strings.ToLower(strings.TrimSpace(a.Key)) {
					case "property", "name":
						key = strings.ToLower(strings.TrimSpace(a.Val))
					case "content":
						val = strings.TrimSpace(a.Val)
					}
				}
				if key != "" && val != "" {
					meta[key] = val
				}
			} else if t.Data == "title" && !titleCaptured {
				tt2 := z.Next()
				if tt2 == xhtml.TextToken {
					title := strings.TrimSpace(string(z.Text()))
					if title != "" {
						meta["title"] = html.UnescapeString(title)
						titleCaptured = true
					}
				}
			}
		}
	}
}

// probeExistenceHTML = lightweight GET, returns (exists, truncated raw up to 8KB)
func probeExistenceHTML(ctx context.Context, clients *httpClients, urlStr string) (bool, string) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	req.Header.Set("User-Agent", "ReconNio/1.0 (+https://github.com/shii9/ReconNio)")
	resp, err := clients.http.Do(req)
	if err != nil || resp == nil {
		return false, ""
	}
	defer resp.Body.Close()
	rawb, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
	return resp.StatusCode == http.StatusOK, string(rawb)
}

// GitHub profile fetcher (public API). If env GITHUB_TOKEN is set we use it to reduce rate limits.
type githubUser struct {
	Login       string `json:"login"`
	Name        string `json:"name"`
	Company     string `json:"company"`
	Blog        string `json:"blog"`
	Location    string `json:"location"`
	Email       string `json:"email"`
	Bio         string `json:"bio"`
	AvatarURL   string `json:"avatar_url"`
	Followers   int64  `json:"followers"`
	Following   int64  `json:"following"`
	PublicRepos int64  `json:"public_repos"`
	CreatedAt   string `json:"created_at"`
}

func fetchGitHubProfile(ctx context.Context, clients *httpClients, username string) (*githubUser, string, error) {
	u := fmt.Sprintf("https://api.github.com/users/%s", username)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "ReconNio/1.0 (+https://github.com/shii9/ReconNio)")
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "token "+token)
	}
	resp, err := clients.http.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("github request error: %w", err)
	}
	defer resp.Body.Close()
	rawb, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if resp.StatusCode == 404 {
		return nil, string(rawb), fmt.Errorf("not found")
	}
	if resp.StatusCode != 200 {
		return nil, string(rawb), fmt.Errorf("github api returned %s", resp.Status)
	}
	var gh githubUser
	if err := json.Unmarshal(rawb, &gh); err != nil {
		return nil, string(rawb), fmt.Errorf("github json parse: %w", err)
	}
	return &gh, string(rawb), nil
}

// Reddit about.json fetcher
type redditAbout struct {
	Data struct {
		Name      string `json:"name"`
		IconImg   string `json:"icon_img"`
		Subreddit struct {
			PublicDescription string `json:"public_description"`
		} `json:"subreddit"`
		TotalKarma int64 `json:"total_karma"`
	} `json:"data"`
}

func fetchRedditProfile(ctx context.Context, clients *httpClients, username string) (*struct {
	DisplayName                string
	IconImg                    string
	SubredditPublicDescription string
	TotalKarma                 int64
}, string, error) {
	u := fmt.Sprintf("https://www.reddit.com/user/%s/about.json", username)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "ReconNio/1.0 (+https://github.com/shii9/ReconNio)")
	resp, err := clients.http.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("reddit request error: %w", err)
	}
	defer resp.Body.Close()
	rawb, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if resp.StatusCode == 404 {
		return nil, string(rawb), fmt.Errorf("not found")
	}
	if resp.StatusCode != 200 {
		return nil, string(rawb), fmt.Errorf("reddit returned %s", resp.Status)
	}
	var r redditAbout
	if err := json.Unmarshal(rawb, &r); err != nil {
		return nil, string(rawb), fmt.Errorf("reddit json parse: %w", err)
	}
	out := &struct {
		DisplayName                string
		IconImg                    string
		SubredditPublicDescription string
		TotalKarma                 int64
	}{
		DisplayName:                r.Data.Name,
		IconImg:                    r.Data.IconImg,
		SubredditPublicDescription: r.Data.Subreddit.PublicDescription,
		TotalKarma:                 r.Data.TotalKarma,
	}
	return out, string(rawb), nil
}

//
// Utilities
//

// UsernamePermutations returns a small set of permutations for exploratory search.
func UsernamePermutations(base string) []string {
	base = strings.TrimSpace(base)
	if base == "" {
		return nil
	}
	out := map[string]struct{}{}
	out[base] = struct{}{}
	vars := []string{
		base + "1", base + "01", base + "123", base + "_", base + "_1", base + ".dev", base + ".io",
		"the" + base, "real" + base, base + "_dev", base + "-dev",
	}
	for _, v := range vars {
		out[v] = struct{}{}
	}
	// try split variants
	parts := regexp.MustCompile(`[.\-_]`).Split(base, -1)
	if len(parts) == 2 {
		a, b := parts[0], parts[1]
		out[a+b] = struct{}{}
		out[a+"."+b] = struct{}{}
		out[a+"_"+b] = struct{}{}
	}
	res := make([]string, 0, len(out))
	for k := range out {
		res = append(res, k)
	}
	return res
}
