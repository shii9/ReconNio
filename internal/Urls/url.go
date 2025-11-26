package urlcollector

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

// Config holds configuration for URL collection
type Config struct {
	MaxDepth        int
	MaxURLs         int
	Concurrency     int
	Delay           time.Duration
	UserAgent       string
	FollowRedirects bool
	IncludeJS       bool
	IncludeCSS      bool
	IncludeForms    bool
	IncludeAPIs     bool
	Extensions      []string
	ExcludePatterns []string
	ProxyURL        string
}

// DefaultConfig returns default configuration
func DefaultConfig() Config {
	return Config{
		MaxDepth:        3,
		MaxURLs:         1000,
		Concurrency:     10,
		Delay:           1 * time.Second,
		UserAgent:       "ReconNio-URL-Collector/1.0",
		FollowRedirects: true,
		IncludeJS:       true,
		IncludeCSS:      true,
		IncludeForms:    true,
		IncludeAPIs:     true,
		Extensions:      []string{},
		ExcludePatterns: []string{},
	}
}

// URLCollector manages URL collection process
type URLCollector struct {
	config    Config
	client    *http.Client
	visited   map[string]bool
	urls      map[string]struct{}
	mu        sync.RWMutex
	wg        sync.WaitGroup
	semaphore chan struct{}
}

// New creates a new URL collector
func New(config Config) *URLCollector {
	if config.MaxDepth <= 0 {
		config.MaxDepth = 3
	}
	if config.MaxURLs <= 0 {
		config.MaxURLs = 1000
	}
	if config.Concurrency <= 0 {
		config.Concurrency = 10
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if config.ProxyURL != "" {
		proxyURL, _ := url.Parse(config.ProxyURL)
		client.Transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		}
	}

	return &URLCollector{
		config:    config,
		client:    client,
		visited:   make(map[string]bool),
		urls:      make(map[string]struct{}),
		semaphore: make(chan struct{}, config.Concurrency),
	}
}

// CollectURLs collects URLs from target with enhanced features
func (uc *URLCollector) CollectURLs(target string) ([]string, error) {
	// Ensure target has scheme
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	// Start with initial URL
	uc.addURL(target)

	// Collect from initial page
	if err := uc.collectFromPage(target, 0); err != nil {
		return nil, fmt.Errorf("failed to collect from target: %v", err)
	}

	// Collect from robots.txt
	uc.collectFromRobotsTxt(target)

	// Collect from sitemap
	uc.collectFromSitemap(target)

	// Collect from common paths
	uc.collectFromCommonPaths(target)

	// Wait for all goroutines to complete
	uc.wg.Wait()

	// Return collected URLs
	return uc.getURLs(), nil
}

// collectFromPage collects URLs from a single page
func (uc *URLCollector) collectFromPage(urlStr string, depth int) error {
	if depth > uc.config.MaxDepth {
		return nil
	}

	uc.semaphore <- struct{}{}
	defer func() { <-uc.semaphore }()

	// Check if already visited
	uc.mu.RLock()
	if uc.visited[urlStr] {
		uc.mu.RUnlock()
		return nil
	}
	uc.mu.RUnlock()

	// Mark as visited
	uc.mu.Lock()
	uc.visited[urlStr] = true
	uc.mu.Unlock()

	// Create request
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", uc.config.UserAgent)

	resp, err := uc.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Read body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Extract URLs from HTML
	uc.extractHTMLURLs(urlStr, body)

	// Extract URLs from plain text
	uc.extractPlainTextURLs(string(body))

	// Extract from JavaScript if enabled
	if uc.config.IncludeJS {
		uc.extractJSURLs(urlStr, string(body))
	}

	// Extract from CSS if enabled
	if uc.config.IncludeCSS {
		uc.extractCSSURLs(urlStr, string(body))
	}

	// Extract form URLs if enabled
	if uc.config.IncludeForms {
		uc.extractFormURLs(urlStr, body)
	}

	// Extract API endpoints
	if uc.config.IncludeAPIs {
		uc.extractAPIURLs(urlStr, string(body))
	}

	// Follow links recursively
	if depth < uc.config.MaxDepth {
		uc.extractAndFollowLinks(urlStr, body, depth+1)
	}

	// Rate limiting
	if uc.config.Delay > 0 {
		time.Sleep(uc.config.Delay)
	}

	return nil
}

// extractHTMLURLs extracts URLs from HTML tags
func (uc *URLCollector) extractHTMLURLs(baseURL string, body []byte) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode {
			for _, attr := range n.Attr {
				var urlValue string
				switch n.Data {
				case "a", "link":
					if attr.Key == "href" {
						urlValue = attr.Val
					}
				case "script", "img", "iframe", "embed", "source":
					if attr.Key == "src" {
						urlValue = attr.Val
					}
				case "form":
					if attr.Key == "action" {
						urlValue = attr.Val
					}
				case "video", "audio":
					if attr.Key == "src" || attr.Key == "poster" {
						urlValue = attr.Val
					}
				}

				if urlValue != "" {
					resolved := uc.resolveURL(baseURL, urlValue)
					if resolved != "" && uc.shouldIncludeURL(resolved) {
						uc.addURL(resolved)
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
}

// extractPlainTextURLs extracts URLs using regex
func (uc *URLCollector) extractPlainTextURLs(text string) {
	// URL regex patterns
	patterns := []string{
		`https?://[^\s"'<>]+`,
		`//[^\s"'<>]+`,
		`["']([^"'<>]*\.(?:js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot))["']`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllString(text, -1)
		for _, match := range matches {
			// Clean up matches
			match = strings.Trim(match, `"'`)
			if strings.HasPrefix(match, "//") {
				match = "https:" + match
			}
			if uc.shouldIncludeURL(match) {
				uc.addURL(match)
			}
		}
	}
}

// extractJSURLs extracts URLs from JavaScript content
func (uc *URLCollector) extractJSURLs(baseURL, content string) {
	// Extract API endpoints
	apiPatterns := []string{
		`["']([^"'<>]*\/api\/[^"'<>]*)["']`,
		`["']([^"'<>]*\/v\d+\/[^"'<>]*)["']`,
		`["']([^"'<>]*\/rest\/[^"'<>]*)["']`,
		`["']([^"'<>]*\/graphql[^"'<>]*)["']`,
	}

	for _, pattern := range apiPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				url := match[1]
				resolved := uc.resolveURL(baseURL, url)
				if resolved != "" && uc.shouldIncludeURL(resolved) {
					uc.addURL(resolved)
				}
			}
		}
	}

	// Extract fetch/XHR URLs
	fetchPatterns := []string{
		`fetch\s*\(\s*["']([^"'<>]+)["']`,
		`XMLHttpRequest\s*\(\s*["']([^"'<>]+)["']`,
		`\$\.(?:get|post|put|delete)\s*\(\s*["']([^"'<>]+)["']`,
	}

	for _, pattern := range fetchPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				url := match[1]
				resolved := uc.resolveURL(baseURL, url)
				if resolved != "" && uc.shouldIncludeURL(resolved) {
					uc.addURL(resolved)
				}
			}
		}
	}
}

// extractCSSURLs extracts URLs from CSS content
func (uc *URLCollector) extractCSSURLs(baseURL, content string) {
	// Extract URLs from CSS
	re := regexp.MustCompile(`url\s*\(\s*["']?([^"')]+)["']?\s*\)`)
	matches := re.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			url := match[1]
			resolved := uc.resolveURL(baseURL, url)
			if resolved != "" && uc.shouldIncludeURL(resolved) {
				uc.addURL(resolved)
			}
		}
	}
}

// extractFormURLs extracts form action URLs
func (uc *URLCollector) extractFormURLs(baseURL string, body []byte) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			for _, attr := range n.Attr {
				if attr.Key == "action" {
					resolved := uc.resolveURL(baseURL, attr.Val)
					if resolved != "" && uc.shouldIncludeURL(resolved) {
						uc.addURL(resolved)
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
}

// extractAPIURLs extracts potential API endpoints
func (uc *URLCollector) extractAPIURLs(baseURL, content string) {
	// Common API patterns
	apiPatterns := []string{
		`/api/[\w-]+`,
		`/v\d+/[\w-]+`,
		`/rest/[\w-]+`,
		`/graphql`,
		`/swagger`,
		`/docs`,
		`/health`,
		`/status`,
	}

	for _, pattern := range apiPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllString(content, -1)
		for _, match := range matches {
			resolved := uc.resolveURL(baseURL, match)
			if resolved != "" && uc.shouldIncludeURL(resolved) {
				uc.addURL(resolved)
			}
		}
	}
}

// extractAndFollowLinks follows links recursively
func (uc *URLCollector) extractAndFollowLinks(baseURL string, body []byte, depth int) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return
	}

	var links []string
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, attr := range n.Attr {
				if attr.Key == "href" {
					resolved := uc.resolveURL(baseURL, attr.Val)
					if resolved != "" && uc.shouldIncludeURL(resolved) {
						links = append(links, resolved)
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	// Process links concurrently
	for _, link := range links {
		link := link
		uc.wg.Add(1)
		go func() {
			defer uc.wg.Done()
			if err := uc.collectFromPage(link, depth); err == nil {
				// Success
			}
		}()
	}
}

// collectFromRobotsTxt collects URLs from robots.txt
func (uc *URLCollector) collectFromRobotsTxt(baseURL string) {
	robotsURL := uc.resolveURL(baseURL, "/robots.txt")

	resp, err := uc.client.Get(robotsURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	// Parse robots.txt
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Sitemap:") {
			sitemapURL := strings.TrimSpace(strings.TrimPrefix(line, "Sitemap:"))
			resolved := uc.resolveURL(baseURL, sitemapURL)
			if resolved != "" {
				uc.addURL(resolved)
				uc.collectFromSitemap(resolved)
			}
		} else if strings.HasPrefix(line, "Disallow:") || strings.HasPrefix(line, "Allow:") {
			path := strings.TrimSpace(strings.TrimPrefix(line, "Disallow:"))
			path = strings.TrimSpace(strings.TrimPrefix(path, "Allow:"))
			if path != "" {
				resolved := uc.resolveURL(baseURL, path)
				if resolved != "" && uc.shouldIncludeURL(resolved) {
					uc.addURL(resolved)
				}
			}
		}
	}
}

// collectFromSitemap collects URLs from sitemap.xml
func (uc *URLCollector) collectFromSitemap(sitemapURL string) {
	resp, err := uc.client.Get(sitemapURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	// Simple sitemap parsing
	re := regexp.MustCompile(`<loc>([^<]+)</loc>`)
	matches := re.FindAllStringSubmatch(string(body), -1)
	for _, match := range matches {
		if len(match) > 1 {
			url := match[1]
			if uc.shouldIncludeURL(url) {
				uc.addURL(url)
			}
		}
	}

	// Handle sitemap index
	indexRe := regexp.MustCompile(`<sitemap>(.*?)</sitemap>`)
	indexMatches := indexRe.FindAllStringSubmatch(string(body), -1)
	for _, match := range indexMatches {
		if len(match) > 1 {
			// Parse nested sitemap
			locRe := regexp.MustCompile(`<loc>([^<]+)</loc>`)
			locMatches := locRe.FindAllStringSubmatch(match[1], -1)
			for _, loc := range locMatches {
				if len(loc) > 1 {
					uc.collectFromSitemap(loc[1])
				}
			}
		}
	}
}

// collectFromCommonPaths collects URLs from common paths
func (uc *URLCollector) collectFromCommonPaths(baseURL string) {
	commonPaths := []string{
		"/sitemap.xml",
		"/sitemap_index.xml",
		"/feed",
		"/rss",
		"/atom",
		"/search",
		"/archive",
		"/blog",
		"/news",
		"/contact",
		"/about",
		"/privacy",
		"/terms",
		"/login",
		"/register",
		"/admin",
		"/api",
		"/docs",
		"/swagger",
		"/health",
		"/status",
	}

	for _, path := range commonPaths {
		fullURL := uc.resolveURL(baseURL, path)
		if fullURL != "" {
			uc.wg.Add(1)
			go func(url string) {
				defer uc.wg.Done()
				uc.collectFromPage(url, 1)
			}(fullURL)
		}
	}
}

// resolveURL resolves relative URLs
func (uc *URLCollector) resolveURL(base, ref string) string {
	if ref == "" || ref == "#" || strings.HasPrefix(ref, "mailto:") || strings.HasPrefix(ref, "tel:") {
		return ""
	}

	baseParsed, err := url.Parse(base)
	if err != nil {
		return ""
	}

	refParsed, err := url.Parse(ref)
	if err != nil {
		return ""
	}

	resolved := baseParsed.ResolveReference(refParsed)

	// Remove fragment
	resolved.Fragment = ""

	return resolved.String()
}

// shouldIncludeURL checks if URL should be included
func (uc *URLCollector) shouldIncludeURL(urlStr string) bool {
	// Check max URLs limit
	uc.mu.RLock()
	if len(uc.urls) >= uc.config.MaxURLs {
		uc.mu.RUnlock()
		return false
	}
	uc.mu.RUnlock()

	// Parse URL
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	// Skip non-HTTP(S) URLs
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}

	// Skip common unwanted extensions
	unwantedExtensions := []string{
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
		".exe", ".msi", ".dmg", ".pkg", ".deb", ".rpm",
		".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv",
		".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
	}

	for _, ext := range unwantedExtensions {
		if strings.HasSuffix(strings.ToLower(parsed.Path), ext) {
			return false
		}
	}

	// Check exclude patterns
	for _, pattern := range uc.config.ExcludePatterns {
		if strings.Contains(urlStr, pattern) {
			return false
		}
	}

	// Check include extensions
	if len(uc.config.Extensions) > 0 {
		hasAllowedExt := false
		for _, ext := range uc.config.Extensions {
			if strings.HasSuffix(strings.ToLower(parsed.Path), strings.ToLower(ext)) {
				hasAllowedExt = true
				break
			}
		}
		if !hasAllowedExt {
			return false
		}
	}

	return true
}

// addURL adds URL to collection
func (uc *URLCollector) addURL(urlStr string) {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	if _, exists := uc.urls[urlStr]; !exists {
		uc.urls[urlStr] = struct{}{}
	}
}

// getURLs returns collected URLs
func (uc *URLCollector) getURLs() []string {
	uc.mu.RLock()
	defer uc.mu.RUnlock()

	urls := make([]string, 0, len(uc.urls))
	for url := range uc.urls {
		urls = append(urls, url)
	}
	return urls
}

// CollectURLs is the main entry point for backward compatibility
func CollectURLs(target string) ([]string, error) {
	config := DefaultConfig()
	collector := New(config)
	return collector.CollectURLs(target)
}

// CollectURLsWithConfig collects URLs with custom configuration
func CollectURLsWithConfig(target string, config Config) ([]string, error) {
	collector := New(config)
	return collector.CollectURLs(target)
}
